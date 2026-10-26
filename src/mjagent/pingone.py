"""PingOne OIDC 登录（授权码 + PKCE，保密客户端）—— 这是客户应用自己的登录逻辑，和 CRM 无关。

唯一与对接 Lyra 有关的点：scope 里带上 Scutum custom resource 的 scope（如 a2a.invoke），
PingOne 就会把 access_token 签给 Scutum（aud = custom resource 的 audience），供 Token Exchange 使用。
因此这张 access_token 不能再拿去调 PingOne userinfo，用户信息从 id_token 读。
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from urllib.parse import urlencode

import httpx
import jwt

_discovery_cache: dict[str, tuple[dict, float]] = {}


GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
TT_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"


class PingOneError(Exception):
    pass


class IdpExchangeError(PingOneError):
    """IdP 拒绝 token exchange（RFC 6749 §5.2 错误）；字段与 ScutumError 对齐，前端统一展示。"""

    def __init__(self, error: str, description: str = ""):
        super().__init__(f"{error}: {description}" if description else error)
        self.error = error
        self.description = description


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


class PingOneClient:
    def __init__(self, issuer: str, client_id: str, client_secret: str, scopes: str, redirect_uri: str,
                 *, verify: bool = True, transport: httpx.BaseTransport | None = None):
        self.issuer = issuer.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = scopes
        self.redirect_uri = redirect_uri
        self._verify = verify
        self._transport = transport
        self._jwks_client: jwt.PyJWKClient | None = None

    def _http(self) -> httpx.Client:
        return httpx.Client(timeout=15.0, verify=self._verify, transport=self._transport)

    def discovery(self) -> dict:
        url = f"{self.issuer}/.well-known/openid-configuration"
        hit = _discovery_cache.get(url)
        if hit and hit[1] > time.time():
            return hit[0]
        with self._http() as c:
            resp = c.get(url)
        if resp.status_code != 200:
            raise PingOneError(f"discovery failed HTTP {resp.status_code}")
        doc = resp.json()
        _discovery_cache[url] = (doc, time.time() + 3600)
        return doc

    def authorization_url(self, *, state: str, nonce: str, code_challenge: str, prompt: str | None = None) -> str:
        params = {
            "response_type": "code", "client_id": self.client_id, "redirect_uri": self.redirect_uri,
            "scope": self.scopes, "state": state, "nonce": nonce,
            "code_challenge": code_challenge, "code_challenge_method": "S256",
        }
        if prompt:
            params["prompt"] = prompt
        return f"{self.discovery()['authorization_endpoint']}?{urlencode(params)}"

    def logout_url(self, *, id_token_hint: str | None, post_logout_redirect_uri: str, state: str) -> str:
        """OIDC RP-Initiated Logout：清掉 PingOne 的 SSO 会话（切换账号用）。

        post_logout_redirect_uri 必须登记在 PingOne 应用的 Signoff URLs 里，否则 PingOne 停在自己的登出页；
        带上 id_token_hint，PingOne 才确认是哪个应用 / 会话发起的登出并允许跳回。
        """
        endpoint = self.discovery().get("end_session_endpoint") or f"{self.issuer}/signoff"
        params = {"post_logout_redirect_uri": post_logout_redirect_uri, "state": state}
        if id_token_hint:
            params["id_token_hint"] = id_token_hint
        return f"{endpoint}?{urlencode(params)}"

    def exchange_code(self, code: str, code_verifier: str) -> dict:
        """授权码换 token（client_secret_basic），返回 PingOne token 响应。"""
        data = {"grant_type": "authorization_code", "code": code, "redirect_uri": self.redirect_uri,
                "code_verifier": code_verifier}
        with self._http() as c:
            resp = c.post(self.discovery()["token_endpoint"], data=data, auth=(self.client_id, self.client_secret))
        if resp.status_code != 200:
            raise PingOneError(f"token endpoint HTTP {resp.status_code}: {resp.text[:300]}")
        return resp.json()

    def token_exchange(self, subject_token: str, *, client_id: str, client_secret: str, scope: str) -> dict:
        """RFC 8693：用登录 access_token 在 IdP 换一张签给 Scutum 的 token（两段交换的第一段）。

        用的是 IdP 上的交换专用 client，不是登录 client：登录 client 拿不到 A2A 权限。
        """
        data = {"grant_type": GRANT_TOKEN_EXCHANGE, "subject_token": subject_token,
                "subject_token_type": TT_ACCESS_TOKEN, "scope": scope}
        with self._http() as c:
            resp = c.post(self.discovery()["token_endpoint"], data=data, auth=(client_id, client_secret))
        if resp.status_code != 200:
            try:
                body = resp.json()
            except ValueError:
                body = {}
            raise IdpExchangeError(body.get("error") or f"HTTP {resp.status_code}",
                                   body.get("error_description") or resp.text[:300])
        return resp.json()

    def verify_id_token(self, id_token: str, nonce: str) -> dict:
        doc = self.discovery()
        if self._jwks_client is None:
            self._jwks_client = jwt.PyJWKClient(doc["jwks_uri"], cache_keys=True)
        key = self._jwks_client.get_signing_key_from_jwt(id_token)
        claims = jwt.decode(id_token, key.key, algorithms=["RS256"], audience=self.client_id, issuer=doc["issuer"],
                            leeway=30)
        if claims.get("nonce") != nonce:
            raise PingOneError("id_token nonce mismatch")
        return claims
