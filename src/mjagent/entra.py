"""Microsoft Entra ID 登录 + OBO（On-Behalf-Of）—— 客户应用自己的登录逻辑，以及换 Scutum token 前的第一段。

登录：标准 OIDC 授权码 + PKCE（v2.0 端点），与 PingOne 共用 PingOneClient 的实现。scope 里带上本应用自己公开的
API（api://<本应用 client id>/access_as_user），这样登录拿到的 access_token 签给本应用 —— OBO 的前提：
assertion 的 aud 必须是发起 OBO 的应用本身，签给 Microsoft Graph 的 token 不能拿来做 OBO。

OBO（Entra 不支持 RFC 8693，对应的是 OBO）：
    POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
    grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
    requested_token_use=on_behalf_of
    assertion=<登录 access_token>
    scope=api://<Scutum 在客户 Entra 注册的 API 应用>/a2a.invoke
    + 本应用的 client_id / client_secret
换出的 token：aud = Scutum API 应用的 client id，azp = 本应用，scp = a2a.invoke，iss = .../v2.0（API 应用的
manifest 设 requestedAccessTokenVersion=2）。再把它作为 subject_token 交给 Scutum 做 token exchange。
"""

from __future__ import annotations

import httpx

from mjagent.pingone import IdpExchangeError, PingOneClient

GRANT_JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"


def entra_issuer(tenant_id: str) -> str:
    return f"https://login.microsoftonline.com/{tenant_id}/v2.0"


class EntraClient(PingOneClient):
    def __init__(self, tenant_id: str, client_id: str, client_secret: str, scopes: str, redirect_uri: str,
                 *, verify: bool = True, transport: httpx.BaseTransport | None = None):
        super().__init__(entra_issuer(tenant_id), client_id, client_secret, scopes, redirect_uri,
                         verify=verify, transport=transport)

    def on_behalf_of(self, assertion: str, scope: str) -> dict:
        """用登录 access_token 代表当前用户申请下游 API（Scutum）的 token。失败抛 IdpExchangeError（AADSTS 原因在 description）。"""
        data = {"grant_type": GRANT_JWT_BEARER, "requested_token_use": "on_behalf_of",
                "assertion": assertion, "scope": scope}
        with self._http() as c:
            resp = c.post(self.discovery()["token_endpoint"], data=data, auth=(self.client_id, self.client_secret))
        if resp.status_code != 200:
            try:
                body = resp.json()
            except ValueError:
                body = {}
            raise IdpExchangeError(body.get("error") or f"HTTP {resp.status_code}",
                                   body.get("error_description") or resp.text[:300])
        return resp.json()
