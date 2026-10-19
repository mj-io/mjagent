"""Scutum Token Exchange 客户端 —— 集成方接入 Lyra A2A 只需要这一个文件。

集成方（保密 client，服务端调用）把自己系统里的用户登录态交给 Scutum，换回 aud = Lyra A2A 的 Bearer token：

    POST {SCUTUM}/oauth/token        Authorization: Basic base64(client_id:client_secret)
    grant_type=urn:ietf:params:oauth:grant-type:token-exchange      (RFC 8693)
    subject_token=<见下>  subject_token_type=<见下>
    resource=<Lyra A2A 资源 URI>     scope=a2a:invoke

    → {"access_token", "issued_token_type", "token_type": "Bearer", "expires_in", "scope"[, "idp_subject"]}

subject_token 取值：
- PingOne：登录时 scope 带上 Scutum custom resource 的 scope（如 a2a.invoke），PingOne 返回的 access_token
  就是签给 Scutum 的，原样交过去（subject_token_type=urn:ietf:params:oauth:token-type:access_token）
- 企业微信：企微 OAuth 回调里的 code **不要自己换**，直接交给 Scutum（subject_token_type=urn:veeva:params:oauth:token-type:wecom-code），
  响应里的 idp_subject 就是企微 userid，用它建立本应用自己的登录态

没有 refresh_token：token 过期（expires_in，默认 ≤ 15 分钟）后重新交换。
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx

GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
TT_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
TT_ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token"
TT_WECOM_CODE = "urn:veeva:params:oauth:token-type:wecom-code"


class ScutumError(Exception):
    """Scutum 返回的 RFC 6749 §5.2 错误。"""

    def __init__(self, error: str, description: str = "", status: int = 400):
        super().__init__(f"{error}: {description}" if description else error)
        self.error = error
        self.description = description
        self.status = status


@dataclass
class ScutumToken:
    access_token: str
    expires_at: float
    scope: str = ""
    idp_subject: str | None = None

    @property
    def expired(self) -> bool:
        # 预留 30 秒余量，避免带着将过期的 token 发起长流式请求
        return time.time() >= self.expires_at - 30


class ScutumClient:
    def __init__(self, issuer: str, client_id: str, client_secret: str, *, resource: str,
                 scope: str = "a2a:invoke", verify: bool = True, transport: httpx.BaseTransport | None = None):
        self.token_endpoint = f"{issuer.rstrip('/')}/oauth/token"
        self.client_id = client_id
        self.client_secret = client_secret
        self.resource = resource
        self.scope = scope
        self._verify = verify
        self._transport = transport

    def exchange(self, subject_token: str, subject_token_type: str) -> ScutumToken:
        data = {
            "grant_type": GRANT_TOKEN_EXCHANGE,
            "subject_token": subject_token,
            "subject_token_type": subject_token_type,
            "requested_token_type": TT_ACCESS_TOKEN,
            "resource": self.resource,
            "scope": self.scope,
        }
        with httpx.Client(timeout=15.0, verify=self._verify, transport=self._transport) as c:
            resp = c.post(self.token_endpoint, data=data, auth=(self.client_id, self.client_secret),
                          headers={"Accept": "application/json"})
        try:
            body = resp.json()
        except ValueError:
            raise ScutumError("server_error", f"HTTP {resp.status_code}: {resp.text[:200]}", resp.status_code) from None
        if resp.status_code != 200:
            raise ScutumError(body.get("error", "server_error"), body.get("error_description", ""), resp.status_code)
        return ScutumToken(access_token=body["access_token"], expires_at=time.time() + int(body.get("expires_in", 300)),
                           scope=body.get("scope", ""), idp_subject=body.get("idp_subject"))

    def exchange_pingone(self, token: str, *, token_kind: str = "access_token") -> ScutumToken:
        return self.exchange(token, TT_ID_TOKEN if token_kind == "id_token" else TT_ACCESS_TOKEN)

    def exchange_wecom_code(self, code: str) -> ScutumToken:
        return self.exchange(code, TT_WECOM_CODE)
