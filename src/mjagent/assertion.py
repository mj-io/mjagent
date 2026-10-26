"""兜底模式（Scutum exchange_mode=subject_field）：客户后端用自己的私钥签断言，换 Lyra A2A 的 Bearer token。

适用于客户 IdP 做不了服务端 token exchange 的情况。客户应用以自己的身份为当前用户担保（RFC 7523）：

    POST {SCUTUM}/oauth/token
    grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
    assertion=<用户断言>        iss=client_id  sub=与 Scutum 约定的 CRM 映射字段值  aud=token 端点  iat exp jti
    client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
    client_assertion=<客户端认证>  iss=sub=client_id  aud=token 端点  iat exp jti
    resource=<Lyra A2A 资源 URI>  scope=a2a:invoke

两张 JWT 用同一把私钥签，header 带 kid；对应公钥（JWKS）事先登记在 Scutum，没有 client_secret。
Scutum 要求 exp - iat ≤ assertion_max_age（默认 300 秒）、jti 只能用一次，所以每次请求都现签。
"""

from __future__ import annotations

import time
import uuid
from pathlib import Path

import jwt

GRANT_JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


class AssertionSigner:
    def __init__(self, client_id: str, private_key_pem: bytes | str, *, kid: str, audience: str,
                 alg: str = "RS256", ttl: int = 60):
        self.client_id = client_id
        self._key = private_key_pem
        self.kid = kid
        self.audience = audience   # Scutum token 端点
        self.alg = alg
        self.ttl = ttl

    @classmethod
    def from_file(cls, client_id: str, key_file: str, **kw) -> AssertionSigner:
        return cls(client_id, Path(key_file).read_bytes(), **kw)

    def _sign(self, sub: str) -> str:
        now = int(time.time())
        claims = {"iss": self.client_id, "sub": sub, "aud": self.audience, "iat": now, "exp": now + self.ttl,
                  "jti": uuid.uuid4().hex}
        return jwt.encode(claims, self._key, algorithm=self.alg, headers={"kid": self.kid} if self.kid else None)

    def user_assertion(self, subject: str) -> str:
        """为用户担保：sub 是双方约定的 CRM 映射字段值（如 CRM username）。"""
        return self._sign(subject)

    def client_assertion(self) -> str:
        """private_key_jwt 客户端认证：iss = sub = client_id。"""
        return self._sign(self.client_id)
