"""端到端（全 mock）：PingOne / 企业微信登录 → Scutum Token Exchange → Lyra A2A。"""

import dataclasses
import json
import time
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from jwt.algorithms import RSAAlgorithm

from mjagent import wecom
from mjagent.app import create_app
from mjagent.assertion import CLIENT_ASSERTION_TYPE, GRANT_JWT_BEARER
from mjagent.config import Config
from mjagent.scutum_client import TT_ACCESS_TOKEN, TT_WECOM_CODE, ScutumClient, ScutumError

ISS = "https://auth.pingone.test/env-1/as"
SCUTUM = "https://scutum.test"
LYRA = "https://lyra.test/lyra"
RESOURCE = "https://lyra.test/lyra/a2a"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWK = {**json.loads(RSAAlgorithm.to_jwk(KEY.public_key())), "kid": "k1", "alg": "RS256", "use": "sig"}

TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"

CFG = Config(
    secret_key="test", app_base_url="https://mjagent.test", debug_page=True,
    pingone_issuer=ISS, pingone_client_id="p1-app", pingone_client_secret="p1-secret",
    pingone_scopes="openid profile email a2a.invoke", pingone_subject_token="access_token",
    wecom_corp_id="ww-corp", wecom_agent_id="1000002",
    scutum_issuer=SCUTUM, scutum_pingone_client_id="agt-p", scutum_pingone_client_secret="sp",
    scutum_wecom_client_id="agt-w", scutum_wecom_client_secret="sw",
    lyra_base_url=LYRA, lyra_resource=RESOURCE,
)


class World:
    """一组外部服务的 mock 与调用记录。"""

    def __init__(self):
        self.calls: list[httpx.Request] = []
        self.nonce = ""
        self.scutum_ttl = 900
        self.scutum_error: dict | None = None
        self.idp_exchange_error: dict | None = None

    def handler(self, req: httpx.Request) -> httpx.Response:
        self.calls.append(req)
        url = str(req.url)
        if url == f"{ISS}/.well-known/openid-configuration":
            return httpx.Response(200, json={"issuer": ISS, "authorization_endpoint": f"{ISS}/authorize",
                                             "token_endpoint": f"{ISS}/token", "jwks_uri": f"{ISS}/jwks",
                                             "end_session_endpoint": f"{ISS}/signoff"})
        if url == f"{ISS}/token" and parse_qs(req.content.decode()).get("grant_type") == [TOKEN_EXCHANGE]:
            if self.idp_exchange_error:
                return httpx.Response(400, json=self.idp_exchange_error)
            return httpx.Response(200, json={"access_token": "idp-at-for-scutum", "token_type": "Bearer",
                                             "issued_token_type": TT_ACCESS_TOKEN, "expires_in": 300, "scope": "a2a.invoke"})
        if url == f"{ISS}/token":
            now = int(time.time())
            id_token = jwt.encode({"iss": ISS, "aud": "p1-app", "sub": "p1-alice", "email": "alice@contoso.com",
                                   "name": "Alice", "nonce": self.nonce, "iat": now, "exp": now + 3600},
                                  KEY, algorithm="RS256", headers={"kid": "k1"})
            return httpx.Response(200, json={"access_token": "pingone-at-for-scutum", "id_token": id_token,
                                             "expires_in": 3600, "scope": "openid profile email a2a.invoke"})
        if url == f"{SCUTUM}/oauth/token":
            if self.scutum_error:
                return httpx.Response(400, json=self.scutum_error)
            form = parse_qs(req.content.decode())
            subject = "assertion" if form["grant_type"] == [GRANT_JWT_BEARER] else form["subject_token"][0]
            body = {"access_token": f"lyra-token-for-{subject}", "token_type": "Bearer",
                    "issued_token_type": TT_ACCESS_TOKEN, "expires_in": self.scutum_ttl, "scope": "a2a:invoke"}
            if form.get("subject_token_type") == [TT_WECOM_CODE]:
                body["idp_subject"] = "zhangsan"
            return httpx.Response(200, json=body)
        if url == f"{LYRA}/a2a/agents":
            if not req.headers.get("authorization", "").startswith("Bearer lyra-token-for-"):
                return httpx.Response(401, json={"detail": "Unauthorized"}, headers={"WWW-Authenticate": 'Bearer realm="lyra-a2a"'})
            return httpx.Response(200, json={"agents": [{"key": "crm_bot", "name": "CRM Bot"}]})
        if url == f"{LYRA}/a2a/crm_bot/jsonrpc":
            ev1 = {"jsonrpc": "2.0", "id": "1", "result": {"statusUpdate": {"contextId": "ctx-9", "status": {"state": "TASK_STATE_WORKING"}}}}
            ev2 = {"jsonrpc": "2.0", "id": "1", "result": {"statusUpdate": {"contextId": "ctx-9", "status": {
                "state": "TASK_STATE_COMPLETED", "message": {"parts": [{"text": "你好"}]}}}}}
            sse = "".join(f"data: {json.dumps(e)}\n\n" for e in (ev1, ev2))
            return httpx.Response(200, content=sse.encode(), headers={"content-type": "text/event-stream"})
        return httpx.Response(404, json={"detail": f"unmocked {url}"})


@pytest.fixture
def world(monkeypatch):
    w = World()
    real_client = httpx.Client

    class MockedClient(real_client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(w.handler)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "Client", MockedClient)
    monkeypatch.setattr(jwt.PyJWKClient, "fetch_data", lambda self: {"keys": [JWK]})
    from mjagent import pingone
    pingone._discovery_cache.clear()
    return w


@pytest.fixture
def client(world):
    app = create_app(CFG)
    app.testing = True
    return app.test_client()


def _pingone_login(client, world):
    r = client.get("/auth/pingone/login")
    assert r.status_code == 302
    q = parse_qs(urlparse(r.headers["Location"]).query)
    assert q["scope"] == ["openid profile email a2a.invoke"] and q["code_challenge_method"] == ["S256"]
    world.nonce = q["nonce"][0]
    return client.get(f"/auth/pingone/callback?code=c1&state={q['state'][0]}")


def test_pingone_login_exchange_and_chat(client, world):
    r = _pingone_login(client, world)
    assert r.status_code == 302 and r.headers["Location"].endswith("/chat")
    ex = next(c for c in world.calls if str(c.url) == f"{SCUTUM}/oauth/token")
    form = parse_qs(ex.content.decode())
    assert form["grant_type"] == ["urn:ietf:params:oauth:grant-type:token-exchange"]
    assert form["subject_token"] == ["pingone-at-for-scutum"] and form["subject_token_type"] == [TT_ACCESS_TOKEN]
    assert form["resource"] == [RESOURCE] and form["scope"] == ["a2a:invoke"]
    assert ex.headers["authorization"].startswith("Basic ")

    r = client.get("/api/agents")
    assert r.status_code == 200 and r.json["agents"][0]["key"] == "crm_bot"

    r = client.post("/api/chat", json={"agent": "crm_bot", "text": "hi"})
    body = r.get_data(as_text=True)
    assert r.mimetype == "text/event-stream" and "你好" in body
    # 第二轮带回 contextId
    client.post("/api/chat", json={"agent": "crm_bot", "text": "again"}).get_data()
    rpc = [c for c in world.calls if str(c.url).endswith("/jsonrpc")]
    msg2 = json.loads(rpc[-1].content)["params"]["message"]
    assert msg2["contextId"] == "ctx-9" and rpc[-1].headers["a2a-version"] == "1.0"

    page = client.get("/debug").get_data(as_text=True)
    assert "token_exchange" in page and "p1-alice" in page


def test_pingone_reexchanges_when_lyra_token_expires(client, world):
    world.scutum_ttl = 10   # 小于 30 秒余量 → 立即视为过期
    _pingone_login(client, world)
    n = sum(1 for c in world.calls if str(c.url) == f"{SCUTUM}/oauth/token")
    assert client.get("/api/agents").status_code == 200
    assert sum(1 for c in world.calls if str(c.url) == f"{SCUTUM}/oauth/token") == n + 1


def test_pingone_exchange_failure_still_logs_in(client, world):
    world.scutum_error = {"error": "invalid_grant", "error_description": "subject could not be mapped"}
    r = _pingone_login(client, world)
    assert r.headers["Location"].endswith("/chat")
    # 登录态仍有效：不能再把用户送回登录页（会无限跳转），而是直接报交换失败原因
    r = client.get("/api/agents")
    assert r.status_code == 502 and r.json["error"] == "token_exchange_failed" and "subject could not be mapped" in r.json["message"]


TWO_STAGE = dataclasses.replace(CFG, pingone_scopes="openid profile email",
                                idp_exchange_client_id="xchg", idp_exchange_client_secret="xs")


def _two_stage_client():
    app = create_app(TWO_STAGE)
    app.testing = True
    return app.test_client()


def _login_without_a2a_scope(client, world):
    r = client.get("/auth/pingone/login")
    q = parse_qs(urlparse(r.headers["Location"]).query)
    assert q["scope"] == ["openid profile email"]   # 登录不再申请 A2A 权限
    world.nonce = q["nonce"][0]
    return client.get(f"/auth/pingone/callback?code=c1&state={q['state'][0]}")


def test_two_stage_exchanges_at_idp_then_scutum(world):
    client = _two_stage_client()
    r = _login_without_a2a_scope(client, world)
    assert r.headers["Location"].endswith("/chat")
    idp_x = [c for c in world.calls if str(c.url) == f"{ISS}/token" and b"token-exchange" in c.content]
    assert len(idp_x) == 1
    form = parse_qs(idp_x[0].content.decode())
    assert form["subject_token"] == ["pingone-at-for-scutum"] and form["subject_token_type"] == [TT_ACCESS_TOKEN]
    assert form["scope"] == ["a2a.invoke"]
    # 交换专用 client 认证，不是登录 client
    assert idp_x[0].headers["authorization"] == httpx.BasicAuth("xchg", "xs")._auth_header
    scutum_form = parse_qs(next(c for c in world.calls if str(c.url) == f"{SCUTUM}/oauth/token").content.decode())
    assert scutum_form["subject_token"] == ["idp-at-for-scutum"]
    assert client.get("/api/agents").status_code == 200
    page = client.get("/debug").get_data(as_text=True)
    assert "idp_token_exchange" in page and "IdP 交换出的 token（签给 Scutum）" in page


def test_two_stage_reexchange_repeats_both_steps(world):
    world.scutum_ttl = 10
    client = _two_stage_client()
    _login_without_a2a_scope(client, world)
    assert client.get("/api/agents").status_code == 200
    assert sum(1 for c in world.calls if str(c.url) == f"{ISS}/token" and b"token-exchange" in c.content) == 2
    assert sum(1 for c in world.calls if str(c.url) == f"{SCUTUM}/oauth/token") == 2


def test_two_stage_idp_refusal_is_reported(world):
    world.idp_exchange_error = {"error": "invalid_scope", "error_description": "scope a2a.invoke not allowed"}
    client = _two_stage_client()
    r = _login_without_a2a_scope(client, world)
    assert r.headers["Location"].endswith("/chat")
    assert not any(str(c.url) == f"{SCUTUM}/oauth/token" for c in world.calls)
    r = client.get("/api/agents")
    assert r.status_code == 502 and "scope a2a.invoke not allowed" in r.json["message"]


ASSERTION_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _assertion_client(tmp_path):
    key_file = tmp_path / "scutum-assertion.pem"
    key_file.write_bytes(ASSERTION_KEY.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    cfg = dataclasses.replace(CFG, scutum_assertion_client_id="agt-c", scutum_assertion_key_file=str(key_file),
                              scutum_assertion_kid="c1", scutum_assertion_subject_map=json.dumps({"alice@contoso.com": "alice.crm"}))
    app = create_app(cfg)
    app.testing = True
    return app.test_client()


def _assertion_forms(world) -> list[dict]:
    return [parse_qs(c.content.decode()) for c in world.calls if str(c.url) == f"{SCUTUM}/oauth/token"]


def test_assertion_mode_signs_user_and_client_assertions(world, tmp_path):
    client = _assertion_client(tmp_path)
    r = _pingone_login(client, world)
    assert r.headers["Location"].endswith("/chat")
    req = next(c for c in world.calls if str(c.url) == f"{SCUTUM}/oauth/token")
    assert "authorization" not in req.headers   # 不用 client_secret
    form = parse_qs(req.content.decode())
    assert form["grant_type"] == [GRANT_JWT_BEARER] and form["client_assertion_type"] == [CLIENT_ASSERTION_TYPE]
    assert form["resource"] == [RESOURCE] and form["scope"] == ["a2a:invoke"]
    pub, aud = ASSERTION_KEY.public_key(), f"{SCUTUM}/oauth/token"
    user = jwt.decode(form["assertion"][0], pub, algorithms=["RS256"], audience=aud)
    cli = jwt.decode(form["client_assertion"][0], pub, algorithms=["RS256"], audience=aud)
    # 登录账号经客户侧对照表换成 CRM 映射字段值
    assert user["iss"] == "agt-c" and user["sub"] == "alice.crm"
    assert cli["iss"] == cli["sub"] == "agt-c" and user["jti"] != cli["jti"]
    assert user["exp"] - user["iat"] <= 300
    assert jwt.get_unverified_header(form["assertion"][0])["kid"] == "c1"
    # 兜底模式不碰 IdP 的 token exchange
    assert not any(str(c.url) == f"{ISS}/token" and b"token-exchange" in c.content for c in world.calls)
    assert client.get("/api/agents").status_code == 200
    assert "alice.crm" in client.get("/debug").get_data(as_text=True)


def test_assertion_mode_signs_fresh_assertions_on_reexchange(world, tmp_path):
    world.scutum_ttl = 10
    client = _assertion_client(tmp_path)
    _pingone_login(client, world)
    assert client.get("/api/agents").status_code == 200
    forms = _assertion_forms(world)
    assert len(forms) == 2
    jtis = {jwt.decode(f["assertion"][0], options={"verify_signature": False})["jti"] for f in forms}
    assert len(jtis) == 2   # Scutum 的 jti 只能用一次，每次都现签


def test_assertion_refusal_is_reported(world, tmp_path):
    world.scutum_error = {"error": "invalid_grant", "error_description": "subject must match exactly one active CRM user"}
    client = _assertion_client(tmp_path)
    _pingone_login(client, world)
    r = client.get("/api/agents")
    assert r.status_code == 502 and "exactly one active CRM user" in r.json["message"]


def test_scutum_non_oauth_error_keeps_reason(client, world):
    world.scutum_error = {"detail": "Not Found"}
    _pingone_login(client, world)
    r = client.get("/api/agents")
    assert r.status_code == 502 and "HTTP 400" in r.json["message"] and "Not Found" in r.json["message"]


def test_wecom_login_hands_code_to_scutum(client, world):
    r = client.get("/auth/wecom/login", headers={"User-Agent": "Mozilla/5.0 wxwork/4.1"})
    loc = r.headers["Location"]
    assert loc.startswith(wecom.OAUTH_AUTHORIZE) and "scope=snsapi_base" in loc and loc.endswith("#wechat_redirect")
    state = parse_qs(urlparse(loc.split("#")[0]).query)["state"][0]
    r = client.get(f"/auth/wecom/callback?code=wx-code-1&state={state}")
    assert r.headers["Location"].endswith("/chat")
    form = parse_qs(next(c for c in world.calls if str(c.url) == f"{SCUTUM}/oauth/token").content.decode())
    assert form["subject_token"] == ["wx-code-1"] and form["subject_token_type"] == [TT_WECOM_CODE]
    assert "zhangsan" in client.get("/chat").get_data(as_text=True)
    # 本应用没有直接调企微 API
    assert not any("qyapi.weixin.qq.com" in str(c.url) for c in world.calls)


def test_wecom_token_expiry_requires_silent_reauth(client, world):
    world.scutum_ttl = 10
    r = client.get("/auth/wecom/login")
    assert r.headers["Location"].startswith(wecom.QR_LOGIN)   # 普通浏览器 → 扫码
    state = parse_qs(urlparse(r.headers["Location"]).query)["state"][0]
    client.get(f"/auth/wecom/callback?code=wx-code-2&state={state}")
    r = client.get("/api/agents")
    assert r.status_code == 401 and r.json["login_url"] == "/auth/wecom/login"


def test_wecom_callback_rejects_bad_state(client, world):
    client.get("/auth/wecom/login")
    r = client.get("/auth/wecom/callback?code=x&state=forged")
    assert "error=" in r.headers["Location"]
    assert not any(str(c.url) == f"{SCUTUM}/oauth/token" for c in world.calls)


def test_scutum_client_error_mapping():
    def handler(req):
        return httpx.Response(400, json={"error": "invalid_grant", "error_description": "nope"})
    c = ScutumClient(SCUTUM, "agt-x", "s", resource=RESOURCE, transport=httpx.MockTransport(handler))
    with pytest.raises(ScutumError) as ei:
        c.exchange_wecom_code("code")
    assert ei.value.error == "invalid_grant" and ei.value.status == 400


def test_pingone_logout_clears_sso(client, world):
    _pingone_login(client, world)
    r = client.get("/auth/pingone/logout")
    q = parse_qs(urlparse(r.headers["Location"]).query)
    assert r.status_code == 302 and r.headers["Location"].startswith(f"{ISS}/signoff?")
    assert q["post_logout_redirect_uri"] == ["https://mjagent.test/"] and q["id_token_hint"][0].count(".") == 2 and q["state"]
    assert client.get("/api/agents").status_code == 401       # 本应用会话已清
