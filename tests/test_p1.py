"""PingOne 登录 + PingOne Token Exchange（全 mock）：授权码登录（不带 a2a.invoke）→ 同一应用在 PingOne 换出签给
Scutum 的 token → Scutum token exchange → Lyra。与 PINGONE_* 槽位（目前接 PingFederate）互不影响。"""

import base64
import dataclasses
import time
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from test_flows import CFG, ISS, JWK, KEY, SCUTUM, TOKEN_EXCHANGE, World

from mjagent.app import create_app
from mjagent.config import load_config
from mjagent.scutum_client import TT_ACCESS_TOKEN

P1ISS = "https://auth.pingone.sg/env-p1/as"
APP = "p1-agentx"
AUD = "https://scutum.test"

PCFG = dataclasses.replace(
    CFG, pingone_label="PingFederate",
    p1_issuer=P1ISS, p1_client_id=APP, p1_client_secret="p1-secret",
    scutum_p1_client_id="agt-p1", scutum_p1_client_secret="sp1",
)


def _jwt(claims: dict) -> str:
    now = int(time.time())
    return jwt.encode({"iat": now, "exp": now + 3600, **claims}, KEY, algorithm="RS256", headers={"kid": "k1"})


class P1World(World):
    def handler(self, req: httpx.Request) -> httpx.Response:
        url = str(req.url)
        if url == f"{P1ISS}/.well-known/openid-configuration":
            self.calls.append(req)
            return httpx.Response(200, json={"issuer": P1ISS, "authorization_endpoint": f"{P1ISS}/authorize",
                                             "token_endpoint": f"{P1ISS}/token", "jwks_uri": f"{P1ISS}/jwks",
                                             "end_session_endpoint": f"{P1ISS}/signoff"})
        if url == f"{P1ISS}/token":
            self.calls.append(req)
            form = parse_qs(req.content.decode())
            if form.get("grant_type") == [TOKEN_EXCHANGE]:
                if self.idp_exchange_error:
                    return httpx.Response(400, json=self.idp_exchange_error)
                return httpx.Response(200, json={"access_token": _jwt({
                    "iss": P1ISS, "aud": [AUD], "client_id": APP, "sub": "p1-alice", "scope": "a2a.invoke",
                    "email": "alice@contoso.com"}), "token_type": "Bearer", "issued_token_type": TT_ACCESS_TOKEN,
                    "expires_in": 300, "scope": "a2a.invoke"})
            return httpx.Response(200, json={
                "access_token": _jwt({"iss": P1ISS, "aud": ["https://api.pingone.sg"], "client_id": APP,
                                      "sub": "p1-alice", "scope": "openid profile email offline_access"}),
                "id_token": _jwt({"iss": P1ISS, "aud": APP, "sub": "p1-alice", "email": "alice@contoso.com",
                                  "name": "Alice", "nonce": self.nonce}),
                "expires_in": 3600, "scope": "openid profile email offline_access"})
        return super().handler(req)


@pytest.fixture
def pworld(monkeypatch):
    w = P1World()
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
def pclient(pworld):
    app = create_app(PCFG)
    app.testing = True
    return app.test_client()


def _p1_login(client, world):
    r = client.get("/auth/p1/login")
    assert r.status_code == 302
    loc = urlparse(r.headers["Location"])
    q = parse_qs(loc.query)
    assert f"{loc.scheme}://{loc.netloc}{loc.path}" == f"{P1ISS}/authorize"
    # 登录不请求 a2a.invoke：A2A 权限只在交换出的 token 上
    assert q["scope"] == ["openid profile email offline_access"] and q["client_id"] == [APP]
    assert q["redirect_uri"] == ["https://mjagent.test/auth/p1/callback"] and q["code_challenge_method"] == ["S256"]
    world.nonce = q["nonce"][0]
    return client.get(f"/auth/p1/callback?code=c1&state={q['state'][0]}")


def test_p1_login_token_exchange_then_scutum_and_chat(pclient, pworld):
    r = _p1_login(pclient, pworld)
    assert r.status_code == 302 and r.headers["Location"].endswith("/chat")

    ex1 = next(c for c in pworld.calls if str(c.url) == f"{P1ISS}/token"
               and parse_qs(c.content.decode()).get("grant_type") == [TOKEN_EXCHANGE])
    form = parse_qs(ex1.content.decode())
    assert form["subject_token_type"] == [TT_ACCESS_TOKEN] and form["scope"] == ["a2a.invoke"]
    assert jwt.decode(form["subject_token"][0], options={"verify_signature": False})["aud"] == ["https://api.pingone.sg"]
    assert base64.b64decode(ex1.headers["authorization"].split()[1]).decode() == f"{APP}:p1-secret"   # 登录应用自己交换

    ex2 = next(c for c in pworld.calls if str(c.url) == f"{SCUTUM}/oauth/token")
    xform = parse_qs(ex2.content.decode())
    assert jwt.decode(xform["subject_token"][0], options={"verify_signature": False})["aud"] == [AUD]
    assert base64.b64decode(ex2.headers["authorization"].split()[1]).decode() == "agt-p1:sp1"   # PingOne 专用的 Scutum client
    assert not any(str(c.url).startswith(ISS) for c in pworld.calls)   # 不碰 PINGONE_* 槽位

    assert pclient.get("/api/agents").status_code == 200
    page = pclient.get("/debug").get_data(as_text=True)
    assert "PingOne Token Exchange 配置自检" in page and "✗" not in page


def test_p1_exchange_failure_keeps_login_and_explains(pclient, pworld):
    pworld.idp_exchange_error = {"error": "invalid_scope", "error_description": "The requested scope(s) must be granted"}
    r = _p1_login(pclient, pworld)
    assert r.headers["Location"].endswith("/chat")
    assert not any(str(c.url) == f"{SCUTUM}/oauth/token" for c in pworld.calls)
    r = pclient.get("/api/agents")
    assert r.status_code >= 400 and "invalid_scope" in r.get_data(as_text=True)


def test_login_page_labels_both_ping_slots(pclient):
    page = pclient.get("/").get_data(as_text=True)
    assert "使用 PingFederate 登录" in page and "使用 PingOne 登录" in page


def test_p1_secrets_can_live_in_files(tmp_path, monkeypatch):
    sec = tmp_path / "p1.secret"
    sec.write_text("from-file\n")
    sec.chmod(0o600)
    env = tmp_path / ".env"
    env.write_text(f"P1_ISSUER={P1ISS}/\nP1_CLIENT_ID={APP}\nP1_CLIENT_SECRET_FILE={sec}\n")
    for k in ("P1_ISSUER", "P1_CLIENT_ID", "P1_CLIENT_SECRET", "P1_CLIENT_SECRET_FILE", "P1_SCOPES", "P1_EXCHANGE_SCOPE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("MJAGENT_ENV_FILE", str(env))
    cfg = load_config()
    assert cfg.p1_enabled and cfg.p1_client_secret == "from-file" and cfg.p1_issuer == P1ISS
    assert cfg.p1_scopes == "openid profile email offline_access" and cfg.p1_exchange_scope == "a2a.invoke"
