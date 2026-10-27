"""Microsoft Entra ID 登录 + OBO（全 mock）：授权码登录 → OBO 换签给 Scutum 的 token → Scutum token exchange → Lyra。"""

import dataclasses
import time
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from test_flows import CFG, KEY, SCUTUM, World

from mjagent.app import create_app
from mjagent.config import load_config
from mjagent.entra import GRANT_JWT_BEARER
from mjagent.scutum_client import TT_ACCESS_TOKEN

TENANT = "tid-1"
EISS = f"https://login.microsoftonline.com/{TENANT}/v2.0"
APP = "entra-app"                        # 客户应用在 Entra 的 client id
API = "scutum-api"                       # Scutum 在客户 Entra 注册的 API 应用的 client id
OBO_SCOPE = f"api://{API}/a2a.invoke"

ECFG = dataclasses.replace(
    CFG, pingone_issuer="", pingone_client_id="",
    entra_tenant_id=TENANT, entra_client_id=APP, entra_client_secret="entra-secret",
    entra_scopes=f"openid profile email offline_access api://{APP}/access_as_user", entra_obo_scope=OBO_SCOPE,
    scutum_entra_client_id="agt-e", scutum_entra_client_secret="se",
)


def _jwt(claims: dict) -> str:
    now = int(time.time())
    return jwt.encode({"iat": now, "exp": now + 3600, **claims}, KEY, algorithm="RS256", headers={"kid": "k1"})


class EntraWorld(World):
    def __init__(self):
        super().__init__()
        self.obo_error: dict | None = None

    def handler(self, req: httpx.Request) -> httpx.Response:
        url = str(req.url)
        if url == f"{EISS}/.well-known/openid-configuration":
            self.calls.append(req)
            base = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0"
            return httpx.Response(200, json={"issuer": EISS, "authorization_endpoint": f"{base}/authorize",
                                             "token_endpoint": f"{base}/token", "jwks_uri": f"{EISS}/keys",
                                             "end_session_endpoint": f"{base}/logout"})
        if url == f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token":
            self.calls.append(req)
            form = parse_qs(req.content.decode())
            if form.get("grant_type") == [GRANT_JWT_BEARER]:
                if self.obo_error:
                    return httpx.Response(400, json=self.obo_error)
                return httpx.Response(200, json={"access_token": _jwt({
                    "iss": EISS, "aud": API, "azp": APP, "scp": "a2a.invoke", "preferred_username": "alice@contoso.com",
                    "tid": TENANT}), "token_type": "Bearer", "expires_in": 3600, "scope": OBO_SCOPE})
            return httpx.Response(200, json={
                "access_token": _jwt({"iss": f"https://sts.windows.net/{TENANT}/", "aud": f"api://{APP}",
                                      "appid": APP, "scp": "access_as_user", "upn": "alice@contoso.com"}),
                "id_token": _jwt({"iss": EISS, "aud": APP, "sub": "entra-alice", "name": "Alice",
                                  "preferred_username": "alice@contoso.com", "nonce": self.nonce}),
                "expires_in": 3600, "scope": f"api://{APP}/access_as_user openid profile email"})
        return super().handler(req)


@pytest.fixture
def eworld(monkeypatch):
    w = EntraWorld()
    real_client = httpx.Client

    class MockedClient(real_client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(w.handler)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "Client", MockedClient)
    from test_flows import JWK
    monkeypatch.setattr(jwt.PyJWKClient, "fetch_data", lambda self: {"keys": [JWK]})
    from mjagent import pingone
    pingone._discovery_cache.clear()
    return w


@pytest.fixture
def eclient(eworld):
    app = create_app(ECFG)
    app.testing = True
    return app.test_client()


def _entra_login(client, world):
    r = client.get("/auth/entra/login")
    assert r.status_code == 302
    loc = urlparse(r.headers["Location"])
    q = parse_qs(loc.query)
    assert loc.netloc == "login.microsoftonline.com" and loc.path == f"/{TENANT}/oauth2/v2.0/authorize"
    # 登录 scope 带本应用自己公开的 API：access_token 签给本应用，才能拿去做 OBO
    assert q["scope"] == [f"openid profile email offline_access api://{APP}/access_as_user"]
    assert q["redirect_uri"] == ["https://mjagent.test/auth/entra/callback"] and q["code_challenge_method"] == ["S256"]
    world.nonce = q["nonce"][0]
    return client.get(f"/auth/entra/callback?code=c1&state={q['state'][0]}")


def test_entra_login_obo_then_scutum_exchange_and_chat(eclient, eworld):
    r = _entra_login(eclient, eworld)
    assert r.status_code == 302 and r.headers["Location"].endswith("/chat")

    obo = next(c for c in eworld.calls if "oauth2/v2.0/token" in str(c.url)
               and parse_qs(c.content.decode()).get("grant_type") == [GRANT_JWT_BEARER])
    form = parse_qs(obo.content.decode())
    assert form["requested_token_use"] == ["on_behalf_of"] and form["scope"] == [OBO_SCOPE]
    assert jwt.decode(form["assertion"][0], options={"verify_signature": False})["aud"] == f"api://{APP}"
    assert obo.headers["authorization"].startswith("Basic ")

    ex = next(c for c in eworld.calls if str(c.url) == f"{SCUTUM}/oauth/token")
    xform = parse_qs(ex.content.decode())
    assert xform["subject_token_type"] == [TT_ACCESS_TOKEN]
    assert jwt.decode(xform["subject_token"][0], options={"verify_signature": False})["aud"] == API
    import base64
    assert base64.b64decode(ex.headers["authorization"].split()[1]).decode() == "agt-e:se"   # Entra 专用的 Scutum client

    assert eclient.get("/api/agents").status_code == 200
    page = eclient.get("/debug").get_data(as_text=True)
    assert "Entra OBO 换出的 token" in page and "obo" in page and "✗" not in page


def test_entra_obo_failure_keeps_login_and_explains(eclient, eworld):
    eworld.obo_error = {"error": "invalid_grant", "error_description": "AADSTS65001: The user or administrator has not consented"}
    r = _entra_login(eclient, eworld)
    assert r.headers["Location"].endswith("/chat")
    assert not any(str(c.url) == f"{SCUTUM}/oauth/token" for c in eworld.calls)
    r = eclient.get("/api/agents")
    assert r.status_code >= 400 and "AADSTS65001" in r.get_data(as_text=True)


def test_entra_secrets_can_live_in_files(tmp_path, monkeypatch):
    sec = tmp_path / "entra.secret"
    sec.write_text("from-file\n")
    sec.chmod(0o600)
    env = tmp_path / ".env"
    env.write_text(f"ENTRA_TENANT_ID={TENANT}\nENTRA_CLIENT_ID={APP}\nENTRA_CLIENT_SECRET_FILE={sec}\n"
                   f"ENTRA_OBO_SCOPE={OBO_SCOPE}\n")
    for k in ("ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_CLIENT_SECRET", "ENTRA_CLIENT_SECRET_FILE", "ENTRA_OBO_SCOPE",
              "ENTRA_SCOPES"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("MJAGENT_ENV_FILE", str(env))
    cfg = load_config()
    assert cfg.entra_client_secret == "from-file" and cfg.entra_enabled
    assert cfg.entra_scopes == f"openid profile email offline_access api://{APP}/access_as_user"
