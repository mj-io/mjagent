"""iframe 嵌入登录：弹窗 + postMessage（handoff code）/ 轮询兜底、binding 防登录 CSRF、cookie 属性与安全头。"""

import dataclasses
import re
from urllib.parse import parse_qs, urlparse

import pytest
from test_flows import CFG, world  # noqa: F401  (world 是 fixture)

from mjagent.app import create_app

EMBED_CFG = dataclasses.replace(CFG, embed_mode=True, embed_frame_ancestors="https://host.test", app_base_url="https://embed.test")
HOST_CFG = dataclasses.replace(CFG, embed_app_url="https://embed.test/embed/app")
BINDING = "b" * 64


@pytest.fixture
def embed(world):  # noqa: F811
    app = create_app(EMBED_CFG)
    app.testing = True
    return app


def _begin(c, binding=BINDING):
    r = c.post("/embed/auth/begin", json={"binding": binding})
    assert r.status_code == 200, r.get_data(as_text=True)
    return r


def _popup_login(embed, world, flow_id):  # noqa: F811
    """弹窗是顶层窗口：用独立的 client（独立 cookie jar）走 start → PingOne → callback。"""
    popup = embed.test_client()
    r = popup.get(f"/embed/auth/start?flow_id={flow_id}")
    assert r.status_code == 302
    q = parse_qs(urlparse(r.headers["Location"]).query)
    assert q["redirect_uri"] == ["https://embed.test/embed/auth/callback"]
    world.nonce = q["nonce"][0]
    page = popup.get(f"/embed/auth/callback?code=c1&state={q['state'][0]}").get_data(as_text=True)
    m = re.search(r'code: "([^"]+)"', page)
    return page, (m.group(1) if m else None)


def test_embed_app_headers_and_cookie_attributes(embed):
    c = embed.test_client()
    r = c.get("/embed/app")
    assert r.headers["Content-Security-Policy"] == "frame-ancestors 'self' https://host.test"
    assert "X-Frame-Options" not in r.headers
    set_cookie = _begin(c).headers["Set-Cookie"]
    for attr in ("Secure", "HttpOnly", "SameSite=None", "Partitioned"):
        assert attr in set_cookie, set_cookie


def test_postmessage_flow_establishes_iframe_session(embed, world):  # noqa: F811
    iframe = embed.test_client()
    flow_id = _begin(iframe).json["flow_id"]
    page, code = _popup_login(embed, world, flow_id)
    assert code and 'postMessage' in page and '"https://embed.test"' in page     # targetOrigin 写死为本源
    assert "Cross-Origin-Opener-Policy" not in page
    r = iframe.post("/embed/auth/finish", json={"code": code, "binding": BINDING})
    assert r.status_code == 200 and r.json["via"] == "postMessage" and r.json["flow_cookie_seen"] is True
    session_cookie = r.headers.getlist("Set-Cookie")
    assert any("session=" in h and "Partitioned" in h and "SameSite=None" in h for h in session_cookie)
    assert iframe.get("/embed/whoami").json["channel"] == "cookie"
    # cookie 被拦截的浏览器：新 client（无 cookie）只靠内存 token 请求头
    bare = embed.test_client()
    who = bare.get("/embed/whoami", headers={"X-Embed-Session": r.json["session_token"]}).json
    assert who["logged_in"] and who["channel"] == "header" and who["user"]["email"] == "alice@contoso.com"
    assert bare.get("/api/agents", headers={"X-Embed-Session": r.json["session_token"]}).status_code == 200
    # handoff code 单次有效
    assert iframe.post("/embed/auth/finish", json={"code": code, "binding": BINDING}).status_code == 400


def test_finish_rejects_foreign_binding(embed, world):  # noqa: F811
    """登录 CSRF：攻击者用自己账号拿到的 code 塞给受害者 iframe —— 受害者 iframe 的 binding 不同，拒绝。"""
    attacker = embed.test_client()
    flow_id = _begin(attacker, binding="a" * 64).json["flow_id"]
    _, code = _popup_login(embed, world, flow_id)
    victim = embed.test_client()
    _begin(victim)
    r = victim.post("/embed/auth/finish", json={"code": code, "binding": BINDING})
    assert r.status_code == 400 and r.json["message"] == "binding mismatch"


def test_polling_fallback_when_opener_is_cut(embed, world):  # noqa: F811
    iframe = embed.test_client()
    flow_id = _begin(iframe).json["flow_id"]
    assert iframe.get(f"/embed/auth/status?flow_id={flow_id}").status_code == 404          # 不带 binding 不回答
    _popup_login(embed, world, flow_id)                                                       # postMessage 假定丢失
    st = iframe.get(f"/embed/auth/status?flow_id={flow_id}", headers={"X-Embed-Binding": BINDING}).json
    assert st["status"] == "done"
    r = iframe.post("/embed/auth/finish", json={"flow_id": flow_id, "binding": BINDING})
    assert r.status_code == 200 and r.json["via"] == "polling"


def test_begin_requires_binding_and_start_rejects_unknown_flow(embed):
    c = embed.test_client()
    assert c.post("/embed/auth/begin", json={"binding": "short"}).status_code == 400
    assert c.get("/embed/auth/start?flow_id=nope").status_code == 400
    assert c.get("/embed/auth/callback?state=nope&code=x").status_code == 400


def test_embed_routes_disabled_without_embed_mode(world):  # noqa: F811
    app = create_app(CFG)
    assert app.test_client().get("/embed/app").status_code == 404


def test_host_page_iframe_attributes(world):  # noqa: F811
    app = create_app(HOST_CFG)
    r = app.test_client().get("/embed-host")
    html = r.get_data(as_text=True)
    assert r.headers["Content-Security-Policy"] == "frame-src https://embed.test"
    assert 'src="https://embed.test/embed/app?host_url=https%3A%2F%2Fmjagent.test%2Fembed-host"' in html
    # 弹窗不可用（iOS 企业微信）时的兜底只放开「用户点击触发」的顶层跳转，不给无手势的 allow-top-navigation
    assert ('sandbox="allow-scripts allow-same-origin allow-forms allow-popups allow-popups-to-escape-sandbox '
            'allow-top-navigation-by-user-activation"') in html
    assert "allow-top-navigation " not in html and 'allow-top-navigation"' not in html


def _sha(v):
    import hashlib
    return hashlib.sha256(v.encode()).hexdigest()


def test_top_navigation_fallback(embed, world):  # noqa: F811
    """iOS 企业微信：window.open 返回 null → iframe 顶层跳转 /embed/auth/top，登录后 302 回宿主页，iframe 凭 binding 完成。"""
    top = embed.test_client()                                     # 顶层窗口（与 iframe 不同的 cookie 分区）
    r = top.get(f"/embed/auth/top?bh={_sha(BINDING)}&return=https://host.test/embed-host")
    assert r.status_code == 302 and "/embed/auth/start?flow_id=" in r.headers["Location"]
    r = top.get(r.headers["Location"])
    q = parse_qs(urlparse(r.headers["Location"]).query)
    world.nonce = q["nonce"][0]
    r = top.get(f"/embed/auth/callback?code=c1&state={q['state'][0]}")
    assert r.status_code == 302 and r.headers["Location"] == "https://host.test/embed-host"   # URL 里不带 code
    iframe = embed.test_client()                                  # 宿主页重新加载后的 iframe：只有 sessionStorage 里的 binding
    assert iframe.get("/embed/auth/status", headers={"X-Embed-Binding": "x" * 64}).status_code == 404
    st = iframe.get("/embed/auth/status", headers={"X-Embed-Binding": BINDING}).json
    assert st["status"] == "done" and st["flow_id"]
    r = iframe.post("/embed/auth/finish", json={"flow_id": st["flow_id"], "binding": BINDING})
    assert r.status_code == 200 and r.json["user"]["email"] == "alice@contoso.com"


@pytest.mark.parametrize("query", [
    f"bh={'0' * 64}&return=https://evil.test/x",          # 未登记的宿主源 → 防开放重定向
    f"bh={'0' * 64}&return=http://host.test/embed-host",  # 非 https
    "bh=not-a-hash&return=https://host.test/embed-host",
])
def test_top_navigation_rejects_bad_params(embed, query):
    assert embed.test_client().get(f"/embed/auth/top?{query}").status_code == 400
