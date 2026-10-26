"""mjagent：模拟客户的第三方 agent 应用。

用户用客户自己的 IdP 登录（PingOne / 企业微信），本应用在服务端把登录态交给 Scutum 换 Lyra A2A 的 Bearer token，
再代用户调用 Lyra agent。浏览器只拿到本应用的会话 cookie，任何 token 都不下发到前端。
"""

from __future__ import annotations

import hmac
import json
import logging
import re
import secrets
import time
from collections.abc import Iterator
from urllib.parse import urlencode, urlsplit

import jwt
from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    stream_with_context,
    url_for,
)

from mjagent import wecom
from mjagent.a2a_client import A2AClient, A2AError
from mjagent.assertion import AssertionSigner
from mjagent.config import Config, load_config
from mjagent.embed import FLOW_COOKIE, SESSION_HEADER, EmbedFlows, origin_of
from mjagent.local_users import LocalUsers
from mjagent.pingone import IdpExchangeError, PingOneClient, PingOneError, pkce_pair
from mjagent.scutum_client import ScutumClient, ScutumError, ScutumToken
from mjagent.store import SessionStore, UserSession

logger = logging.getLogger("mjagent")

# 本地账号登录：同一账号 LOCKOUT_SECONDS 内失败 LOCKOUT_FAILURES 次即暂时锁定
LOCKOUT_FAILURES = 5
LOCKOUT_SECONDS = 300


class LoginRequired(Exception):
    def __init__(self, login_url: str, reason: str):
        super().__init__(reason)
        self.login_url = login_url
        self.reason = reason


class ExchangeFailed(Exception):
    """登录态有效但 IdP / Scutum 拒绝交换：重新登录解决不了（会无限跳转），直接把原因交给前端。"""

    def __init__(self, err: ScutumError | IdpExchangeError):
        super().__init__(str(err))
        self.error = err.error
        self.description = err.description


def _claims(token: str | None) -> dict:
    """只解码不验签，用于调试页展示。"""
    if not token:
        return {}
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return {"_error": "not a JWT"}


def create_app(cfg: Config | None = None) -> Flask:
    cfg = cfg or load_config()
    app = Flask(__name__)
    app.secret_key = cfg.secret_key
    if cfg.embed_mode:
        # 被 iframe 嵌入：本应用处于第三方上下文，会话 cookie 必须 SameSite=None; Secure，
        # 并加 Partitioned（CHIPS）：按顶层站点分区存储，不被当作跨站追踪 cookie 拦截
        app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="None", SESSION_COOKIE_SECURE=True,
                          SESSION_COOKIE_PARTITIONED=True)
    else:
        app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                          SESSION_COOKIE_SECURE=cfg.app_base_url.startswith("https://"))
    app.extensions["mjagent.cfg"] = cfg
    # 静态资源版本号（每次进程启动变化）：企业微信等 WebView 会激进缓存 js/css，带上它强制取新版本
    app.jinja_env.globals["asset_v"] = str(int(time.time()))
    store = SessionStore()
    app.extensions["mjagent.store"] = store
    flows = EmbedFlows()
    app.extensions["mjagent.embed"] = flows

    def pingone(callback_path: str = "/auth/pingone/callback") -> PingOneClient:
        return PingOneClient(cfg.pingone_issuer, cfg.pingone_client_id, cfg.pingone_client_secret, cfg.pingone_scopes,
                             f"{cfg.app_base_url}{callback_path}", verify=cfg.http_verify)

    def scutum(idp: str) -> ScutumClient:
        if idp == "wecom":
            return ScutumClient(cfg.scutum_issuer, cfg.scutum_wecom_client_id, cfg.scutum_wecom_client_secret,
                                resource=cfg.lyra_resource, verify=cfg.http_verify)
        return ScutumClient(cfg.scutum_issuer, cfg.scutum_pingone_client_id, cfg.scutum_pingone_client_secret,
                            resource=cfg.lyra_resource, verify=cfg.http_verify)

    def auth_channel() -> tuple[str | None, str | None]:
        """(sid, 通道)：会话 cookie 优先；嵌入模式下 cookie 被拦截时，用 iframe 内存里的 session token（请求头）兜底。"""
        sid = session.get("sid")
        if sid and store.get(sid):
            return sid, "cookie"
        if cfg.embed_mode:
            sid = flows.sid_for_token(request.headers.get(SESSION_HEADER))
            if sid and store.get(sid):
                return sid, "header"
        return None, None

    def current() -> UserSession | None:
        return store.get(auth_channel()[0])

    def complete_pingone_login(client: PingOneClient, code: str, verifier: str, nonce: str) -> UserSession:
        """授权码 → PingOne token → 建立本应用会话 → Scutum 交换（失败不影响登录，聊天时再提示原因）。"""
        tok = client.exchange_code(code, verifier)
        claims = client.verify_id_token(tok["id_token"], nonce)
        sess = UserSession(idp="pingone", subject=claims["sub"], email=claims.get("email"),
                           display_name=claims.get("name") or claims.get("preferred_username") or claims.get("email") or claims["sub"],
                           id_token_claims=claims, pingone_access_token=tok.get("access_token"),
                           pingone_id_token=tok["id_token"], pingone_expires_at=time.time() + int(tok.get("expires_in", 3600)))
        sess.log("login", idp="pingone", sub=claims["sub"], email=claims.get("email"), scope=tok.get("scope"))
        try:
            sess.scutum = scutum_token_for(sess)
            sess.log("token_exchange", idp="pingone", result="ok", mode=exchange_mode(sess),
                     expires_in=int(sess.scutum.expires_at - time.time()))
        except IdpExchangeError:
            pass   # scutum_subject 已记录
        except ScutumError as e:
            sess.log("token_exchange", idp="pingone", result=e.error, detail=e.description)
        return sess

    def exchange_mode(sess: UserSession) -> str:
        if sess.idp == "local":
            return "subject_field（私钥断言）"
        return "idp_token（两段交换）" if cfg.idp_exchange_enabled else "idp_token"

    signer_cache: dict[str, AssertionSigner] = {}

    def assertion_signer() -> AssertionSigner:
        if "s" not in signer_cache:
            signer_cache["s"] = AssertionSigner.from_file(
                cfg.scutum_assertion_client_id, cfg.scutum_assertion_key_file, kid=cfg.scutum_assertion_kid,
                audience=f"{cfg.scutum_issuer}/oauth/token", alg=cfg.scutum_assertion_alg)
        return signer_cache["s"]

    def scutum_token_for(sess: UserSession) -> ScutumToken:
        """换 Lyra token，按登录方式选交换模式：本地账号用私钥签断言（兜底），PingOne / PF 用 Token Exchange（单段或两段）。"""
        if sess.idp == "local":
            if not cfg.assertion_enabled:
                raise ScutumError("unauthorized_client", "本地账号需要兜底模式：请配置 SCUTUM_ASSERTION_CLIENT_ID / SCUTUM_ASSERTION_KEY_FILE")
            subject = sess.crm_subject or sess.subject
            sess.log("assertion", client_id=cfg.scutum_assertion_client_id, sub=subject, kid=cfg.scutum_assertion_kid)
            return scutum("pingone").exchange_assertion(assertion_signer(), subject)
        subject, kind = scutum_subject(sess)
        return scutum("pingone").exchange_pingone(subject, token_kind=kind)

    def scutum_subject(sess: UserSession) -> tuple[str, str]:
        """交给 Scutum 的 subject token 与类型。

        两段交换：先用登录 access_token 在 IdP（交换专用 client）换一张签给 Scutum 的 token；
        否则登录拿到的 token 本身就签给 Scutum，直接交过去。
        """
        if not cfg.idp_exchange_enabled:
            kind = cfg.pingone_subject_token
            return (sess.pingone_id_token if kind == "id_token" else sess.pingone_access_token) or "", kind
        try:
            tok = pingone().token_exchange(sess.pingone_access_token or "", client_id=cfg.idp_exchange_client_id,
                                           client_secret=cfg.idp_exchange_client_secret, scope=cfg.idp_exchange_scope)
        except IdpExchangeError as e:
            sess.log("idp_token_exchange", idp="pingone", result=e.error, detail=e.description)
            raise
        sess.idp_exchanged_token = tok["access_token"]
        sess.log("idp_token_exchange", idp="pingone", result="ok", scope=tok.get("scope"), expires_in=tok.get("expires_in"))
        return tok["access_token"], "access_token"

    def login_url_for(idp: str) -> str:
        if idp == "local":
            return url_for("index")
        return url_for("wecom_login") if idp == "wecom" else url_for("pingone_login")

    def ensure_token(sess: UserSession) -> str:
        """拿一张有效的 Lyra token：未过期直接用；PingOne 用户在 PingOne token 有效期内静默重新交换；否则重新登录。"""
        if sess.scutum and not sess.scutum.expired:
            return sess.scutum.access_token
        if sess.idp == "local":
            # 本地会话有效期内随时可以现签断言再换，不依赖外部 IdP
            try:
                sess.scutum = scutum_token_for(sess)
                sess.log("token_exchange", idp="local", result="ok", mode=exchange_mode(sess), reason="re-exchange")
                return sess.scutum.access_token
            except ScutumError as e:
                sess.log("token_exchange", idp="local", result=e.error, detail=e.description)
                raise ExchangeFailed(e) from e
        if sess.idp == "pingone" and sess.pingone_access_token and time.time() < sess.pingone_expires_at - 30:
            try:
                sess.scutum = scutum_token_for(sess)
                sess.log("token_exchange", idp="pingone", result="ok", mode=exchange_mode(sess), reason="re-exchange")
                return sess.scutum.access_token
            except IdpExchangeError as e:
                raise ExchangeFailed(e) from e
            except ScutumError as e:
                sess.log("token_exchange", idp="pingone", result=e.error, detail=e.description)
                raise ExchangeFailed(e) from e
        # PingOne token 也过期了 / 企微 code 一次性：只能再走一次登录（企微内静默；PingOne 有 SSO 会话时同样无感）
        raise LoginRequired(login_url_for(sess.idp), "lyra token expired")

    # ------------------------------------------------------------------ pages

    @app.get("/")
    def index():
        if current():
            return redirect(url_for("chat"))
        if cfg.wecom_enabled and wecom.in_wecom(request.headers.get("User-Agent")):
            return redirect(url_for("wecom_login"))   # 企微内打开：直接静默授权
        csrf = None
        if cfg.local_login_enabled:
            csrf = session.setdefault("login_csrf", secrets.token_urlsafe(24))
        return render_template("index.html", cfg=cfg, error=request.args.get("error"), csrf=csrf)

    # ------------------------------------------------------------------ 本地账号（客户应用自己的账号体系）

    login_failures: dict[str, list[float]] = {}   # 账号 → 最近失败时间；单进程部署，演示级限流

    def locked_out(username: str) -> bool:
        recent = [t for t in login_failures.get(username, []) if t > time.time() - LOCKOUT_SECONDS]
        login_failures[username] = recent
        return len(recent) >= LOCKOUT_FAILURES

    @app.post("/auth/local/login")
    def local_login():
        if not cfg.local_login_enabled:
            abort(404)
        expected = session.get("login_csrf")
        if not expected or not hmac.compare_digest(expected, request.form.get("csrf", "")):
            return redirect(url_for("index", error="登录表单已过期，请重试"))
        username = request.form.get("username", "").strip()
        if locked_out(username):
            return redirect(url_for("index", error=f"失败次数过多，请 {LOCKOUT_SECONDS // 60} 分钟后再试"))
        user = LocalUsers(cfg.local_users_file).authenticate(username, request.form.get("password", ""))
        if not user:
            login_failures.setdefault(username, []).append(time.time())
            logger.warning("local login failed user=%s", username)
            return redirect(url_for("index", error="账号或密码错误"))
        login_failures.pop(username, None)
        store.drop(session.pop("sid", None))
        session.pop("login_csrf", None)
        sess = UserSession(idp="local", subject=user.username, display_name=user.name, crm_subject=user.crm_subject)
        sess.log("login", idp="local", user=user.username, crm_subject=user.crm_subject)
        try:
            sess.scutum = scutum_token_for(sess)
            sess.log("token_exchange", idp="local", result="ok", mode=exchange_mode(sess),
                     expires_in=int(sess.scutum.expires_at - time.time()))
        except ScutumError as e:
            sess.log("token_exchange", idp="local", result=e.error, detail=e.description)
        session["sid"] = store.put(sess)
        return redirect(url_for("chat"))

    @app.get("/chat")
    def chat():
        sess = current()
        if not sess:
            return redirect(url_for("index"))
        return render_template("chat.html", cfg=cfg, user=sess)

    @app.get("/debug")
    def debug():
        if not cfg.debug_page:
            abort(404)
        sess = current()
        if not sess:
            return redirect(url_for("index"))
        two_stage = cfg.idp_exchange_enabled
        tokens = {
            "IdP id_token": _claims(sess.pingone_id_token),
            ("IdP 登录 access_token（签给客户应用）" if two_stage else "PingOne access_token（签给 Scutum）"):
                _claims(sess.pingone_access_token),
            "IdP 交换出的 token（签给 Scutum）": _claims(sess.idp_exchanged_token),
            "Scutum access_token（签给 Lyra）": _claims(sess.scutum.access_token if sess.scutum else None),
        }
        checks = []
        if sess.idp == "local":
            checks = _assertion_checks(sess, cfg)
        elif sess.idp == "pingone":
            checks = _two_stage_checks(sess, cfg) if two_stage else _pingone_checks(sess)
        return render_template("debug.html", cfg=cfg, user=sess, tokens={k: v for k, v in tokens.items() if v},
                               checks=checks,
                               events=list(reversed(sess.events)))

    @app.get("/logout")
    def logout():
        store.drop(session.pop("sid", None))
        return redirect(url_for("index"))

    @app.get("/auth/pingone/logout")
    def pingone_logout():
        """切换账号：清本应用会话，再去 PingOne signoff 清 SSO 会话，完成后回首页（需登记 Signoff URL = {APP_BASE_URL}/）。"""
        sess = current()
        id_token = sess.pingone_id_token if sess and sess.idp == "pingone" else None
        store.drop(session.pop("sid", None))
        if not cfg.pingone_enabled:
            return redirect(url_for("index"))
        return redirect(pingone().logout_url(id_token_hint=id_token, post_logout_redirect_uri=f"{cfg.app_base_url}/",
                                             state=secrets.token_urlsafe(16)))

    # ------------------------------------------------------------------ iframe 嵌入：宿主页（agentx.htltio.cn 扮演 CRM）

    @app.get("/embed-host")
    def embed_host():
        if not cfg.embed_app_url:
            abort(404)
        # 把宿主页自身地址交给 iframe：弹窗不可用时 iframe 顶层跳转去登录，完成后据此跳回（iframe 跨域读不到宿主 URL）
        host_url = f"{cfg.app_base_url}{request.full_path.rstrip('?')}"
        iframe_src = f"{cfg.embed_app_url}?{urlencode({'host_url': host_url})}"
        resp = Response(render_template("embed_host.html", cfg=cfg, user=None, app_origin=origin_of(cfg.embed_app_url),
                                        iframe_src=iframe_src))
        # CSP frame-src 只放行登记过的嵌入应用
        resp.headers["Content-Security-Policy"] = f"frame-src {origin_of(cfg.embed_app_url)}"
        return resp

    # ------------------------------------------------------------------ iframe 嵌入：被嵌入方（agentx.mjio.cn）

    def _embed_only():
        if not cfg.embed_mode or not cfg.pingone_enabled:
            abort(404)

    @app.get("/embed/app")
    def embed_app():
        _embed_only()
        resp = Response(render_template("embed_app.html", cfg=cfg, user=None, origin=origin_of(cfg.app_base_url),
                                        session_header=SESSION_HEADER))
        resp.headers["Content-Security-Policy"] = f"frame-ancestors 'self' {cfg.embed_frame_ancestors}".strip()
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.post("/embed/auth/begin")
    def embed_begin():
        _embed_only()
        binding = (request.get_json(silent=True) or {}).get("binding") or ""
        if len(binding) < 32:
            return jsonify(error="binding required (>= 32 chars, random, kept in iframe memory)"), 400
        flow_id = flows.begin(binding)
        resp = jsonify(flow_id=flow_id, start_url=url_for("embed_start", flow_id=flow_id))
        # 只用于观测：iframe 分区 cookie 能否写入 / 带回（Safari 等可能整体拦截）；安全绑定靠 binding
        resp.set_cookie(FLOW_COOKIE, flow_id, max_age=600, path="/embed", secure=True, httponly=True,
                        samesite="None", partitioned=True)
        return resp

    def _allowed_return(url: str | None) -> str | None:
        """顶层跳转回宿主页的地址：必须是 https 且源在 EMBED_FRAME_ANCESTORS 里（防开放重定向）。"""
        if not url:
            return None
        p = urlsplit(url)
        allowed = set(cfg.embed_frame_ancestors.split())
        return url if p.scheme == "https" and f"{p.scheme}://{p.netloc}" in allowed else None

    @app.get("/embed/auth/top")
    def embed_top():
        """顶层跳转模式入口（iframe 用 window.top 导航过来，此时已是顶层窗口）：建 flow 并送去 PingOne。"""
        _embed_only()
        bh, ret = request.args.get("bh") or "", _allowed_return(request.args.get("return"))
        origin = origin_of(cfg.app_base_url)
        if not re.fullmatch(r"[0-9a-f]{64}", bh) or not ret:
            return render_template("embed_callback.html", cfg=cfg, user=None, code=None, origin=origin,
                                   error="参数无效：bh 须为 binding 的 SHA-256，return 须为登记过的宿主页地址"), 400
        flow_id = flows.begin_with_hash(bh, ret)
        return redirect(url_for("embed_start", flow_id=flow_id))

    @app.get("/embed/auth/start")
    def embed_start():
        """在弹窗（顶层窗口）里执行：把弹窗送去 PingOne。"""
        _embed_only()
        flow_id = request.args.get("flow_id")
        f = flows.get(flow_id)
        if f is None or f.status not in ("pending", "started"):
            return render_template("embed_callback.html", cfg=cfg, user=None, code=None, origin=origin_of(cfg.app_base_url),
                                   error="登录流程不存在或已过期，请回到原页面重新点击登录"), 400
        verifier, challenge = pkce_pair()
        f.state, f.nonce, f.verifier, f.status = secrets.token_urlsafe(16), secrets.token_urlsafe(16), verifier, "started"
        flows.attach_state(flow_id, f.state)
        return redirect(pingone("/embed/auth/callback").authorization_url(state=f.state, nonce=f.nonce, code_challenge=challenge))

    @app.get("/embed/auth/callback")
    def embed_callback():
        """PingOne 回调（仍在弹窗里）：服务端换 token、建会话，回调页 postMessage 一次性 handoff code 给 iframe。"""
        _embed_only()
        hit = flows.by_state(request.args.get("state"))
        origin = origin_of(cfg.app_base_url)
        if hit is None:
            return render_template("embed_callback.html", cfg=cfg, user=None, code=None, origin=origin,
                                   error="state 无效或已使用，请回到原页面重新登录"), 400
        flow_id, f = hit
        if request.args.get("error"):
            f.status, f.error = "error", request.args.get("error_description") or request.args["error"]
            return render_template("embed_callback.html", cfg=cfg, user=None, code=None, origin=origin, error=f"PingOne：{f.error}")
        try:
            sess = complete_pingone_login(pingone("/embed/auth/callback"), request.args.get("code", ""), f.verifier or "", f.nonce or "")
        except (PingOneError, jwt.PyJWTError, KeyError) as e:
            logger.warning("embed PingOne login failed: %s", e)
            f.status, f.error = "error", str(e)
            return render_template("embed_callback.html", cfg=cfg, user=None, code=None, origin=origin, error=f"PingOne 登录失败：{e}")
        sess.log("embed", step="popup_callback", flow=flow_id[:8])
        f.sid, f.status = store.put(sess), "done"
        f.user = {"name": sess.display_name, "email": sess.email}
        if f.return_url:
            # 顶层跳转模式：回到宿主页，iframe 重新加载后凭 sessionStorage 里的 binding 完成登录（URL 里不带任何 code）
            return redirect(f.return_url)
        return render_template("embed_callback.html", cfg=cfg, user=None, code=flows.issue_handoff(flow_id), origin=origin, error=None)

    @app.get("/embed/auth/status")
    def embed_status():
        """轮询兜底（opener 被 COOP 切断时 postMessage 收不到）：只对持有 binding 的 iframe 回答。"""
        _embed_only()
        binding = request.headers.get("X-Embed-Binding")
        flow_id = request.args.get("flow_id")
        if flow_id:
            f = flows.get(flow_id)
        else:                                     # 顶层跳转模式：iframe 只有 binding
            hit = flows.find_by_binding(binding)
            flow_id, f = hit if hit else (None, None)
        if f is None or not flows.binding_ok(f, binding):
            return jsonify(status="unknown"), 404
        return jsonify(status=f.status, error=f.error, flow_id=flow_id)

    @app.post("/embed/auth/finish")
    def embed_finish():
        _embed_only()
        body = request.get_json(silent=True) or {}
        cookie_flow = request.cookies.get(FLOW_COOKIE)
        f, reason = flows.consume(binding=body.get("binding") or "", code=body.get("code"), flow_id=body.get("flow_id"))
        if f is None:
            return jsonify(error="invalid_grant", message=reason), 400
        sess = store.get(f.sid)
        if sess is None:
            return jsonify(error="invalid_grant", message="session expired"), 400
        session["sid"] = f.sid                       # Partitioned 会话 cookie（浏览器允许时生效）
        token = flows.issue_session_token(f.sid)     # cookie 被拦截时的兜底：iframe 只放内存，随请求头带上
        via = "postMessage" if body.get("code") else "polling"
        sess.log("embed", step="finish", via=via, flow_cookie_seen=bool(cookie_flow))
        resp = jsonify(ok=True, user=f.user, session_token=token, via=via, flow_cookie_seen=bool(cookie_flow))
        resp.delete_cookie(FLOW_COOKIE, path="/embed", secure=True, httponly=True, samesite="None", partitioned=True)
        return resp

    @app.post("/embed/auth/logout-ticket")
    def embed_logout_ticket():
        """登录后预领登出票据：点击「登出 PingOne」时 iframe 同步跳转，来不及再发请求（企业微信顶层跳转限制）。"""
        _embed_only()
        sid, _ = auth_channel()
        if not sid:
            return jsonify(error="login_required"), 401
        ret = _allowed_return((request.get_json(silent=True) or {}).get("host_url"))
        ticket = flows.issue_logout_ticket(sid, ret)
        base = cfg.app_base_url
        return jsonify(popup_url=f"{base}{url_for('embed_pingone_logout', ticket=ticket, mode='popup')}",
                       top_url=f"{base}{url_for('embed_pingone_logout', ticket=ticket, mode='top')}" if ret else None)

    @app.get("/embed/auth/pingone-logout")
    def embed_pingone_logout():
        """弹窗 / 顶层窗口里执行：凭票据清掉本应用会话，再送去 PingOne signoff 清 SSO 会话。"""
        _embed_only()
        hit = flows.consume_logout_ticket(request.args.get("ticket"))
        mode = "top" if request.args.get("mode") == "top" else "popup"
        if hit is None:
            return render_template("embed_logged_out.html", cfg=cfg, user=None, origin=origin_of(cfg.app_base_url),
                                   error="登出票据无效或已使用，请回到原页面重试"), 400
        sid, ret = hit
        sess = store.get(sid)
        id_token = sess.pingone_id_token if sess else None
        store.drop(sid)
        flows.drop_tokens_for_sid(sid)
        state = secrets.token_urlsafe(16)
        flows.remember_logout_state(state, mode, ret if mode == "top" else None)
        resp = redirect(pingone("/embed/auth/callback").logout_url(
            id_token_hint=id_token, post_logout_redirect_uri=f"{cfg.app_base_url}/embed/auth/logged-out", state=state))
        if mode == "top" and ret:
            # 兜底：PingOne 若不回传 state，靠这个顶层第一方 cookie 找回宿主页地址
            resp.set_cookie("embed_logout_return", ret, max_age=600, path="/embed/auth", secure=True, httponly=True, samesite="Lax")
        return resp

    @app.get("/embed/auth/logged-out")
    def embed_logged_out():
        """PingOne 登出后的回跳（需登记 Signoff URL）：顶层模式回宿主页，弹窗模式通知 iframe 后关闭。"""
        _embed_only()
        info = flows.pop_logout_state(request.args.get("state"))
        ret = (info[1] if info else None) or _allowed_return(request.cookies.get("embed_logout_return"))
        if (info and info[0] == "top" or not info) and ret:
            resp = redirect(ret)
        else:
            resp = Response(render_template("embed_logged_out.html", cfg=cfg, user=None, origin=origin_of(cfg.app_base_url), error=None))
        resp.delete_cookie("embed_logout_return", path="/embed/auth", secure=True, httponly=True, samesite="Lax")
        return resp

    @app.get("/embed/whoami")
    def embed_whoami():
        _embed_only()
        sid, channel = auth_channel()
        sess = store.get(sid)
        return jsonify(logged_in=bool(sess), channel=channel, user={"name": sess.display_name, "email": sess.email} if sess else None,
                       session_cookie_seen=bool(request.cookies.get(app.config["SESSION_COOKIE_NAME"])),
                       lyra_token=bool(sess and sess.scutum and not sess.scutum.expired))

    @app.post("/embed/logout")
    def embed_logout():
        _embed_only()
        sid, _ = auth_channel()
        store.drop(sid)
        session.pop("sid", None)
        flows.drop_token(request.headers.get(SESSION_HEADER))
        return jsonify(ok=True)

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "pingone": cfg.pingone_enabled, "wecom": cfg.wecom_enabled}

    # ------------------------------------------------------------------ PingOne

    @app.get("/auth/pingone/login")
    def pingone_login():
        if not cfg.pingone_enabled:
            abort(404)
        verifier, challenge = pkce_pair()
        state, nonce = secrets.token_urlsafe(16), secrets.token_urlsafe(16)
        session["pingone"] = {"state": state, "nonce": nonce, "verifier": verifier}
        return redirect(pingone().authorization_url(state=state, nonce=nonce, code_challenge=challenge))

    @app.get("/auth/pingone/callback")
    def pingone_callback():
        pending = session.pop("pingone", None)
        if request.args.get("error"):
            return redirect(url_for("index", error=f"PingOne: {request.args.get('error_description') or request.args['error']}"))
        if not pending or request.args.get("state") != pending["state"]:
            return redirect(url_for("index", error="PingOne 回调 state 不匹配，请重新登录"))
        try:
            sess = complete_pingone_login(pingone(), request.args.get("code", ""), pending["verifier"], pending["nonce"])
        except (PingOneError, jwt.PyJWTError, KeyError) as e:
            logger.warning("PingOne login failed: %s", e)
            return redirect(url_for("index", error=f"PingOne 登录失败：{e}"))
        session["sid"] = store.put(sess)
        return redirect(url_for("chat"))

    # ------------------------------------------------------------------ 企业微信

    @app.get("/auth/wecom/login")
    def wecom_login():
        if not cfg.wecom_enabled:
            abort(404)
        state = secrets.token_urlsafe(16)
        session["wecom_state"] = state
        return redirect(wecom.authorize_url(cfg.wecom_corp_id, cfg.wecom_agent_id, f"{cfg.app_base_url}/auth/wecom/callback",
                                            state, user_agent=request.headers.get("User-Agent")))

    @app.get("/auth/wecom/callback")
    def wecom_callback():
        state = session.pop("wecom_state", None)
        code = request.args.get("code")
        if not code:
            return redirect(url_for("index", error="企业微信未返回 code（用户取消或应用不可见）"))
        if state != request.args.get("state"):
            return redirect(url_for("index", error="企业微信回调 state 不匹配，请重新登录"))
        try:
            # 本应用不自己换 code：交给 Scutum，一次拿到 Lyra token + 企微 userid
            tok = scutum("wecom").exchange_wecom_code(code)
        except ScutumError as e:
            logger.warning("WeCom exchange failed: %s", e)
            return redirect(url_for("index", error=f"企业微信身份交换失败：{e.error} {e.description}"))
        old = current()
        if old and old.idp == "wecom" and old.subject == tok.idp_subject:
            old.scutum = tok                       # token 过期后的静默续期：保留会话与对话上下文
            old.log("token_exchange", idp="wecom", result="ok", reason="re-auth")
            return redirect(request.args.get("next") or url_for("chat"))
        sess = UserSession(idp="wecom", subject=tok.idp_subject or "", display_name=tok.idp_subject or "", scutum=tok)
        sess.log("login", idp="wecom", userid=tok.idp_subject)
        sess.log("token_exchange", idp="wecom", result="ok", expires_in=int(tok.expires_at - time.time()))
        store.drop(session.get("sid"))
        session["sid"] = store.put(sess)
        return redirect(url_for("chat"))

    # ------------------------------------------------------------------ API（前端 → 本应用 → Lyra）

    def _api_error(e: Exception):
        if isinstance(e, LoginRequired):
            return jsonify(error="login_required", reason=e.reason, login_url=e.login_url), 401
        if isinstance(e, ExchangeFailed):
            return jsonify(error="token_exchange_failed", message=f"Scutum 拒绝交换：{e.error} {e.description}".strip()), 502
        if isinstance(e, A2AError):
            return jsonify(error="lyra_error", status=e.status, message=e.message,
                           www_authenticate=e.www_authenticate), 502 if e.status >= 500 else e.status
        return jsonify(error="internal_error", message=str(e)), 500

    def _client(sess: UserSession) -> A2AClient:
        return A2AClient(cfg.lyra_base_url, ensure_token(sess), verify=cfg.http_verify)

    @app.get("/api/agents")
    def api_agents():
        sess = current()
        if not sess:
            return jsonify(error="login_required", login_url=url_for("index")), 401
        try:
            agents = _client(sess).list_agents()
        except (LoginRequired, ExchangeFailed, A2AError) as e:
            sess.log("a2a", call="list_agents", result=type(e).__name__, detail=str(e))
            return _api_error(e)
        return jsonify(agents=agents)

    @app.get("/api/agents/<agent>/card")
    def api_card(agent: str):
        sess = current()
        if not sess:
            return jsonify(error="login_required", login_url=url_for("index")), 401
        try:
            return jsonify(_client(sess).agent_card(agent))
        except (LoginRequired, ExchangeFailed, A2AError) as e:
            return _api_error(e)

    @app.post("/api/chat")
    def api_chat():
        sess = current()
        if not sess:
            return jsonify(error="login_required", login_url=url_for("index")), 401
        body = request.get_json(silent=True) or {}
        agent, text = body.get("agent") or "crm_bot", (body.get("text") or "").strip()
        if not text:
            return jsonify(error="empty_message"), 400
        if body.get("new_conversation"):
            sess.context_ids.pop(agent, None)
        try:
            client = _client(sess)
        except (LoginRequired, ExchangeFailed) as e:
            return _api_error(e)

        def events() -> Iterator[str]:
            try:
                for msg in client.stream_message(agent, text, sess.context_ids.get(agent)):
                    ctx = _context_id(msg)
                    if ctx:
                        sess.context_ids[agent] = ctx
                    yield f"data: {json.dumps(msg, ensure_ascii=False)}\n\n"
                sess.log("a2a", call="SendStreamingMessage", agent=agent, result="ok")
            except A2AError as e:
                sess.log("a2a", call="SendStreamingMessage", agent=agent, result=e.status, detail=e.message)
                yield f"event: error\ndata: {json.dumps({'status': e.status, 'message': e.message}, ensure_ascii=False)}\n\n"
            except Exception as e:  # 网络中断等：告诉前端，别让它一直转圈
                logger.exception("stream failed")
                yield f"event: error\ndata: {json.dumps({'status': 0, 'message': str(e)}, ensure_ascii=False)}\n\n"

        return Response(stream_with_context(events()), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    return app


def _pingone_checks(sess: UserSession) -> list[tuple[bool, str]]:
    """PingOne 侧配置自检：PingOne 会静默丢掉应用未授权的 scope，只看登录成功看不出问题。"""
    at, idt = _claims(sess.pingone_access_token), sess.id_token_claims
    scopes = set(str(at.get("scope", "")).split())
    auds = at.get("aud") if isinstance(at.get("aud"), list) else [at.get("aud")]
    platform = any(isinstance(a, str) and a.startswith("https://api.pingone.") for a in auds)
    return [
        ("a2a.invoke" in scopes, f"access_token scope 含 a2a.invoke（实际：{' '.join(sorted(scopes)) or '无'}）"
                                 "——否则在应用 Resources 标签勾选 Custom Resource 的 a2a.invoke"),
        (not platform, f"access_token aud 是 Scutum 而非 PingOne 平台（实际：{auds}）"
                       "——aud 为 api.pingone.* 说明没拿到 Custom Resource 的 token"),
        (bool(at.get("email")), "access_token 带 email（Scutum 按它匹配 CRM 用户）——否则在 Custom Resource 的 Attributes 映射 email"),
        (bool(idt.get("email")), "id_token 带 email——否则在应用 Resources 勾选 openid 的 email、profile"),
    ]


def _two_stage_checks(sess: UserSession, cfg: Config) -> list[tuple[bool, str]]:
    """两段交换自检：登录 token 不该带 A2A 权限；交换出的 token 要签给 Scutum、带 a2a.invoke 和 email。"""
    at, xt = _claims(sess.pingone_access_token), _claims(sess.idp_exchanged_token)
    login_scopes = set(str(at.get("scope", "")).split())
    x_scopes = set(str(xt.get("scope", "")).split())
    return [
        (cfg.idp_exchange_scope not in login_scopes,
         f"登录 access_token 不含 {cfg.idp_exchange_scope}（实际：{' '.join(sorted(login_scopes)) or '无'}）——登录 client 不应放行 A2A 权限"),
        (bool(xt), "IdP token exchange 成功——失败原因见下方事件"),
        (bool(xt) and at.get("aud") != xt.get("aud"),
         f"交换出的 token 签给另一方（登录 aud={at.get('aud')}，交换后 aud={xt.get('aud')}）"),
        (cfg.idp_exchange_scope in x_scopes, f"交换出的 token scope 含 {cfg.idp_exchange_scope}（实际：{' '.join(sorted(x_scopes)) or '无'}）"),
        (xt.get("client_id") == cfg.idp_exchange_client_id,
         f"交换出的 token client_id 是交换专用 client（实际：{xt.get('client_id')}）——Scutum 按它绑定应用"),
        (bool(xt.get("email")), "交换出的 token 带 email——否则检查 Processor Policy 和交换上下文的映射"),
    ]


def _assertion_checks(sess: UserSession, cfg: Config) -> list[tuple[bool, str]]:
    """兜底断言自检：断言 sub 要能映射到 CRM 用户；Scutum token 由断言 client 换出、指向 CRM 用户。"""
    st = _claims(sess.scutum.access_token if sess.scutum else None)
    sub = next((e.get("sub") for e in reversed(sess.events) if e.get("kind") == "assertion"), None)
    return [
        (bool(sub), f"已用私钥签发用户断言（sub={sub}）——sub 须是与 Scutum 约定的 CRM 映射字段值"),
        (bool(st), "Scutum 接受断言并签发 token——失败原因见下方事件"),
        (st.get("azp") == cfg.scutum_assertion_client_id, f"Scutum token azp 是断言 client（实际：{st.get('azp')}）"),
        (str(st.get("sub", "")).isdigit(), f"Scutum token sub 是 CRM 用户 id（实际：{st.get('sub')}）"),
        (st.get("idp") == "assertion", f"Scutum token idp=assertion（实际：{st.get('idp')}）"),
    ]


def _context_id(msg: dict) -> str | None:
    result = msg.get("result") or {}
    for key in ("statusUpdate", "artifactUpdate", "task", "message"):
        obj = result.get(key)
        if isinstance(obj, dict) and obj.get("contextId"):
            return obj["contextId"]
    return None


app = create_app()
