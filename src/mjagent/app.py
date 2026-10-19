"""mjagent：模拟客户的第三方 agent 应用。

用户用客户自己的 IdP 登录（PingOne / 企业微信），本应用在服务端把登录态交给 Scutum 换 Lyra A2A 的 Bearer token，
再代用户调用 Lyra agent。浏览器只拿到本应用的会话 cookie，任何 token 都不下发到前端。
"""

from __future__ import annotations

import json
import logging
import secrets
import time
from collections.abc import Iterator

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
from mjagent.config import Config, load_config
from mjagent.pingone import PingOneClient, PingOneError, pkce_pair
from mjagent.scutum_client import ScutumClient, ScutumError
from mjagent.store import SessionStore, UserSession

logger = logging.getLogger("mjagent")


class LoginRequired(Exception):
    def __init__(self, login_url: str, reason: str):
        super().__init__(reason)
        self.login_url = login_url
        self.reason = reason


class ExchangeFailed(Exception):
    """登录态有效但 Scutum 拒绝交换：重新登录解决不了（会无限跳转），直接把原因交给前端。"""

    def __init__(self, err: ScutumError):
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
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                      SESSION_COOKIE_SECURE=cfg.app_base_url.startswith("https://"))
    app.extensions["mjagent.cfg"] = cfg
    store = SessionStore()
    app.extensions["mjagent.store"] = store

    def pingone() -> PingOneClient:
        return PingOneClient(cfg.pingone_issuer, cfg.pingone_client_id, cfg.pingone_client_secret, cfg.pingone_scopes,
                             f"{cfg.app_base_url}/auth/pingone/callback", verify=cfg.http_verify)

    def scutum(idp: str) -> ScutumClient:
        if idp == "wecom":
            return ScutumClient(cfg.scutum_issuer, cfg.scutum_wecom_client_id, cfg.scutum_wecom_client_secret,
                                resource=cfg.lyra_resource, verify=cfg.http_verify)
        return ScutumClient(cfg.scutum_issuer, cfg.scutum_pingone_client_id, cfg.scutum_pingone_client_secret,
                            resource=cfg.lyra_resource, verify=cfg.http_verify)

    def current() -> UserSession | None:
        return store.get(session.get("sid"))

    def login_url_for(idp: str) -> str:
        return url_for("wecom_login") if idp == "wecom" else url_for("pingone_login")

    def ensure_token(sess: UserSession) -> str:
        """拿一张有效的 Lyra token：未过期直接用；PingOne 用户在 PingOne token 有效期内静默重新交换；否则重新登录。"""
        if sess.scutum and not sess.scutum.expired:
            return sess.scutum.access_token
        if sess.idp == "pingone" and sess.pingone_access_token and time.time() < sess.pingone_expires_at - 30:
            kind = cfg.pingone_subject_token
            subject = sess.pingone_id_token if kind == "id_token" else sess.pingone_access_token
            try:
                sess.scutum = scutum("pingone").exchange_pingone(subject, token_kind=kind)
                sess.log("token_exchange", idp="pingone", result="ok", reason="re-exchange")
                return sess.scutum.access_token
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
        return render_template("index.html", cfg=cfg, error=request.args.get("error"))

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
        tokens = {
            "PingOne id_token": _claims(sess.pingone_id_token),
            "PingOne access_token（签给 Scutum）": _claims(sess.pingone_access_token),
            "Scutum access_token（签给 Lyra）": _claims(sess.scutum.access_token if sess.scutum else None),
        }
        return render_template("debug.html", cfg=cfg, user=sess, tokens={k: v for k, v in tokens.items() if v},
                               checks=_pingone_checks(sess) if sess.idp == "pingone" else [],
                               events=list(reversed(sess.events)))

    @app.get("/logout")
    def logout():
        store.drop(session.pop("sid", None))
        return redirect(url_for("index"))

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
        client = pingone()
        try:
            tok = client.exchange_code(request.args.get("code", ""), pending["verifier"])
            claims = client.verify_id_token(tok["id_token"], pending["nonce"])
        except (PingOneError, jwt.PyJWTError, KeyError) as e:
            logger.warning("PingOne login failed: %s", e)
            return redirect(url_for("index", error=f"PingOne 登录失败：{e}"))
        sess = UserSession(idp="pingone", subject=claims["sub"], email=claims.get("email"),
                           display_name=claims.get("name") or claims.get("preferred_username") or claims.get("email") or claims["sub"],
                           id_token_claims=claims, pingone_access_token=tok.get("access_token"),
                           pingone_id_token=tok["id_token"], pingone_expires_at=time.time() + int(tok.get("expires_in", 3600)))
        sess.log("login", idp="pingone", sub=claims["sub"], email=claims.get("email"), scope=tok.get("scope"))
        kind = cfg.pingone_subject_token
        try:
            sess.scutum = scutum("pingone").exchange_pingone(
                sess.pingone_id_token if kind == "id_token" else sess.pingone_access_token or "", token_kind=kind)
            sess.log("token_exchange", idp="pingone", result="ok", subject_token=kind, expires_in=int(sess.scutum.expires_at - time.time()))
        except ScutumError as e:
            # 登录本身成功（客户应用自己的会话），只是换不到 Lyra token：照样进入，聊天时提示原因
            sess.log("token_exchange", idp="pingone", result=e.error, detail=e.description)
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


def _context_id(msg: dict) -> str | None:
    result = msg.get("result") or {}
    for key in ("statusUpdate", "artifactUpdate", "task", "message"):
        obj = result.get(key)
        if isinstance(obj, dict) and obj.get("contextId"):
            return obj["contextId"]
    return None


app = create_app()
