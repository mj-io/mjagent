"""iframe 嵌入登录：宿主页（如 CRM）用 iframe 嵌入本应用时，在**顶层弹窗**里完成 PingOne 授权码登录。

为什么不在 iframe 内直接跳 IdP：IdP 登录页带 frame-ancestors 'none'（拒绝被嵌入）；iframe 是第三方上下文，
IdP 会话 cookie 带不上、本应用 cookie 被分区或拦截。弹窗是顶层窗口：IdP 页面正常渲染、cookie 是第一方、SSO 通常一闪而过。

流程（弹窗 + postMessage，轮询兜底）：
  iframe  POST /embed/auth/begin {binding}      → flow_id；同时下发 Partitioned cookie embed_flow（仅作观测）
          window.open → /embed/auth/start?flow_id   （window.open 必须在点击里同步调用，先开 about:blank）
  弹窗    → PingOne /authorize（redirect_uri = 本域 /embed/auth/callback）→ 回调：服务端换 token、建会话
          → 回调页 window.opener.postMessage({type, code}, 本源) ；code 为一次性 handoff code（60 秒，单次）
  iframe  POST /embed/auth/finish {code, binding} → 会话 cookie（SameSite=None; Secure; Partitioned）+ 内存 session_token
          COOP 切断 opener 时 postMessage 收不到：iframe 轮询 /embed/auth/status，完成后用 {flow_id, binding} finish

防登录 CSRF / 会话固定：finish 必须带上发起 begin 的那个 iframe 的 binding（iframe 内存里的随机值，只提交其 SHA-256），
攻击者拿到自己账号的 handoff code 也塞不进受害者的 iframe。binding 不依赖 cookie，Safari 等彻底拦截第三方 cookie 时同样成立；
partitioned cookie 若存在则额外校验一致。token 一律留在服务端，浏览器只见 handoff code 与本应用会话。
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

FLOW_TTL = 600
HANDOFF_TTL = 60
TOKEN_TTL = 8 * 3600
FLOW_COOKIE = "embed_flow"
SESSION_HEADER = "X-Embed-Session"


def _h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def origin_of(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


@dataclass
class Flow:
    binding_hash: str
    created: float = field(default_factory=time.time)
    status: str = "pending"            # pending → started → done | error
    state: str | None = None
    nonce: str | None = None
    verifier: str | None = None
    sid: str | None = None
    error: str | None = None
    user: dict = field(default_factory=dict)


class EmbedFlows:
    """进程内存储（单进程部署足够演示；多实例应换 Redis）。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.flows: dict[str, Flow] = {}
        self._by_state: dict[str, str] = {}
        self._handoffs: dict[str, tuple[str, float]] = {}
        self._tokens: dict[str, tuple[str, float]] = {}

    def _gc(self) -> None:
        now = time.time()
        for k in [k for k, f in self.flows.items() if now - f.created > FLOW_TTL]:
            self.flows.pop(k, None)
        for k in [k for k, (_, exp) in self._handoffs.items() if exp <= now]:
            self._handoffs.pop(k, None)
        for k in [k for k, (_, exp) in self._tokens.items() if exp <= now]:
            self._tokens.pop(k, None)
        self._by_state = {s: f for s, f in self._by_state.items() if f in self.flows}

    def begin(self, binding: str) -> str:
        with self._lock:
            self._gc()
            flow_id = secrets.token_urlsafe(24)
            self.flows[flow_id] = Flow(binding_hash=_h(binding))
            return flow_id

    def get(self, flow_id: str | None) -> Flow | None:
        with self._lock:
            f = self.flows.get(flow_id or "")
            return f if f and time.time() - f.created <= FLOW_TTL else None

    def attach_state(self, flow_id: str, state: str) -> None:
        with self._lock:
            self._by_state[state] = flow_id

    def by_state(self, state: str | None) -> tuple[str, Flow] | None:
        with self._lock:
            flow_id = self._by_state.pop(state or "", None)
            f = self.flows.get(flow_id or "")
            return (flow_id, f) if f else None

    def issue_handoff(self, flow_id: str) -> str:
        with self._lock:
            code = secrets.token_urlsafe(32)          # 256 bit
            self._handoffs[code] = (flow_id, time.time() + HANDOFF_TTL)
            return code

    def consume(self, *, binding: str, code: str | None = None, flow_id: str | None = None) -> tuple[Flow | None, str]:
        """finish：用 handoff code（主通道）或 flow_id（轮询兜底）取完成的 flow，校验 binding，单次有效。"""
        with self._lock:
            if code:
                hit = self._handoffs.pop(code, None)
                if not hit or hit[1] <= time.time():
                    return None, "handoff code invalid, used or expired"
                flow_id = hit[0]
            f = self.flows.get(flow_id or "")
            if f is None:
                return None, "flow not found or expired"
            if not hmac.compare_digest(f.binding_hash, _h(binding or "")):
                return None, "binding mismatch"          # 不是发起这次登录的 iframe
            if f.status != "done" or not f.sid:
                return None, f"flow not completed ({f.status})"
            self.flows.pop(flow_id, None)                # 单次有效：flow 与其 handoff 一起作废
            for k in [k for k, (fid, _) in self._handoffs.items() if fid == flow_id]:
                self._handoffs.pop(k, None)
            return f, "ok"

    def binding_ok(self, f: Flow, binding: str | None) -> bool:
        return hmac.compare_digest(f.binding_hash, _h(binding or ""))

    def issue_session_token(self, sid: str) -> str:
        with self._lock:
            token = secrets.token_urlsafe(32)
            self._tokens[token] = (sid, time.time() + TOKEN_TTL)
            return token

    def sid_for_token(self, token: str | None) -> str | None:
        with self._lock:
            hit = self._tokens.get(token or "")
            return hit[0] if hit and hit[1] > time.time() else None

    def drop_token(self, token: str | None) -> None:
        with self._lock:
            self._tokens.pop(token or "", None)
