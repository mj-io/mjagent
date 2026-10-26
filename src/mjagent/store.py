"""服务端会话存储：token 不进浏览器 cookie（PingOne / Scutum token 合计会超过 4KB，也不该暴露给前端）。

进程内字典，单进程部署（gunicorn -w 1 --threads N）足够演示；生产应换 Redis 等共享存储。
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field

from mjagent.scutum_client import ScutumToken

_TTL_SECONDS = 8 * 3600


@dataclass
class UserSession:
    idp: str                                   # pingone | wecom
    subject: str                               # PingOne sub / 企微 userid
    display_name: str = ""
    email: str | None = None
    id_token_claims: dict = field(default_factory=dict)
    pingone_access_token: str | None = None    # 签给 Scutum 的 PingOne token（重新交换用）
    pingone_id_token: str | None = None
    idp_exchanged_token: str | None = None     # 两段交换：IdP 换出的、签给 Scutum 的 token（调试页展示）
    pingone_expires_at: float = 0
    scutum: ScutumToken | None = None
    context_ids: dict[str, str] = field(default_factory=dict)   # agent → 当前会话 contextId
    events: list[dict] = field(default_factory=list)            # 调试页的交换 / 调用记录
    created_at: float = field(default_factory=time.time)

    def log(self, kind: str, **detail) -> None:
        self.events.append({"at": time.strftime("%H:%M:%S"), "kind": kind, **detail})
        del self.events[:-30]


class SessionStore:
    def __init__(self) -> None:
        self._data: dict[str, UserSession] = {}
        self._lock = threading.Lock()

    def put(self, sess: UserSession) -> str:
        sid = secrets.token_urlsafe(24)
        with self._lock:
            self._gc()
            self._data[sid] = sess
        return sid

    def get(self, sid: str | None) -> UserSession | None:
        if not sid:
            return None
        with self._lock:
            sess = self._data.get(sid)
            if sess and time.time() - sess.created_at > _TTL_SECONDS:
                self._data.pop(sid, None)
                return None
            return sess

    def drop(self, sid: str | None) -> None:
        with self._lock:
            self._data.pop(sid or "", None)

    def _gc(self) -> None:
        now = time.time()
        for k in [k for k, v in self._data.items() if now - v.created_at > _TTL_SECONDS]:
            self._data.pop(k, None)
