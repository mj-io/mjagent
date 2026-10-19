"""Lyra A2A 调用（JSON-RPC over HTTP，A2A 1.0），带 Scutum Bearer token。

- GET  {lyra}/a2a/agents                              当前用户可用的 agent 列表（Lyra 扩展端点）
- GET  {lyra}/a2a/{agent}/.well-known/agent-card.json  Agent Card（需认证，含 securitySchemes）
- POST {lyra}/a2a/{agent}/jsonrpc  SendStreamingMessage → SSE，每条 data 是一个 JSON-RPC 响应
多轮对话：把首轮响应里的 contextId 带回下一条消息。
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator

import httpx

A2A_VERSION = "1.0"


class A2AError(Exception):
    def __init__(self, status: int, message: str, www_authenticate: str | None = None):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status
        self.message = message
        self.www_authenticate = www_authenticate


class A2AClient:
    def __init__(self, base_url: str, access_token: str, *, verify: bool = True,
                 transport: httpx.BaseTransport | None = None):
        self.base_url = base_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {access_token}", "A2A-Version": A2A_VERSION}
        self._verify = verify
        self._transport = transport

    def _http(self, timeout: float | httpx.Timeout = 30.0) -> httpx.Client:
        return httpx.Client(timeout=timeout, verify=self._verify, transport=self._transport, headers=self._headers)

    def _url(self, path: str) -> str:
        return path if path.startswith("http") else f"{self.base_url}{path}"

    @staticmethod
    def _raise(resp: httpx.Response) -> None:
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("detail") or resp.text
            except ValueError:
                detail = resp.text
            raise A2AError(resp.status_code, str(detail)[:500], resp.headers.get("www-authenticate"))

    def list_agents(self) -> list[dict]:
        with self._http() as c:
            resp = c.get(self._url("/a2a/agents"))
        self._raise(resp)
        return resp.json().get("agents", [])

    def agent_card(self, agent: str) -> dict:
        with self._http() as c:
            resp = c.get(self._url(f"/a2a/{agent}/.well-known/agent-card.json"))
        self._raise(resp)
        return resp.json()

    @staticmethod
    def build_message(text: str, context_id: str | None = None) -> dict:
        msg = {"role": "ROLE_USER", "messageId": uuid.uuid4().hex, "parts": [{"text": text}]}
        if context_id:
            msg["contextId"] = context_id
        return msg

    def stream_message(self, agent: str, text: str, context_id: str | None = None) -> Iterator[dict]:
        """SendStreamingMessage：逐条产出 JSON-RPC 响应（result / error）。"""
        body = {"jsonrpc": "2.0", "id": uuid.uuid4().hex, "method": "SendStreamingMessage",
                "params": {"message": self.build_message(text, context_id)}}
        timeout = httpx.Timeout(connect=10.0, read=300.0, write=30.0, pool=10.0)
        with self._http(timeout) as c, c.stream("POST", self._url(f"/a2a/{agent}/jsonrpc"), json=body,
                                                headers={"Accept": "text/event-stream"}) as resp:
            if resp.status_code >= 400:
                resp.read()
                self._raise(resp)
            data_lines: list[str] = []
            for line in resp.iter_lines():
                if line.startswith("data:"):
                    data_lines.append(line[5:].lstrip())
                elif line == "" and data_lines:
                    yield json.loads("\n".join(data_lines))
                    data_lines = []
            if data_lines:
                yield json.loads("\n".join(data_lines))
