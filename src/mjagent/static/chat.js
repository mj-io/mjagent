// 对话页：浏览器 → mjagent /api/chat（SSE）→ Lyra A2A SendStreamingMessage。
// 浏览器只认 mjagent 的会话 cookie，Lyra 的 Bearer token 留在服务端。
(function () {
  const $ = (id) => document.getElementById(id);
  const log = $("log"), input = $("input"), agentSel = $("agent"), notice = $("notice"), sendBtn = $("send");
  let newConversation = false;

  function showNotice(text) { notice.textContent = text; notice.hidden = !text; }

  function handleAuth(res, body) {
    if (res.status === 401 && body && body.login_url) {
      showNotice("登录已过期，正在重新登录…");
      location.href = body.login_url;   // 企微内为静默授权；PingOne 有 SSO 会话时同样无感
      return true;
    }
    return false;
  }

  function bubble(role, text) {
    const el = document.createElement("div");
    el.className = "msg " + role;
    const body = document.createElement("div");
    body.className = "body";
    body.textContent = text || "";
    el.appendChild(body);
    const status = document.createElement("div");
    status.className = "status";
    el.appendChild(status);
    log.appendChild(el);
    log.scrollTop = log.scrollHeight;
    return { el, body, status };
  }

  function partsOf(obj) { return (obj && obj.parts) || []; }
  function textOf(parts) { return parts.map((p) => p.text || "").join(""); }
  function dataOf(parts) { return parts.filter((p) => p.data !== undefined).map((p) => p.data); }

  function renderData(b, data) {
    if (!data.length) return;
    const pre = document.createElement("details");
    pre.innerHTML = "<summary>结构化内容（A2UI / data part）</summary>";
    const code = document.createElement("pre");
    code.textContent = JSON.stringify(data.length === 1 ? data[0] : data, null, 2);
    pre.appendChild(code);
    b.el.appendChild(pre);
  }

  // 把一条 JSON-RPC 流式响应渲染进当前 agent 气泡
  function apply(b, msg, acc) {
    if (msg.error) { b.status.textContent = "错误：" + (msg.error.message || JSON.stringify(msg.error)); b.el.classList.add("failed"); return; }
    const r = msg.result || {};
    if (r.artifactUpdate) {
      const parts = partsOf(r.artifactUpdate.artifact);
      const t = textOf(parts);
      acc.text = r.artifactUpdate.append ? acc.text + t : (t || acc.text);
      b.body.textContent = acc.text;
      renderData(b, dataOf(parts));
    } else if (r.statusUpdate || r.task) {
      const status = (r.statusUpdate || r.task).status || {};
      const parts = partsOf(status.message);
      const t = textOf(parts);
      const state = status.state || "";
      if (state.endsWith("WORKING") || state.endsWith("SUBMITTED")) {
        if (t) b.status.textContent = t;
      } else if (state.endsWith("COMPLETED") || state.endsWith("INPUT_REQUIRED")) {
        if (t && !acc.text) { acc.text = t; b.body.textContent = t; }
        renderData(b, dataOf(parts));
        b.status.textContent = state.endsWith("INPUT_REQUIRED") ? "等待输入" : "";
      } else if (state.endsWith("FAILED") || state.endsWith("REJECTED") || state.endsWith("CANCELED")) {
        b.status.textContent = (t || "请求处理失败") + "（" + state + "）";
        b.el.classList.add("failed");
      }
    } else if (r.message) {
      const parts = partsOf(r.message);
      const t = textOf(parts);
      if (t) { acc.text = t; b.body.textContent = t; }
      renderData(b, dataOf(parts));
    }
    log.scrollTop = log.scrollHeight;
  }

  async function loadAgents() {
    const res = await fetch("/api/agents");
    const body = await res.json().catch(() => ({}));
    if (handleAuth(res, body)) return;
    if (!res.ok) {
      agentSel.innerHTML = "<option value='crm_bot'>crm_bot</option>";
      showNotice("获取 agent 列表失败：" + (body.message || body.error || res.status) + (body.www_authenticate ? "\n" + body.www_authenticate : ""));
      return;
    }
    agentSel.innerHTML = "";
    for (const a of body.agents) {
      const opt = document.createElement("option");
      opt.value = a.key; opt.textContent = a.name + "（" + a.key + "）";
      agentSel.appendChild(opt);
    }
    if (!body.agents.length) showNotice("当前用户没有可用的 agent");
  }

  async function send(text) {
    bubble("user", text);
    const b = bubble("agent", "");
    b.status.textContent = "发送中…";
    sendBtn.disabled = true;
    const acc = { text: "" };
    try {
      const res = await fetch("/api/chat", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ agent: agentSel.value, text, new_conversation: newConversation }),
      });
      newConversation = false;
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        if (handleAuth(res, body)) return;
        b.status.textContent = "失败：" + (body.message || body.error || res.status);
        b.el.classList.add("failed");
        return;
      }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        let idx;
        while ((idx = buf.indexOf("\n\n")) >= 0) {
          const frame = buf.slice(0, idx); buf = buf.slice(idx + 2);
          const isError = /^event: error$/m.test(frame);
          const data = frame.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trim()).join("\n");
          if (!data) continue;
          const msg = JSON.parse(data);
          if (isError) { b.status.textContent = "Lyra 返回错误：" + msg.status + " " + msg.message; b.el.classList.add("failed"); }
          else apply(b, msg, acc);
        }
      }
      if (b.status.textContent === "发送中…") b.status.textContent = "";
    } catch (e) {
      b.status.textContent = "网络错误：" + e.message;
      b.el.classList.add("failed");
    } finally {
      sendBtn.disabled = false;
      input.focus();
    }
  }

  $("composer").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const text = input.value.trim();
    if (!text) return;
    input.value = "";
    send(text);
  });
  input.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" && !ev.shiftKey && !ev.isComposing) { ev.preventDefault(); $("composer").requestSubmit(); }
  });
  $("new").addEventListener("click", () => { newConversation = true; log.innerHTML = ""; showNotice(""); input.focus(); });

  loadAgents();
})();
