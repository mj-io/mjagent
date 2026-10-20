// iframe 内的客户应用：顶层弹窗完成 PingOne 登录，postMessage 交回一次性 code（轮询兜底），再建立 iframe 自己的会话。
// 会话两条通道：Partitioned cookie（浏览器允许时）+ 内存 session token（cookie 被拦截时随请求头带上）。token 不落任何存储。
(function () {
  const $ = (id) => document.getElementById(id);
  const cfg = $("embed-cfg").dataset;
  const ORIGIN = cfg.origin;
  let sessionToken = null;

  function step(text, cls) {
    const li = document.createElement("li");
    li.textContent = `${new Date().toLocaleTimeString()}  ${text}`;
    if (cls) li.className = cls;
    $("steps").appendChild(li);
  }

  function headers(extra) {
    const h = Object.assign({}, extra || {});
    if (sessionToken) h[cfg.sessionHeader] = sessionToken;
    return h;
  }
  const api = (url, opts = {}) => fetch(url, Object.assign({ credentials: "include" }, opts, { headers: headers(opts.headers) }));

  function randomHex(bytes) {
    const a = new Uint8Array(bytes);
    crypto.getRandomValues(a);
    return Array.from(a, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  // ---------------------------------------------------------------- 环境诊断
  async function diagnose() {
    const inIframe = window.top !== window.self;
    let topOrigin = "-";
    try { topOrigin = (location.ancestorOrigins && location.ancestorOrigins[0]) || (inIframe ? "（跨域，不可读）" : location.origin); } catch (e) { /* ignore */ }
    document.cookie = "js_probe=1; Path=/embed; SameSite=None; Secure; Partitioned";
    const jsCookie = document.cookie.includes("js_probe=1");
    let storageAccess = "不支持 Storage Access API";
    if (document.hasStorageAccess) {
      try { storageAccess = (await document.hasStorageAccess()) ? "已有（未分区 cookie 可用）" : "没有（第三方未分区 cookie 不可用）"; } catch (e) { storageAccess = "查询失败"; }
    }
    const rows = [
      ["运行位置", inIframe ? "iframe（第三方上下文）" : "顶层窗口（第一方）"],
      ["宿主源", topOrigin],
      ["JS 写 Partitioned cookie", jsCookie ? "可以" : "被拦截"],
      ["hasStorageAccess", storageAccess],
    ];
    $("env").innerHTML = "";
    for (const [k, v] of rows) {
      const dt = document.createElement("dt"); dt.textContent = k;
      const dd = document.createElement("dd"); dd.textContent = v; dd.id = "env-" + k;
      $("env").append(dt, dd);
    }
  }

  function setEnv(key, value) {
    let dd = document.getElementById("env-" + key);
    if (!dd) {
      const dt = document.createElement("dt"); dt.textContent = key;
      dd = document.createElement("dd"); dd.id = "env-" + key;
      $("env").append(dt, dd);
    }
    dd.textContent = value;
  }

  // ---------------------------------------------------------------- 会话状态
  async function whoami() {
    const r = await api("/embed/whoami").then((x) => x.json());
    setEnv("会话通道", r.logged_in ? (r.channel === "cookie" ? "Partitioned 会话 cookie" : "内存 token（请求头）——会话 cookie 未带回") : "未登录");
    setEnv("请求带回会话 cookie", r.session_cookie_seen ? "是" : "否");
    setEnv("Lyra token", r.logged_in ? (r.lyra_token ? "已换到" : "未换到（见交换错误）") : "-");
    $("who").textContent = r.logged_in ? `${r.user.name || ""} ${r.user.email ? "· " + r.user.email : ""}` : "";
    $("login").hidden = r.logged_in;
    $("logout").hidden = !r.logged_in;
    $("chat").hidden = !r.logged_in;
    if (r.logged_in) loadAgents();
    return r;
  }

  // ---------------------------------------------------------------- 登录：弹窗 + postMessage + 轮询兜底
  $("login").addEventListener("click", async () => {
    // 必须在点击回调里**同步**打开弹窗（先 about:blank），await 之后再开会被浏览器拦截
    const popup = window.open("about:blank", "mjagent-login", "width=480,height=680");
    if (!popup) { step("弹窗被浏览器拦截：请允许本站弹窗后重试", "bad"); return; }
    step("已在点击中同步打开顶层弹窗");
    const binding = randomHex(32);          // 只在本 iframe 内存里；服务端只存其 SHA-256
    let r;
    try {
      r = await api("/embed/auth/begin", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ binding }) })
        .then((x) => x.json());
    } catch (e) { popup.close(); step("begin 失败：" + e.message, "bad"); return; }
    const flowId = r.flow_id;
    step(`begin 完成，flow=${flowId.slice(0, 8)}…；弹窗跳转 PingOne`);
    popup.location.href = r.start_url;

    let done = false;
    const stop = () => { done = true; window.removeEventListener("message", onMsg); clearInterval(timer); };
    const onMsg = async (e) => {
      if (e.origin !== ORIGIN || e.source !== popup || !e.data || e.data.type !== "mjagent-login") return;
      if (done) return;
      stop();
      step("收到弹窗 postMessage（已校验 origin 与 source）");
      await finish({ code: e.data.code }, binding);
    };
    window.addEventListener("message", onMsg);
    // 兜底：IdP 返回 COOP same-origin 会永久切断 opener，postMessage 收不到 → 轮询服务端
    const timer = setInterval(async () => {
      if (done) return;
      const s = await fetch(`/embed/auth/status?flow_id=${encodeURIComponent(flowId)}`, { headers: { "X-Embed-Binding": binding } })
        .then((x) => x.json()).catch(() => ({}));
      if (s.status === "done") { stop(); step("轮询发现登录已完成（postMessage 未到达，可能 opener 被切断）", "warn"); await finish({ flow_id: flowId }, binding); }
      else if (s.status === "error") { stop(); step("登录失败：" + (s.error || ""), "bad"); }
      else if (popup.closed && s.status !== "done") { /* 用户关掉了弹窗：继续等几轮，回调可能刚好在关闭前完成 */ }
    }, 1500);
    setTimeout(() => { if (!done) { stop(); step("登录超时（5 分钟）", "bad"); } }, 5 * 60 * 1000);
  });

  async function finish(payload, binding) {
    const r = await api("/embed/auth/finish", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(Object.assign({ binding }, payload)) });
    const body = await r.json().catch(() => ({}));
    if (!r.ok) { step(`finish 失败：${body.message || r.status}`, "bad"); return; }
    sessionToken = body.session_token;
    step(`finish 成功（${body.via}）；begin 时下发的分区 flow cookie ${body.flow_cookie_seen ? "已带回" : "未带回"}`, "ok");
    await whoami();
  }

  $("logout").addEventListener("click", async () => {
    await api("/embed/logout", { method: "POST" });
    sessionToken = null;
    $("log").innerHTML = "";
    step("已退出");
    whoami();
  });

  // ---------------------------------------------------------------- 对话（与 /chat 相同的后端接口）
  async function loadAgents() {
    const r = await api("/api/agents");
    const body = await r.json().catch(() => ({}));
    const sel = $("agent");
    sel.innerHTML = "";
    if (!r.ok) { step("获取 agent 列表失败：" + (body.message || body.error || r.status), "bad"); return; }
    for (const a of body.agents) {
      const o = document.createElement("option"); o.value = a.key; o.textContent = `${a.name}（${a.key}）`; sel.appendChild(o);
    }
  }

  function bubble(role, text) {
    const el = document.createElement("div");
    el.className = "msg " + role;
    const b = document.createElement("div"); b.className = "body"; b.textContent = text; el.appendChild(b);
    $("log").appendChild(el);
    $("log").scrollTop = $("log").scrollHeight;
    return b;
  }

  const textOf = (parts) => (parts || []).map((p) => p.text || "").join("");

  $("composer").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const text = $("input").value.trim();
    if (!text) return;
    $("input").value = "";
    bubble("user", text);
    const out = bubble("agent", "…");
    const res = await api("/api/chat", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ agent: $("agent").value, text }) });
    if (!res.ok) { const b = await res.json().catch(() => ({})); out.textContent = "失败：" + (b.message || b.error || res.status); return; }
    const reader = res.body.getReader(); const dec = new TextDecoder(); let buf = "", acc = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf("\n\n")) >= 0) {
        const frame = buf.slice(0, i); buf = buf.slice(i + 2);
        const data = frame.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trim()).join("\n");
        if (!data) continue;
        const msg = JSON.parse(data);
        if (/^event: error$/m.test(frame)) { out.textContent = "Lyra 错误：" + msg.message; continue; }
        const r = msg.result || {};
        if (r.artifactUpdate) { const t = textOf(r.artifactUpdate.artifact && r.artifactUpdate.artifact.parts); acc = r.artifactUpdate.append ? acc + t : (t || acc); }
        const st = (r.statusUpdate || r.task || {}).status || {};
        if (/COMPLETED|INPUT_REQUIRED/.test(st.state || "") && !acc) acc = textOf(st.message && st.message.parts);
        if (/FAILED/.test(st.state || "")) acc = "失败：" + textOf(st.message && st.message.parts);
        if (r.message) acc = textOf(r.message.parts) || acc;
        out.textContent = acc || "…";
      }
    }
  });
  $("input").addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" && !ev.shiftKey && !ev.isComposing) { ev.preventDefault(); $("composer").requestSubmit(); }
  });

  diagnose().then(whoami);
})();
