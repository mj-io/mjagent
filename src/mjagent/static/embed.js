// iframe 内的客户应用：顶层弹窗完成 PingOne 登录，postMessage 交回一次性 code（轮询兜底），再建立 iframe 自己的会话。
// 会话两条通道：Partitioned cookie（浏览器允许时）+ 内存 session token（cookie 被拦截时随请求头带上）。token 不落任何存储。
(function () {
  const $ = (id) => document.getElementById(id);
  const cfg = $("embed-cfg").dataset;
  const ORIGIN = cfg.origin;
  const HOST_URL = new URLSearchParams(location.search).get("host_url") || "";
  const K_TOKEN = "mjagent_embed_token", K_PENDING = "mjagent_embed_pending";
  // sessionStorage 在第三方 iframe 里按顶层站点分区、按标签页隔离：顶层跳走再回来仍在（WebKit / 企业微信 iOS 也可用）
  const ss = {
    get(k) { try { return sessionStorage.getItem(k); } catch (e) { return null; } },
    set(k, v) { try { sessionStorage.setItem(k, v); return true; } catch (e) { return false; } },
    del(k) { try { sessionStorage.removeItem(k); } catch (e) { /* ignore */ } },
  };
  let sessionToken = ss.get(K_TOKEN);
  let topNav = null;   // {binding, url}：弹窗不可用时的顶层跳转地址，加载时预先算好（点击时必须同步跳转）

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

  async function sha256hex(text) {
    const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return Array.from(new Uint8Array(d), (b) => b.toString(16).padStart(2, "0")).join("");
  }

  async function prepareTopNav() {
    if (!HOST_URL) return;
    const binding = randomHex(32);
    const bh = await sha256hex(binding);
    topNav = { binding, url: `${ORIGIN}/embed/auth/top?bh=${bh}&return=${encodeURIComponent(HOST_URL)}` };
  }

  function goTop() {
    // 流程 B：弹窗不可用（iOS 企业微信 WKWebView 的 window.open 返回 null）→ 在同一个点击的同步调用栈里导航顶层窗口
    if (!topNav) { step("无法顶层跳转：宿主页未传 host_url", "bad"); return; }
    if (!ss.set(K_PENDING, topNav.binding)) { step("sessionStorage 不可用，跳回后无法完成登录", "bad"); return; }
    step("弹窗不可用，改为顶层跳转登录（完成后回到本页）", "warn");
    try {
      window.top.location.href = topNav.url;
    } catch (e) {
      // sandbox 缺 allow-top-navigation-by-user-activation，或浏览器不认这次点击：给一个原生 target=_top 链接再点一次
      step("顶层跳转被拒绝：" + e.message + "；请点下方链接", "bad");
      const a = document.createElement("a");
      a.href = topNav.url; a.target = "_top"; a.textContent = "前往登录"; a.className = "btn small primary";
      $("steps").appendChild(a);
    }
  }

  async function resumeTopNav() {
    // 从顶层跳转回来：iframe 重新加载，凭 sessionStorage 里的 binding 向服务端确认登录结果
    const binding = ss.get(K_PENDING);
    if (!binding) return false;
    step("检测到未完成的顶层跳转登录，正在确认…");
    for (let i = 0; i < 5; i++) {
      const s = await fetch("/embed/auth/status", { headers: { "X-Embed-Binding": binding } }).then((x) => x.json()).catch(() => ({}));
      if (s.status === "done") { ss.del(K_PENDING); await finish({ flow_id: s.flow_id }, binding); return true; }
      if (s.status === "error") { ss.del(K_PENDING); step("登录失败：" + (s.error || ""), "bad"); return false; }
      if (s.status === "unknown") break;
      await new Promise((r) => setTimeout(r, 800));
    }
    ss.del(K_PENDING);
    step("没有找到已完成的登录（可能已取消或超时），请重新登录", "warn");
    return false;
  }

  // ---------------------------------------------------------------- 登录：A 弹窗 + postMessage（轮询兜底）/ B 顶层跳转
  $("login").addEventListener("click", async () => {
    // 必须在点击回调里**同步**打开弹窗（先 about:blank），await 之后再开会被浏览器拦截
    const popup = window.open("about:blank", "mjagent-login", "width=480,height=680");
    if (!popup) { goTop(); return; }
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
    ss.set(K_TOKEN, sessionToken);   // cookie 被拦截（WebKit）时整页重载后仍能续用；分区存储，宿主外不可见
    step(`finish 成功（${body.via}）；begin 时下发的分区 flow cookie ${body.flow_cookie_seen ? "已带回" : "未带回"}`, "ok");
    await whoami();
  }

  $("logout").addEventListener("click", async () => {
    await api("/embed/logout", { method: "POST" });
    sessionToken = null;
    ss.del(K_TOKEN);
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

  (async () => {
    await diagnose();
    setEnv("宿主页地址（host_url）", HOST_URL || "未传入");
    prepareTopNav().catch((e) => step("准备顶层跳转失败：" + e.message, "bad"));
    if (!(await resumeTopNav())) await whoami();
  })();
})();
