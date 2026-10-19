# mjagent

模拟**客户的第三方 agent 应用**：用户用客户自己的身份系统（PingOne / 企业微信）登录，应用在服务端把登录态交给 Veeva 认证中心 **Scutum**
做 Token Exchange，换回签给 **Lyra A2A** 的 Bearer token，再代用户调用 Lyra agent。客户不需要接 CRM 的登录，也不需要让用户再授权一次。

关联：Jira ORI-159317；设计「认证中心支持ai应用授权鉴权流程」及子文档「Token Exchange 接入方案」（wiki ORI 空间）。

```
浏览器 / 企业微信 ──登录──▶ mjagent ──(1) 客户 IdP 登录──▶ PingOne（OIDC）/ 企业微信 OAuth
                              │
                              ├──(2) POST /oauth/token  grant_type=token-exchange ──▶ Scutum
                              │      PingOne：subject_token = PingOne 签给 Scutum 的 access_token
                              │      企业微信：subject_token = 企微回调 code（本应用不自己换）
                              │◀── access_token（aud=Lyra A2A，sub=CRM 用户，act=本应用）
                              │
                              └──(3) Authorization: Bearer ──▶ Lyra /a2a/agents、/a2a/{agent}/jsonrpc
```

浏览器只持有 mjagent 的会话 cookie，所有 token 都留在服务端（`src/mjagent/store.py`）。

## 客户的开发量

| 步骤 | PingOne | 企业微信 |
| --- | --- | --- |
| 登录 | 标准 OIDC 授权码，scope 多带一个 `a2a.invoke` | 标准企微网页授权（企微内 `snsapi_base` 静默 / 浏览器扫码） |
| 换 token | 把 PingOne 的 access_token 交给 Scutum | 把企微回调的 `code` 交给 Scutum，响应里的 `idp_subject` 就是企微 userid |
| 调 Lyra | 请求头带 `Authorization: Bearer <token>` | 同左 |
| 续期 | token 过期后在 PingOne token 有效期内重新交换 | 再走一次（静默的）企微授权，拿新 code 交换 |

整个对接只依赖 [`src/mjagent/scutum_client.py`](src/mjagent/scutum_client.py)（约 100 行，无第三方 SDK）。

## 配置清单

### 1. PingOne（客户管理员在 PingOne 控制台）

| 位置 | 配置 |
| --- | --- |
| Applications → **Resources** → `+` | 新建 Custom Resource，**Audience** 填 Scutum 的标识（如 `https://scutum-auth-login.crmdev.veevasfa.com`，即 Scutum 侧 `exchange_audience`） |
| 该 Resource → **Scopes** | 新增 `a2a.invoke` |
| 该 Resource → **Attributes** | 新增 `email` → Email Address（Scutum 按 email 匹配 CRM 用户） |
| Applications → mjagent（OIDC Web App） | Resources 勾选 `a2a.invoke`；Redirect URI 登记 `{APP_BASE_URL}/auth/pingone/callback`；Token Auth Method = Client Secret Basic；PKCE 可选 S256 |

### 2. 企业微信（客户管理员在企微管理后台，自建应用）

- 网页授权及 JS-SDK → **可信域名** = mjagent 域名（需备案；校验文件放到 `deploy/wecom-verify/`）
- **企业可信 IP** 加上 **Scutum 的出口 IP**（换 userid 是 Scutum 调企微，不是 mjagent）
- 应用主页 = `{APP_BASE_URL}/`
- 记下 corpid、agentid、应用 secret（secret 配到 Scutum，mjagent 不需要）

### 3. Scutum（Veeva 侧，管理 API，`X-Admin-Token`）

```bash
S=https://scutum-auth-login.crmdev.veevasfa.com; H="X-Admin-Token: $SCUTUM_ADMIN_TOKEN"
LYRA_RESOURCE=https://wchat-auth-login.crmdev.veevasfa.com/lyra/a2a

# PingOne 作为受信 subject token 签发方
curl -sX POST $S/admin/idps -H "$H" -H 'Content-Type: application/json' -d '{
  "name":"pingone","type":"pingone","tenant_id":"<PingOne Environment ID>","client_id":"-","identity_claim":"email",
  "exchange_enabled":true,"exchange_audience":"https://scutum-auth-login.crmdev.veevasfa.com","exchange_required_scopes":["a2a.invoke"]}'
# 非 .com 区域另加 "discovery_url":"https://auth.pingone.asia/<env>/as/.well-known/openid-configuration"

# mjagent 的 PingOne 交换 client → 记下返回的 client_id / client_secret（secret 只返回这一次）
curl -sX POST $S/admin/clients -H "$H" -H 'Content-Type: application/json' -d '{
  "client_name":"mjagent (PingOne)","interaction_mode":"token_exchange","exchange_mode":"idp_token",
  "exchange_idp":"pingone","exchange_subject_client_ids":["<mjagent 在 PingOne 的 Client ID>"],
  "crm_match_field":"email","default_resource":"'$LYRA_RESOURCE'","scope":"a2a:invoke"}'

# 客户的企微应用（code 由 Scutum 代换）
curl -sX POST $S/admin/idps -H "$H" -H 'Content-Type: application/json' -d '{
  "name":"wecom-mjagent","type":"wecom","client_id":"<corpid>","tenant_id":"<agentid>","client_secret":"<应用 secret>",
  "exchange_enabled":true}'
curl -sX POST $S/admin/clients -H "$H" -H 'Content-Type: application/json' -d '{
  "client_name":"mjagent (WeCom)","interaction_mode":"token_exchange","exchange_mode":"wecom_code",
  "exchange_idp":"wecom-mjagent","crm_match_field":"wecom_user_id","default_resource":"'$LYRA_RESOURCE'","scope":"a2a:invoke"}'
```

Scutum 环境变量：`SCUTUM_OAUTH_RESOURCES={"<LYRA_RESOURCE>":"lyra"}`（lyra 资源应用须已存在于 `auth_apps`）。

### 4. Lyra（Veeva 侧，`.env`）

```
A2A_AUTH_ENABLED=true
A2A_AUTH_SCUTUM_BASE_URL=http://127.0.0.1:8001                 # 拉 JWKS，可走内网
A2A_AUTH_SCUTUM_PUBLIC_URL=https://scutum-auth-login.crmdev.veevasfa.com
A2A_AUTH_ISSUER=<与 SCUTUM_JWT_ISSUER 相同>
A2A_AUTH_RESOURCE_URL=https://wchat-auth-login.crmdev.veevasfa.com/lyra/a2a
A2A_AUTH_RESOURCE_APPID=<Scutum auth_apps 中 lyra 的 appid>
A2A_AUTH_PRM_URL=https://wchat-auth-login.crmdev.veevasfa.com/lyra/.well-known/oauth-protected-resource
```

### 5. mjagent

复制 `.env.example` 为 `.env` 并填写，各项含义见文件注释。

## 本地运行

```bash
uv sync
cp .env.example .env   # 填写；APP_BASE_URL=http://localhost:5000
uv run flask --app mjagent.app run --port 5000 --debug
uv run pytest
```

PingOne 允许 `http://localhost` 回调，本地即可跑通 PingOne 全链路；企业微信必须部署到有备案域名的服务器。

## 部署到阿里云 ECS

```bash
sudo REPO=git@github.com:mj-io/mjagent.git bash deploy/install.sh            # 首次
sudo bash /opt/mjagent/deploy/install.sh --update                          # 更新
```

nginx 参考 [`deploy/nginx-mjagent.conf`](deploy/nginx-mjagent.conf)（`/api/chat` 是 SSE，必须关闭 `proxy_buffering`）。
安全组放行 80 / 443。

## 页面

| 路径 | 说明 |
| --- | --- |
| `/` | 登录（企微内打开自动静默授权） |
| `/chat` | 选择 agent 对话（多轮自动带 contextId） |
| `/debug` | 各段 token 的 claims 与交换 / 调用记录（`DEBUG_PAGE=false` 关闭） |
| `/healthz` | 健康检查 |

## 错误排查

| 现象 | 原因 |
| --- | --- |
| 交换返回 `invalid_grant: subject_token audience not accepted` | PingOne access_token 的 aud 不是 Scutum：检查 scope 是否带了 `a2a.invoke`、Resource 的 Audience 与 Scutum `exchange_audience` 是否一致 |
| `invalid_grant: subject_token was not issued to a bound application` | Scutum client 的 `exchange_subject_client_ids` 没有 mjagent 的 PingOne Client ID |
| `invalid_grant: subject could not be mapped to a single active CRM user` | CRM 中没有该 email / 企微 userid 的活跃用户，或有多个 |
| 企微交换 `wecom getuserinfo failed`（errcode 60020） | Scutum 出口 IP 不在企微应用的企业可信 IP 里 |
| Lyra 401 + `WWW-Authenticate: Bearer … error="invalid_token"` | Lyra 的 `A2A_AUTH_*` 与 Scutum 不一致（issuer / resource / appid） |
