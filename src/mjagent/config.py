"""配置：全部来自环境变量（.env）。见 .env.example。"""

import os
from dataclasses import dataclass

from dotenv import load_dotenv


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _secret(name: str) -> str:
    """secret 可直接配在 NAME，也可放在单独文件里（NAME_FILE，权限 600），后者不进 .env。"""
    value = _env(name)
    path = _env(f"{name}_FILE")
    if not value and path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            value = f.read().strip()
    return value


def _bool(name: str, default: bool = False) -> bool:
    v = _env(name)
    return default if not v else v.lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Config:
    secret_key: str
    app_base_url: str                   # 本应用对外地址（OAuth 回调地址由它拼出）
    debug_page: bool                    # 是否开放 /debug（展示各段 token 的 claims，仅联调用）

    # ---- PingOne（客户自己的 IdP）----
    pingone_issuer: str                 # https://auth.pingone.{com|eu|asia}/<envId>/as
    pingone_client_id: str
    pingone_client_secret: str
    pingone_scopes: str                 # 含 Scutum custom resource 的 scope（如 a2a.invoke）
    # 交给 Scutum 的 subject token：access_token（方案 A，PingOne 签给 Scutum 的）| id_token（方案 A-lite）
    pingone_subject_token: str

    # ---- 企业微信（客户自己的企微应用；secret 只配在 Scutum，本应用不需要）----
    wecom_corp_id: str
    wecom_agent_id: str

    # ---- Scutum（CRM 认证中心）：每种交换方式一个集成方 client ----
    scutum_issuer: str
    scutum_pingone_client_id: str
    scutum_pingone_client_secret: str
    scutum_wecom_client_id: str
    scutum_wecom_client_secret: str

    # ---- Lyra A2A ----
    lyra_base_url: str                  # /a2a/agents 等相对路径的前缀，如 https://host/lyra
    lyra_resource: str                  # RFC 8707 resource（= token aud），如 https://host/lyra/a2a
    http_verify: bool = True

    # ---- iframe 嵌入（ORI-159317 iframe 内外 PingOne 授权测试）----
    # 被嵌入方（agentx.mjio.cn）：开启 /embed/*，会话 cookie 改为 SameSite=None; Secure; Partitioned
    embed_mode: bool = False
    # 允许嵌入本应用 /embed/app 的宿主（CSP frame-ancestors），空格分隔
    embed_frame_ancestors: str = ""
    # 宿主方（agentx.htltio.cn）：/embed-host 页面用 iframe 加载的地址
    embed_app_url: str = ""

    # ---- 两段交换（ORI-159317）：登录 token 先在客户 IdP（如 PingFederate）换出签给 Scutum 的 token ----
    # 配了交换专用 client 才启用；不配 = 登录 access_token 本身就签给 Scutum，直接交给 Scutum
    idp_exchange_client_id: str = ""
    idp_exchange_client_secret: str = ""
    idp_exchange_scope: str = "a2a.invoke"

    # ---- Microsoft Entra ID 登录 + OBO（ORI-158433，见 entra.py）----
    entra_tenant_id: str = ""
    entra_client_id: str = ""                   # 本应用在 Entra 的 client id
    entra_client_secret: str = ""
    # 登录 scope：必须带本应用自己公开的 API（api://<client id>/access_as_user），access_token 才签给本应用
    entra_scopes: str = ""
    # OBO 目标：Scutum 在客户 Entra 注册的 API 应用的 scope，如 api://<API 应用 client id>/a2a.invoke
    entra_obo_scope: str = ""
    scutum_entra_client_id: str = ""            # Scutum 上 idp_token 模式、身份源为 Entra 的集成应用
    scutum_entra_client_secret: str = ""

    # ---- PingOne 登录 + PingOne Token Exchange（ORI-158433）----
    # 与上面的 PINGONE_* 槽位独立（那个槽位目前接的是 PingFederate）。登录只拿签给本应用的 token，
    # 调 A2A 前用同一个应用（开了 Token Exchange 授权）在 PingOne 换出签给 Scutum 的 token
    p1_issuer: str = ""                         # https://auth.pingone.{com|eu|asia|sg}/<envId>/as
    p1_client_id: str = ""
    p1_client_secret: str = ""
    p1_scopes: str = "openid profile email offline_access"   # 不含 a2a.invoke：登录 token 不带 A2A 权限
    p1_exchange_scope: str = "a2a.invoke"       # Scutum custom resource 的 scope
    scutum_p1_client_id: str = ""               # Scutum 上 idp_token 模式、身份源为 PingOne 的集成应用
    scutum_p1_client_secret: str = ""

    # 登录页按钮上 PINGONE_* 槽位的厂商名（接 PingFederate 时配 PingFederate）
    pingone_label: str = "PingOne"

    # ---- 本地账号登录（客户应用自己的账号体系，见 local_users.py）----
    local_users_file: str = ""

    # ---- 兜底模式（ORI-159317 方案 C，Scutum exchange_mode=subject_field）----
    # 本地账号没有外部 IdP：客户后端用自己的私钥签用户断言（RFC 7523），sub = 账号的 crm_subject
    scutum_assertion_client_id: str = ""
    scutum_assertion_key_file: str = ""         # PEM 私钥路径，只放在客户后端；公钥（JWKS）登记在 Scutum
    scutum_assertion_kid: str = ""
    scutum_assertion_alg: str = "RS256"         # RS256 | ES256

    @property
    def pingone_enabled(self) -> bool:
        # 不要求 Scutum client：PingOne 登录是客户应用自己的事，交换失败会在调试页 / 对话里提示
        return bool(self.pingone_issuer and self.pingone_client_id)

    @property
    def entra_enabled(self) -> bool:
        return bool(self.entra_tenant_id and self.entra_client_id and self.entra_client_secret and self.entra_obo_scope)

    @property
    def p1_enabled(self) -> bool:
        return bool(self.p1_issuer and self.p1_client_id and self.p1_client_secret)

    @property
    def idp_exchange_enabled(self) -> bool:
        return bool(self.idp_exchange_client_id and self.idp_exchange_client_secret)

    @property
    def local_login_enabled(self) -> bool:
        return bool(self.local_users_file)

    @property
    def assertion_enabled(self) -> bool:
        return bool(self.scutum_assertion_client_id and self.scutum_assertion_key_file)

    @property
    def wecom_enabled(self) -> bool:
        return bool(self.wecom_corp_id and self.wecom_agent_id and self.scutum_wecom_client_id)


def load_config() -> Config:
    # 同一份代码跑多个实例（agentx.htltio.cn / agentx.mjio.cn）：MJAGENT_ENV_FILE 指定各自的 dotenv
    load_dotenv(os.environ.get("MJAGENT_ENV_FILE", ".env"))
    return Config(
        secret_key=_env("FLASK_SECRET_KEY") or os.urandom(32).hex(),
        app_base_url=_env("APP_BASE_URL", "http://localhost:5000").rstrip("/"),
        debug_page=_bool("DEBUG_PAGE", True),
        pingone_issuer=_env("PINGONE_ISSUER").rstrip("/"),
        pingone_client_id=_env("PINGONE_CLIENT_ID"),
        pingone_client_secret=_env("PINGONE_CLIENT_SECRET"),
        pingone_scopes=_env("PINGONE_SCOPES", "openid profile email a2a.invoke"),
        pingone_subject_token=_env("PINGONE_SUBJECT_TOKEN", "access_token"),
        wecom_corp_id=_env("WECOM_CORP_ID"),
        wecom_agent_id=_env("WECOM_AGENT_ID"),
        scutum_issuer=_env("SCUTUM_ISSUER").rstrip("/"),
        scutum_pingone_client_id=_env("SCUTUM_PINGONE_CLIENT_ID"),
        scutum_pingone_client_secret=_env("SCUTUM_PINGONE_CLIENT_SECRET"),
        scutum_wecom_client_id=_env("SCUTUM_WECOM_CLIENT_ID"),
        scutum_wecom_client_secret=_env("SCUTUM_WECOM_CLIENT_SECRET"),
        lyra_base_url=_env("LYRA_BASE_URL").rstrip("/"),
        lyra_resource=_env("LYRA_RESOURCE").rstrip("/"),
        http_verify=_bool("HTTP_VERIFY_TLS", True),
        embed_mode=_bool("EMBED_MODE", False),
        embed_frame_ancestors=_env("EMBED_FRAME_ANCESTORS"),
        embed_app_url=_env("EMBED_APP_URL"),
        idp_exchange_client_id=_env("PINGONE_EXCHANGE_CLIENT_ID"),
        idp_exchange_client_secret=_env("PINGONE_EXCHANGE_CLIENT_SECRET"),
        idp_exchange_scope=_env("PINGONE_EXCHANGE_SCOPE", "a2a.invoke"),
        entra_tenant_id=_env("ENTRA_TENANT_ID"),
        entra_client_id=_env("ENTRA_CLIENT_ID"),
        entra_client_secret=_secret("ENTRA_CLIENT_SECRET"),
        entra_scopes=_env("ENTRA_SCOPES") or (
            f"openid profile email offline_access api://{_env('ENTRA_CLIENT_ID')}/access_as_user" if _env("ENTRA_CLIENT_ID") else ""),
        entra_obo_scope=_env("ENTRA_OBO_SCOPE"),
        scutum_entra_client_id=_env("SCUTUM_ENTRA_CLIENT_ID"),
        scutum_entra_client_secret=_secret("SCUTUM_ENTRA_CLIENT_SECRET"),
        p1_issuer=_env("P1_ISSUER").rstrip("/"),
        p1_client_id=_env("P1_CLIENT_ID"),
        p1_client_secret=_secret("P1_CLIENT_SECRET"),
        p1_scopes=_env("P1_SCOPES", "openid profile email offline_access"),
        p1_exchange_scope=_env("P1_EXCHANGE_SCOPE", "a2a.invoke"),
        scutum_p1_client_id=_env("SCUTUM_P1_CLIENT_ID"),
        scutum_p1_client_secret=_secret("SCUTUM_P1_CLIENT_SECRET"),
        pingone_label=_env("PINGONE_LABEL", "PingOne"),
        local_users_file=_env("LOCAL_USERS_FILE"),
        scutum_assertion_client_id=_env("SCUTUM_ASSERTION_CLIENT_ID"),
        scutum_assertion_key_file=_env("SCUTUM_ASSERTION_KEY_FILE"),
        scutum_assertion_kid=_env("SCUTUM_ASSERTION_KID"),
        scutum_assertion_alg=_env("SCUTUM_ASSERTION_ALG", "RS256"),
    )
