"""配置：全部来自环境变量（.env）。见 .env.example。"""

import os
from dataclasses import dataclass

from dotenv import load_dotenv


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


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

    @property
    def pingone_enabled(self) -> bool:
        # 不要求 Scutum client：PingOne 登录是客户应用自己的事，交换失败会在调试页 / 对话里提示
        return bool(self.pingone_issuer and self.pingone_client_id)

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
    )
