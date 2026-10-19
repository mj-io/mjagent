"""企业微信 OAuth 登录入口 —— 本应用只负责把用户送去企微授权、拿回 code。

code 不在本应用换 userid，而是交给 Scutum（wecom_code 交换）：Scutum 用本应用对应企微应用的凭证调 getuserinfo，
同时返回 CRM 侧的 access_token 和企微 userid。所以本应用不需要配置企微应用 secret，也不需要加企业可信 IP。

- 在企业微信客户端内打开：网页授权 snsapi_base，静默，用户无感
- 在普通浏览器打开：企业微信扫码登录
回调域名必须是该企微应用配置的「可信域名」。
"""

from urllib.parse import quote, urlencode

OAUTH_AUTHORIZE = "https://open.weixin.qq.com/connect/oauth2/authorize"
QR_LOGIN = "https://login.work.weixin.qq.com/wwlogin/sso/login"


def in_wecom(user_agent: str | None) -> bool:
    return "wxwork" in (user_agent or "").lower()


def authorize_url(corp_id: str, agent_id: str, redirect_uri: str, state: str, *, user_agent: str | None) -> str:
    if in_wecom(user_agent):
        # 企微要求参数顺序固定且以 #wechat_redirect 结尾
        return (f"{OAUTH_AUTHORIZE}?appid={corp_id}&redirect_uri={quote(redirect_uri, safe='')}"
                f"&response_type=code&scope=snsapi_base&state={state}&agentid={agent_id}#wechat_redirect")
    return f"{QR_LOGIN}?{urlencode({'login_type': 'CorpApp', 'appid': corp_id, 'agentid': agent_id, 'redirect_uri': redirect_uri, 'state': state})}"
