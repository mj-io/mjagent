#!/usr/bin/env bash
# 在阿里云 ECS（Alibaba Cloud Linux / CentOS / Ubuntu）上安装或更新 mjagent。
# 用法：sudo bash deploy/install.sh            # 首次安装：建用户、装 uv、同步依赖、注册 systemd
#       sudo bash deploy/install.sh --update   # 只拉代码、同步依赖、重启
set -euo pipefail

APP_DIR=/opt/mjagent
REPO=${REPO:-git@github.com:mj-io/mjagent.git}
BRANCH=${BRANCH:-main}

if [[ "${1:-}" != "--update" ]]; then
  id mjagent >/dev/null 2>&1 || useradd --system --home "$APP_DIR" --shell /sbin/nologin mjagent
  if ! command -v uv >/dev/null 2>&1; then
    curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh
  fi
  [[ -d "$APP_DIR/.git" ]] || git clone -b "$BRANCH" "$REPO" "$APP_DIR"
  [[ -f "$APP_DIR/.env" ]] || { cp "$APP_DIR/.env.example" "$APP_DIR/.env"; echo ">> 请编辑 $APP_DIR/.env 后重新执行"; }
  mkdir -p "$APP_DIR/deploy/wecom-verify"
  install -m 644 "$APP_DIR/deploy/mjagent.service" /etc/systemd/system/mjagent.service
  systemctl daemon-reload
  systemctl enable mjagent
fi

cd "$APP_DIR"
git fetch origin "$BRANCH" && git checkout "$BRANCH" && git pull --ff-only origin "$BRANCH"
UV_PYTHON_INSTALL_DIR=/opt/uv-python uv sync --frozen --no-dev
chown -R mjagent:mjagent "$APP_DIR"
chmod 600 "$APP_DIR/.env"
systemctl restart mjagent
sleep 2
curl -fsS http://127.0.0.1:5000/healthz && echo
