"""客户应用自己的账号体系（演示）：账号存在 JSON 文件里，密码只存哈希（werkzeug scrypt）。

账号文件（LOCAL_USERS_FILE，权限 600）：
    {"alice": {"password_hash": "scrypt:...", "name": "Alice", "crm_subject": "at_rep10@veeva.com"}}

crm_subject 是这个账号在 Veeva CRM 里对应的映射字段值（与 Scutum 约定的 crm_match_field，如 CRM username）。
本地账号没有外部 IdP，换 Lyra token 走兜底模式：客户后端用私钥签断言，sub 就是 crm_subject。
这份对应关系由客户自己维护。

添加账号或重设密码（交互式输入密码，不进命令行历史）：
    python -m mjagent.local_users add <username> --crm-subject at_rep10@veeva.com [--name 显示名] [--file 路径]
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from werkzeug.security import check_password_hash, generate_password_hash

_dummy_hash: str | None = None


@dataclass(frozen=True)
class LocalUser:
    username: str
    name: str
    crm_subject: str


class LocalUsers:
    def __init__(self, path: str):
        self.path = Path(path)

    def _load(self) -> dict:
        # 每次读文件：改账号不用重启服务；账号量是演示级别
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}

    def authenticate(self, username: str, password: str) -> LocalUser | None:
        global _dummy_hash
        rec = self._load().get(username)
        if not rec:
            # 账号不存在也做一次同样代价的哈希比对，避免按响应时间枚举账号
            _dummy_hash = _dummy_hash or generate_password_hash(os.urandom(16).hex())
            check_password_hash(_dummy_hash, password)
            return None
        if not check_password_hash(rec["password_hash"], password):
            return None
        return LocalUser(username=username, name=rec.get("name") or username, crm_subject=rec.get("crm_subject") or "")

    def upsert(self, username: str, password: str, *, crm_subject: str, name: str = "") -> None:
        users = self._load()
        users[username] = {"password_hash": generate_password_hash(password), "name": name or username,
                           "crm_subject": crm_subject}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".users-")   # mkstemp 建出的文件就是 600
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(users, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m mjagent.local_users")
    sub = p.add_subparsers(dest="cmd", required=True)
    add = sub.add_parser("add", help="添加账号或重设密码")
    add.add_argument("username")
    add.add_argument("--crm-subject", required=True, help="对应的 CRM 映射字段值，如 CRM username")
    add.add_argument("--name", default="")
    add.add_argument("--file", default=os.environ.get("LOCAL_USERS_FILE", ""))
    args = p.parse_args(argv)
    if not args.file:
        p.error("缺少账号文件：--file 或环境变量 LOCAL_USERS_FILE")
    pw = getpass.getpass("密码：")
    if len(pw) < 8:
        print("密码至少 8 位", file=sys.stderr)
        return 1
    if getpass.getpass("再输一次：") != pw:
        print("两次输入不一致", file=sys.stderr)
        return 1
    LocalUsers(args.file).upsert(args.username, pw, crm_subject=args.crm_subject, name=args.name)
    print(f"已保存账号 {args.username} → CRM {args.crm_subject}（{args.file}）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
