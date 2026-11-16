"""Operator CLI. Creating the first admin needs a way in that is not the API:
    docker compose exec backend .venv/bin/python -m app.manage create-user alice admin
The password is read from a prompt, or from stdin with --password-stdin (never from the command line)."""
import argparse
import getpass
import sys

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.audit import audit
from app.core.security import USERNAME_RE, check_password_policy, hash_password
from app.database.models import ROLES, User
from app.database.session import get_factory


def create_user(db: Session, username: str, password: str, role: str) -> User:
    if not USERNAME_RE.match(username):
        raise ValueError("username must be 3-64 characters of a-z 0-9 . _ -")
    if role not in ROLES:
        raise ValueError(f"role must be one of {', '.join(ROLES)}")
    check_password_policy(password)
    if db.scalar(select(User.id).where(User.username == username)):
        raise ValueError("username already exists")
    user = User(username=username, password_hash=hash_password(password), role=role)
    db.add(user)
    db.flush()
    audit(db, "cli", "user.create", target_type="user", target_id=str(user.id), detail={"username": username, "role": role})
    db.commit()
    return user


def set_password(db: Session, username: str, password: str) -> None:
    check_password_policy(password)
    user = db.scalar(select(User).where(User.username == username))
    if user is None:
        raise ValueError("no such user")
    user.password_hash = hash_password(password)
    audit(db, "cli", "user.set_password", target_type="user", target_id=str(user.id))
    db.commit()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="app.manage")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create-user")
    c.add_argument("username")
    c.add_argument("role", choices=ROLES)
    s = sub.add_parser("set-password")
    s.add_argument("username")
    for p in (c, s):
        p.add_argument("--password-stdin", action="store_true")
    a = ap.parse_args(argv)
    password = sys.stdin.readline().rstrip("\n") if a.password_stdin else getpass.getpass("Password: ")
    try:
        with get_factory()() as db:
            if a.cmd == "create-user":
                create_user(db, a.username, password, a.role)
            else:
                set_password(db, a.username, password)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
