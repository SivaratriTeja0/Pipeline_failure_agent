"""Administrative CLI for the TokenAuthProvider (spec L5).

    python -m api.cli create-principal --id alice --type HUMAN --roles ENGINEER,APPROVER
    python -m api.cli list-principals
    python -m api.cli disable-principal --id alice
    python -m api.cli set-roles --id alice --roles VIEWER

The bearer token is printed exactly once at creation; only its SHA-256 hash is stored. Uses
DATABASE_URL (default sqlite:///./triage.db).
"""

import argparse
import sys

from dotenv import load_dotenv

from core.config import Settings
from core.models.enums import PrincipalType, Role
from database.repository import Database, SqlPrincipalStore
from security.auth import create_principal


def _roles(raw: str) -> frozenset[Role]:
    try:
        return frozenset(Role(r.strip().upper()) for r in raw.split(",") if r.strip())
    except ValueError as exc:
        raise SystemExit(f"invalid role in {raw!r}; valid: {[r.value for r in Role]}") from exc


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(prog="python -m api.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create-principal")
    create.add_argument("--id", required=True)
    create.add_argument("--type", choices=[t.value for t in PrincipalType], default="HUMAN")
    create.add_argument("--roles", required=True, help="comma-separated: VIEWER,ENGINEER,APPROVER,ADMIN")
    sub.add_parser("list-principals")
    disable = sub.add_parser("disable-principal")
    disable.add_argument("--id", required=True)
    roles = sub.add_parser("set-roles")
    roles.add_argument("--id", required=True)
    roles.add_argument("--roles", required=True)
    args = parser.parse_args(argv)

    store = SqlPrincipalStore(Database(Settings.from_env().database_url))
    if args.command == "create-principal":
        principal, token = create_principal(store, args.id, PrincipalType(args.type), _roles(args.roles))
        print(f"created {principal.principal_id} ({principal.principal_type.value}, "
              f"{','.join(sorted(r.value for r in principal.roles))})")
        print(f"bearer token (shown once, store it securely): {token}")
    elif args.command == "list-principals":
        for p in store.list():
            print(f"{p.principal_id}\t{p.principal_type.value}\t{','.join(sorted(r.value for r in p.roles))}")
    elif args.command == "disable-principal":
        store.update(args.id, disabled=True)
        print(f"disabled {args.id}")
    else:
        store.update(args.id, roles=_roles(args.roles))
        print(f"updated roles for {args.id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
