import csv
import sys
from pathlib import Path

CURRENT_FILE = Path(__file__).resolve()
PROJECT_ROOT = CURRENT_FILE.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sqlalchemy import Engine, func, select, text
from sqlalchemy.orm import Session

from core.logger import logger
from database.db.session import engine
from database.models import Permission, Role, RolePermission

SRC_DIR = CURRENT_FILE.parent / "src"


def _read_csv(path: Path) -> list[dict[str, str]]:
    # Seed files are saved with a UTF-8 BOM, so the first header is "\ufeffid".
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def _reset_id_sequence(session: Session, table: str) -> None:
    bind = session.get_bind()
    if bind is None or bind.dialect.name != "postgresql":
        return
    session.execute(
        text(
            "SELECT setval("
            "pg_get_serial_sequence(:table, 'id'), "
            "COALESCE((SELECT MAX(id) FROM "
            + table
            + "), 1))"
        ),
        {"table": table},
    )


def sync_permissions(db_engine: Engine) -> None:
    """Insert every seed permission and role grant that is not already stored.

    Permissions match on resource + action. Grants match on role name and that
    permission. Rows already present are left unchanged.
    """
    permissions = _read_csv(SRC_DIR / "permission.csv")
    roles = {int(row["id"]): row["name"] for row in _read_csv(SRC_DIR / "role.csv")}
    permissions_by_id = {int(row["id"]): row for row in permissions}
    grants = _read_csv(SRC_DIR / "role_permissions.csv")

    with Session(db_engine) as session, session.begin():
        for row in permissions:
            resource = row["resource"].strip()
            action = row["action"].strip()
            existing = session.scalar(
                select(Permission).where(
                    Permission.resource == resource,
                    Permission.action == action,
                )
            )
            if existing is not None:
                continue
            session.add(
                Permission(
                    name=row["name"],
                    description=row["description"],
                    resource=resource,
                    action=action,
                )
            )
            session.flush()
            logger.info(f"Created permission {resource}:{action}")

        for row in grants:
            permission_row = permissions_by_id.get(int(row["permission_id"]))
            role_name = roles.get(int(row["role_id"]))
            if permission_row is None or role_name is None:
                logger.warning(
                    "Seed grant "
                    f"{row['role_id']} -> {row['permission_id']} "
                    "does not match a seed role or permission"
                )
                continue

            resource = permission_row["resource"].strip()
            action = permission_row["action"].strip()
            permission = session.scalar(
                select(Permission).where(
                    Permission.resource == resource,
                    Permission.action == action,
                )
            )
            if permission is None:
                logger.warning(
                    f"Permission {resource}:{action} missing after sync, skipping grant"
                )
                continue

            normalized_role = role_name.strip().lower()
            role = session.scalar(
                select(Role).where(func.lower(func.trim(Role.name)) == normalized_role)
            )
            if role is None:
                logger.warning(
                    f"Role '{role_name}' not found, skipping {resource}:{action}"
                )
                continue

            linked = session.scalar(
                select(RolePermission.id).where(
                    RolePermission.role_id == role.id,
                    RolePermission.permission_id == permission.id,
                )
            )
            if linked is not None:
                continue
            session.add(RolePermission(role_id=role.id, permission_id=permission.id))
            logger.info(f"Granted {resource}:{action} to role '{role_name}'")

        _reset_id_sequence(session, "permission")
        _reset_id_sequence(session, "role_permissions")


if __name__ == "__main__":
    sync_permissions(engine)
