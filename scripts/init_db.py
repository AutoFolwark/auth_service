import sys
from pathlib import Path

CURRENT_FILE = Path(__file__).resolve()
PROJECT_ROOT = CURRENT_FILE.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
from sqlalchemy import Engine, MetaData, Table, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from database.db.session import engine
from core.logger import logger


def _coerce_bool_series(series: pd.Series) -> pd.Series:
    true_vals = {"1", "true", "t", "yes", "y"}
    false_vals = {"0", "false", "f", "no", "n"}

    def to_bool(x):
        if isinstance(x, bool):
            return x
        if pd.isna(x):
            return False
        s = str(x).strip().lower()
        if s in true_vals:
            return True
        if s in false_vals:
            return False
        try:
            return bool(int(s))
        except Exception:
            return s not in ("", "0", "false", "none", "nan")

    return series.map(to_bool)


def _reflect_table(db_engine: Engine, table_name: str) -> Table:
    metadata = MetaData()
    metadata.reflect(bind=db_engine, only=[table_name], resolve_fks=False)
    if table_name in metadata.tables:
        return metadata.tables[table_name]
    qualified = f"public.{table_name}"
    if qualified in metadata.tables:
        return metadata.tables[qualified]
    raise KeyError(
        f"Table {table_name!r} not found after reflect; have {list(metadata.tables)!r}"
    )


def _prepare_dataframe_for_sql(df: pd.DataFrame, table: str) -> pd.DataFrame:
    """Normalize CSV dtypes for SQLAlchemy (matches prior pandas.to_sql behavior)."""
    df = df.copy()
    if 'created_at' in df.columns:
        df['created_at'] = pd.to_datetime(df['created_at'], utc=True, errors='coerce')
    if table == 'role' and 'is_default' in df.columns:
        df['is_default'] = _coerce_bool_series(df['is_default'])
    return df


def _insert_ignore_by_id(db_engine: Engine, table_name: str, df: pd.DataFrame) -> None:
    """Append rows whose primary key id is not present; skip existing ids."""
    if df.empty:
        return
    df = df.where(pd.notnull(df), None)
    records = df.to_dict("records")
    if not records:
        return
    tbl = _reflect_table(db_engine, table_name)
    dialect_name = db_engine.dialect.name
    if dialect_name == "postgresql":
        stmt = pg_insert(tbl).values(records)
    elif dialect_name == "sqlite":
        stmt = sqlite_insert(tbl).values(records)
    else:
        raise RuntimeError(
            f"Idempotent seed supports postgresql and sqlite; got {dialect_name!r}"
        )
    stmt = stmt.on_conflict_do_nothing(index_elements=["id"])
    with db_engine.begin() as conn:
        conn.execute(stmt)


def reset_all_sequences(db_engine: Engine):
    if db_engine.dialect.name != "postgresql":
        logger.info("Skipping sequence reset for non-PostgreSQL dialect")
        return
    sql = """
DO $$
DECLARE
  r record;
  max_id bigint;
  seq_reg regclass;
  seq_schema text;
  seq_name text;
  startv bigint;
BEGIN
  FOR r IN
    SELECT
      n.nspname AS sch,
      c.relname AS tbl,
      a.attname AS col,
      pg_get_serial_sequence(format('%I.%I', n.nspname, c.relname), a.attname) AS seq
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
    WHERE c.relkind IN ('r','p')
      AND n.nspname NOT IN ('pg_catalog','information_schema','pg_toast')
  LOOP
    IF r.seq IS NOT NULL THEN
      seq_reg := r.seq::regclass;
      SELECT ns.nspname, cl.relname
      INTO seq_schema, seq_name
      FROM pg_class cl
      JOIN pg_namespace ns ON ns.oid = cl.relnamespace
      WHERE cl.oid = seq_reg;

      SELECT start_value
      INTO startv
      FROM pg_sequences
      WHERE schemaname = seq_schema AND sequencename = seq_name;

      EXECUTE format('SELECT MAX(%I) FROM %I.%I', r.col, r.sch, r.tbl) INTO max_id;

      IF max_id IS NULL THEN
        EXECUTE format('SELECT setval(%L, %s, false)', r.seq, startv);
      ELSE
        EXECUTE format('SELECT setval(%L, %s, true)', r.seq, max_id);
      END IF;
    END IF;
  END LOOP;
END $$;
"""
    with db_engine.begin() as conn:
        conn.execute(text(sql))


def seed_db(db_engine: Engine):
    src_dir = CURRENT_FILE.parent / 'src'

    tables = {
        'permission': src_dir / 'permission.csv',
        'role': src_dir / 'role.csv',
        'role_permissions': src_dir / 'role_permissions.csv',
    }

    # FK order: permission & role before role_permissions
    insert_order = [
        'permission',
        'role',
        'role_permissions',
    ]

    for table in insert_order:
        path = tables[table]
        logger.info(f'Seeding table {table} from {path} (insert new ids only)')
        df = pd.read_csv(path)
        if df.empty:
            logger.warning(f'Skipping {table}: CSV is empty')
            continue
        df = _prepare_dataframe_for_sql(df, table)
        _insert_ignore_by_id(db_engine, table, df)

    logger.info('Resetting all sequences to match current max ids')
    reset_all_sequences(db_engine)


if __name__ == '__main__':
    seed_db(engine)
