#!/bin/bash
set -e

echo "⏳ Waiting for DB"
until pg_isready -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER"; do
  sleep 1
done
echo "📦 Applying migrations"
alembic upgrade head

# Seed assigns the CSV ids. Sync then adds any permission or role grant still missing.
# Syncing first would insert those rows under new ids and the seed would collide.
if [ "$1" = "python" ] && [ "$2" = "scripts/init_db.py" ]; then
  echo "📥 Seeding roles and permissions"
  python scripts/init_db.py
fi

echo "🔑 Syncing permissions"
python scripts/sync_permissions.py

echo "🚀 Start App"
if [ "$1" = "python" ] && [ "$2" = "scripts/init_db.py" ]; then
  exit 0
fi
exec "$@"