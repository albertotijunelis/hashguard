#!/usr/bin/env python3
"""Migrate HashGuard data from SQLite to PostgreSQL.

Usage:
    # Set the target PostgreSQL URL
    export DATABASE_URL=postgresql://hashguard:changeme@localhost:5432/hashguard

    # Run migration (reads from default SQLite at %APPDATA%/HashGuard/hashguard.db)
    python scripts/migrate_to_postgres.py

    # Or specify a custom SQLite path
    python scripts/migrate_to_postgres.py --sqlite /path/to/hashguard.db

This script:
1. Connects to the source SQLite database
2. Creates all ORM tables in the target PostgreSQL database
3. Copies all data table-by-table with batched inserts
4. Migrates the dynamic dataset_features table if it exists
5. Reports row counts for verification
"""

import argparse
import os
import sqlite3
import sys

# Add project src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def get_default_sqlite_path() -> str:
    app_data = os.environ.get("APPDATA") or os.path.expanduser("~")
    return os.path.join(app_data, "HashGuard", "hashguard.db")


def migrate(sqlite_path: str, pg_url: str, batch_size: int = 500):
    """Copy all data from SQLite to PostgreSQL."""
    from sqlalchemy import create_engine, text, inspect
    from hashguard.models import Base, init_orm_db, get_engine, reset_engine

    # Validate SQLite exists
    if not os.path.exists(sqlite_path):
        print(f"ERROR: SQLite database not found: {sqlite_path}")
        sys.exit(1)

    # Connect to source SQLite
    src = sqlite3.connect(sqlite_path)
    src.row_factory = sqlite3.Row
    print(f"Source: {sqlite_path}")
    print(f"Target: {pg_url}")

    # Set DATABASE_URL and initialize ORM (creates tables in PostgreSQL)
    os.environ["DATABASE_URL"] = pg_url
    reset_engine()
    init_orm_db()
    dst_engine = get_engine()
    print("PostgreSQL tables created via ORM.\n")

    # Get table list from SQLite
    tables = [
        row[0]
        for row in src.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'alembic_%'"
        ).fetchall()
    ]

    # Migrate each table
    for table in tables:
        rows = src.execute(f"SELECT * FROM [{table}]").fetchall()
        if not rows:
            print(f"  {table}: 0 rows (skip)")
            continue

        columns = rows[0].keys()

        # Check which columns exist in target
        insp = inspect(dst_engine)
        if table not in insp.get_table_names():
            # Dynamic table (e.g. dataset_features) — create it
            print(f"  {table}: skipped (not in ORM schema)")
            continue

        target_cols = {c["name"] for c in insp.get_columns(table)}
        valid_cols = [c for c in columns if c in target_cols]

        if not valid_cols:
            print(f"  {table}: no matching columns (skip)")
            continue

        # Batch insert
        col_list = ", ".join(valid_cols)
        placeholders = ", ".join(f":{c}" for c in valid_cols)
        insert_sql = text(
            f"INSERT INTO {table} ({col_list}) VALUES ({placeholders}) ON CONFLICT DO NOTHING"
        )

        count = 0
        with dst_engine.begin() as conn:
            batch = []
            for row in rows:
                d = {c: row[c] for c in valid_cols}
                batch.append(d)
                if len(batch) >= batch_size:
                    conn.execute(insert_sql, batch)
                    count += len(batch)
                    batch = []
            if batch:
                conn.execute(insert_sql, batch)
                count += len(batch)

        print(f"  {table}: {count} rows migrated")

    # Migrate dataset_features (dynamic table)
    try:
        ds_rows = src.execute("SELECT * FROM dataset_features").fetchall()
        if ds_rows:
            columns = ds_rows[0].keys()
            insp = inspect(dst_engine)
            if "dataset_features" in insp.get_table_names():
                target_cols = {c["name"] for c in insp.get_columns("dataset_features")}
                valid_cols = [c for c in columns if c in target_cols]
                if valid_cols:
                    col_list = ", ".join(valid_cols)
                    placeholders = ", ".join(f":{c}" for c in valid_cols)
                    insert_sql = text(
                        f"INSERT INTO dataset_features ({col_list}) VALUES ({placeholders}) ON CONFLICT DO NOTHING"
                    )
                    count = 0
                    with dst_engine.begin() as conn:
                        batch = []
                        for row in ds_rows:
                            d = {c: row[c] for c in valid_cols}
                            batch.append(d)
                            if len(batch) >= batch_size:
                                conn.execute(insert_sql, batch)
                                count += len(batch)
                                batch = []
                        if batch:
                            conn.execute(insert_sql, batch)
                            count += len(batch)
                    print(f"  dataset_features: {count} rows migrated")
    except Exception as e:
        print(f"  dataset_features: skipped ({e})")

    src.close()

    # Verify counts
    print("\n── Verification ──")
    with dst_engine.connect() as conn:
        for table in tables:
            try:
                result = conn.execute(text(f"SELECT COUNT(*) FROM {table}"))
                n = result.scalar()
                print(f"  {table}: {n} rows in PostgreSQL")
            except Exception:
                pass

    print("\nMigration complete.")


def main():
    parser = argparse.ArgumentParser(description="Migrate HashGuard data from SQLite to PostgreSQL")
    parser.add_argument(
        "--sqlite",
        default=get_default_sqlite_path(),
        help="Path to source SQLite database (default: %%APPDATA%%/HashGuard/hashguard.db)",
    )
    parser.add_argument(
        "--pg-url",
        default=os.environ.get("DATABASE_URL", ""),
        help="PostgreSQL connection URL (or set DATABASE_URL env var)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=500,
        help="Batch size for inserts (default: 500)",
    )
    args = parser.parse_args()

    if not args.pg_url:
        print("ERROR: PostgreSQL URL required. Set DATABASE_URL or use --pg-url")
        sys.exit(1)

    if not args.pg_url.startswith("postgresql"):
        print("ERROR: Target must be a PostgreSQL URL (postgresql://...)")
        sys.exit(1)

    migrate(args.sqlite, args.pg_url, args.batch_size)


if __name__ == "__main__":
    main()
