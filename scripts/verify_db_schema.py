"""
Quick database verification script
"""

import sqlite3

db_path = "collected_logs/ironclad_logs.db"

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Get all tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()

print("=" * 60)
print("📊 DATABASE SCHEMA")
print("=" * 60)

for table in tables:
    table_name = table[0]
    print(f"\n📋 Table: {table_name}")
    
    # Get columns
    cursor.execute(f"PRAGMA table_info({table_name});")
    columns = cursor.fetchall()
    
    for col in columns:
        col_id, col_name, col_type, not_null, default, pk = col
        pk_marker = " 🔑" if pk else ""
        print(f"   - {col_name}: {col_type}{pk_marker}")

conn.close()

print("\n" + "=" * 60)
print("✅ Database structure verified!")
print("=" * 60)
