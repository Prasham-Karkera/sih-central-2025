"""Inspect database structure and contents."""
import sqlite3
import json

DB_PATH = "c:/Users/Harsh/_codes_/sih/sih_take4/src/app/ironchad_logs.db"

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

print("=" * 80)
print("DATABASE INSPECTION: ironchad_logs.db")
print("=" * 80)

# Get all tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
tables = [row[0] for row in cursor.fetchall()]

print(f"\n📊 TABLES ({len(tables)}):")
for table in tables:
    cursor.execute(f"SELECT COUNT(*) FROM {table}")
    count = cursor.fetchone()[0]
    print(f"  • {table}: {count} rows")

print("\n" + "=" * 80)

# Show schema for each table
for table in tables:
    print(f"\n📋 TABLE: {table}")
    print("-" * 80)
    
    cursor.execute(f"PRAGMA table_info({table})")
    columns = cursor.fetchall()
    
    print("Columns:")
    for col in columns:
        col_id, name, type_, notnull, default, pk = col
        pk_flag = " [PRIMARY KEY]" if pk else ""
        null_flag = " NOT NULL" if notnull else ""
        default_flag = f" DEFAULT {default}" if default else ""
        print(f"  • {name}: {type_}{pk_flag}{null_flag}{default_flag}")
    
    # Show sample data if exists
    cursor.execute(f"SELECT COUNT(*) FROM {table}")
    count = cursor.fetchone()[0]
    
    if count > 0:
        print(f"\nSample Data (showing up to 3 rows):")
        cursor.execute(f"SELECT * FROM {table} LIMIT 3")
        rows = cursor.fetchall()
        col_names = [desc[0] for desc in cursor.description]
        
        for i, row in enumerate(rows, 1):
            print(f"\n  Row {i}:")
            for col_name, value in zip(col_names, row):
                # Pretty print JSON if it looks like JSON
                if isinstance(value, str) and (value.startswith('{') or value.startswith('[')):
                    try:
                        parsed = json.loads(value)
                        value = json.dumps(parsed, indent=4)
                        print(f"    {col_name}:")
                        for line in value.split('\n'):
                            print(f"      {line}")
                    except:
                        print(f"    {col_name}: {value}")
                else:
                    # Truncate long values
                    str_value = str(value)
                    if len(str_value) > 100:
                        str_value = str_value[:97] + "..."
                    print(f"    {col_name}: {str_value}")

print("\n" + "=" * 80)
print("END OF INSPECTION")
print("=" * 80)

conn.close()
