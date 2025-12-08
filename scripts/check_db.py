"""Quick database check."""
import sqlite3

conn = sqlite3.connect('c:/Users/Harsh/_codes_/sih/sih_take4/src/app/logs.db')
cursor = conn.cursor()

cursor.execute('SELECT COUNT(*) FROM log_entry')
print(f'Total logs: {cursor.fetchone()[0]}')

cursor.execute('SELECT log_type, COUNT(*) FROM log_entry GROUP BY log_type')
print('By type:')
for row in cursor.fetchall():
    print(f'  {row[0]}: {row[1]}')

cursor.execute('SELECT COUNT(*) FROM server')
print(f'Total servers: {cursor.fetchone()[0]}')

cursor.execute('SELECT hostname, ip_address, COUNT(*) as log_count FROM server s LEFT JOIN log_entry l ON s.id = l.server_id GROUP BY s.id')
print('\nServers:')
for row in cursor.fetchall():
    print(f'  {row[0]} ({row[1]}): {row[2]} logs')

conn.close()
