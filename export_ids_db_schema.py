import sqlite3

DB_PATH = 'ids.db'
OUTPUT_PATH = 'ids_db_schema.sql'

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
cur.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name<>'sqlite_sequence' ORDER BY name")
rows = [r[0] for r in cur.fetchall()]
conn.close()

with open(OUTPUT_PATH, 'w', encoding='utf-8') as f:
    f.write('-- Schema for ids.db\n')
    f.write('-- Generated from sqlite_master\n\n')
    for sql in rows:
        if sql:
            f.write(sql.strip() + '\n\n')

print('Created', OUTPUT_PATH)
