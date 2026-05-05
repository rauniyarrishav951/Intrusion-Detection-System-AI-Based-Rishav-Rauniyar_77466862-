import sqlite3

DB_PATH = 'ids.db'
OUTPUT_PATH = 'ids_db_export.txt'

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
cur = conn.cursor()
cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name<>'sqlite_sequence' ORDER BY name")
tables = [row['name'] for row in cur.fetchall()]

with open(OUTPUT_PATH, 'w', encoding='utf-8') as f:
    f.write('IDS Database Export\n')
    f.write('===================\n\n')
    for table in tables:
        f.write(f'TABLE: {table}\n')
        f.write('-' * (7 + len(table)) + '\n')
        cur.execute(f'PRAGMA table_info({table})')
        cols = [row['name'] for row in cur.fetchall()]
        f.write('COLUMNS: ' + ', '.join(cols) + '\n')
        cur.execute(f'SELECT * FROM {table}')
        rows = cur.fetchall()
        f.write(f'ROWS: {len(rows)}\n')
        if rows:
            widths = [max(len(str(col)), max(len(str(row[col])) for row in rows)) for col in cols]
            header = ' | '.join(col.ljust(width) for col, width in zip(cols, widths))
            sep = '-+-'.join('-' * width for width in widths)
            f.write(header + '\n')
            f.write(sep + '\n')
            for row in rows:
                f.write(' | '.join(str(row[col]).ljust(width) for col, width in zip(cols, widths)) + '\n')
        f.write('\n')

conn.close()
print('Export complete:', OUTPUT_PATH)
