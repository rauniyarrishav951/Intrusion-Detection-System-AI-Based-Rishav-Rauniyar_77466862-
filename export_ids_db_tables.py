import sqlite3

DB_PATH = 'ids.db'

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
cur = conn.cursor()
cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name<>'sqlite_sequence' ORDER BY name")
tables = [row['name'] for row in cur.fetchall()]

for table in tables:
    filename = f'ids_db_{table}.txt'
    with open(filename, 'w', encoding='utf-8') as f:
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
    print('Exported', filename)

conn.close()
