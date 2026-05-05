# add_admin.py
import sqlite3
from werkzeug.security import generate_password_hash

# Use the exact path to your database
DB_PATH = r'C:\Users\user\Desktop\flask_project\flask_venv\ids.db'

def add_admin_user():
    """Add admin user to the existing ids.db database"""
    
    print(f"📁 Connecting to database: {DB_PATH}")
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Check if admin already exists
    c.execute("SELECT id, username, role FROM users WHERE username = ?", ('admin',))
    existing = c.fetchone()
    
    if existing:
        print(f"\n⚠️  Admin user already exists!")
        print(f"   ID: {existing[0]}")
        print(f"   Username: {existing[1]}")
        print(f"   Role: {existing[2]}")
    else:
        # Create admin user
        try:
            c.execute('''
                INSERT INTO users (username, password_hash, firstname, lastname, email, phone, role, is_active, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                'admin',
                generate_password_hash('admin123'),
                'System',
                'Administrator',
                'admin@ids-system.com',
                '1234567890',
                'admin',
                1
            ))
            conn.commit()
            print("\n✅ Admin user created successfully!")
            print("   Username: admin")
            print("   Password: admin123")
            print("   Role: admin")
        except Exception as e:
            print(f"\n❌ Error: {e}")
            conn.rollback()
    
    # Show all users in database
    print("\n" + "="*50)
    print("Current Users in Database:")
    print("="*50)
    c.execute("SELECT id, username, role, is_active, created_at FROM users ORDER BY id")
    users = c.fetchall()
    
    for user in users:
        print(f"ID: {user[0]} | Username: {user[1]} | Role: {user[2]} | Active: {user[3]} | Created: {user[4]}")
    
    conn.close()
    
    print("\n" + "="*50)
    print("You can now login at: http://localhost:5000/login")
    print("Username: admin")
    print("Password: admin123")
    print("="*50)

if __name__ == '__main__':
    add_admin_user()