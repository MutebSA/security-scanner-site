import sqlite3

conn = sqlite3.connect("scanner.db")
cur = conn.cursor()

cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
print("\nجداول الداتا بيس:")
print(cur.fetchall())

print("\nusers:")
cur.execute("SELECT * FROM users")
print(cur.fetchall())

print("\nscans:")
cur.execute("SELECT * FROM scans")
print(cur.fetchall())

conn.close()
