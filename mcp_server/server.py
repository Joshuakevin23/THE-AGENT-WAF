import sqlite3
from pathlib import Path
from typing import Dict, Any, List

DB_PATH = Path(__file__).parent.parent / "app.db"

def init_app_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 1. project_x_customers
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS project_x_customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE,
            country TEXT
        )
    """)
    
    # 2. project_x_orders
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS project_x_orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER,
            product TEXT NOT NULL,
            amount REAL,
            date TEXT,
            FOREIGN KEY(customer_id) REFERENCES project_x_customers(id)
        )
    """)
    
    # 3. project_x_employees
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS project_x_employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            role TEXT,
            salary REAL
        )
    """)
    
    # 4. other_tenant_orders
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS other_tenant_orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER,
            product TEXT NOT NULL,
            amount REAL,
            date TEXT
        )
    """)
    
    # Seed data if tables are empty
    cursor.execute("SELECT COUNT(*) FROM project_x_customers")
    if cursor.fetchone()[0] == 0:
        cursor.executemany("""
            INSERT INTO project_x_customers (name, email, country)
            VALUES (?, ?, ?)
        """, [
            ("Alice Smith", "alice@projectx.com", "USA"),
            ("Bob Jones", "bob@projectx.com", "UK"),
            ("Charlie Brown", "charlie@projectx.com", "Canada")
        ])
        
        cursor.executemany("""
            INSERT INTO project_x_orders (customer_id, product, amount, date)
            VALUES (?, ?, ?, ?)
        """, [
            (1, "Premium Subscription", 199.99, "2026-08-01"),
            (2, "Consulting Hours", 1500.00, "2026-08-05"),
            (1, "API Access Add-on", 49.99, "2026-08-10")
        ])
        
        cursor.executemany("""
            INSERT INTO project_x_employees (name, role, salary)
            VALUES (?, ?, ?)
        """, [
            ("John Doe", "Lead Engineer", 120000.0),
            ("Jane Miller", "Database Administrator", 110000.0),
            ("Jack Wilson", "Security Architect", 130000.0)
        ])
        
        cursor.executemany("""
            INSERT INTO other_tenant_orders (customer_id, product, amount, date)
            VALUES (?, ?, ?, ?)
        """, [
            (10, "Unauthorized Hardware", 9999.99, "2026-08-02"),
            (11, "Secret Server Rental", 500.00, "2026-08-08")
        ])
        
    conn.commit()
    conn.close()

def get_schema() -> Dict[str, Any]:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='table'")
    tables = cursor.fetchall()
    
    schema = {}
    for table_name, create_sql in tables:
        if table_name.startswith("sqlite_"):
            continue
        cursor.execute(f"PRAGMA table_info({table_name})")
        cols = cursor.fetchall()
        schema[table_name] = [
            {"name": col[1], "type": col[2], "notnull": bool(col[3]), "pk": bool(col[5])}
            for col in cols
        ]
        
    conn.close()
    return {"status": "success", "schema": schema}

def validate_sql(sql: str) -> Dict[str, Any]:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        # Using EXPLAIN checks syntax and compiles the query without modifying database
        cursor.execute(f"EXPLAIN {sql}")
        conn.close()
        return {"status": "success", "valid": True}
    except Exception as e:
        conn.close()
        return {"status": "success", "valid": False, "error": str(e)}

def execute_sql(sql: str) -> Dict[str, Any]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        # Check if query returned rows (e.g. SELECT)
        if cursor.description:
            rows = cursor.fetchall()
            results = [dict(row) for row in rows]
            conn.commit()
            conn.close()
            return {"status": "success", "rows": results}
        else:
            conn.commit()
            changes = conn.total_changes
            conn.close()
            return {"status": "success", "rows_affected": changes}
    except Exception as e:
        conn.close()
        return {"status": "error", "error": str(e)}
