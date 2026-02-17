#!/usr/bin/env python3
"""
Database initialization script
Initializes the database schema and applies migrations
"""
import sys
import os

# Add parent directory to path to import main.py
parent_dir = '/vercel/share/v0-project'
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

try:
    from main import init_db, migrate_db
    
    print("[INFO] Starting database initialization...")
    
    # Initialize database schema
    init_db()
    
    # Apply migrations
    migrate_db()
    
    print("[INFO] Database initialization completed successfully!")
except Exception as e:
    print(f"[ERROR] Database initialization failed: {str(e)}")
    import traceback
    traceback.print_exc()
