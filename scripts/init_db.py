#!/usr/bin/env python3
"""
Database initialization script
Initializes the database schema and applies migrations
"""
import sys
import os

# Add parent directory to path to import main.py
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import init_db, migrate_db

if __name__ == "__main__":
    print("[INFO] Starting database initialization...")
    
    # Initialize database schema
    init_db()
    
    # Apply migrations
    migrate_db()
    
    print("[INFO] Database initialization completed successfully!")
