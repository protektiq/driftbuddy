#!/usr/bin/env python3
"""
Database migration script for integrations
Adds integration_id, source, and raw_data columns to findings table
"""

import sqlite3
import os
from datetime import datetime

def migrate_database():
    """Migrate the database to add integration columns"""
    db_path = "driftbuddy.db"
    
    if not os.path.exists(db_path):
        print("❌ Database file not found. Please run the application first to create the database.")
        return False
    
    print("🔧 Starting database migration for integrations...")
    
    try:
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if columns already exist
        cursor.execute("PRAGMA table_info(findings)")
        columns = [column[1] for column in cursor.fetchall()]
        
        print(f"📋 Current findings table columns: {columns}")
        
        # Add integration_id column if it doesn't exist
        if 'integration_id' not in columns:
            print("➕ Adding integration_id column...")
            cursor.execute("ALTER TABLE findings ADD COLUMN integration_id INTEGER")
            print("✅ integration_id column added")
        else:
            print("✅ integration_id column already exists")
        
        # Add source column if it doesn't exist
        if 'source' not in columns:
            print("➕ Adding source column...")
            cursor.execute("ALTER TABLE findings ADD COLUMN source VARCHAR(100)")
            print("✅ source column added")
        else:
            print("✅ source column already exists")
        
        # Add raw_data column if it doesn't exist
        if 'raw_data' not in columns:
            print("➕ Adding raw_data column...")
            cursor.execute("ALTER TABLE findings ADD COLUMN raw_data TEXT")
            print("✅ raw_data column added")
        else:
            print("✅ raw_data column already exists")
        
        # Commit changes
        conn.commit()
        
        # Verify the migration
        cursor.execute("PRAGMA table_info(findings)")
        updated_columns = [column[1] for column in cursor.fetchall()]
        print(f"📋 Updated findings table columns: {updated_columns}")
        
        print("✅ Database migration completed successfully!")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        return False

if __name__ == "__main__":
    success = migrate_database()
    if success:
        print("\n🎉 Migration completed! You can now restart the application.")
    else:
        print("\n💥 Migration failed! Please check the error messages above.") 