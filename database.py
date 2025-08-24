import sqlite3
import os
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional

class SecuritaNovaDB:
    """Database manager for SecuritaNova antivirus scanner"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize the database with required tables"""
        # Create instance folder if it doesn't exist
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS scan_results (
                    scan_id TEXT PRIMARY KEY,
                    file_name TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    file_type TEXT,
                    scan_timestamp TEXT NOT NULL,
                    validation_data TEXT,
                    hashes_data TEXT,
                    database_lookup_data TEXT,
                    sandbox_analysis_data TEXT,
                    heuristic_analysis_data TEXT,
                    code_analysis_data TEXT,
                    gemini_analysis_data TEXT,
                    overall_threat_data TEXT,
                    status TEXT DEFAULT 'completed'
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS file_storage (
                    scan_id TEXT PRIMARY KEY,
                    filepath TEXT NOT NULL,
                    original_name TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    upload_timestamp REAL NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scan_results (scan_id)
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS scan_progress (
                    scan_id TEXT PRIMARY KEY,
                    stage TEXT NOT NULL,
                    progress INTEGER NOT NULL,
                    message TEXT,
                    updated_at REAL NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scan_results (scan_id)
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS malicious_hashes (
                    hash_value TEXT PRIMARY KEY,
                    hash_type TEXT NOT NULL,
                    threat_name TEXT,
                    added_date TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Insert some sample malicious hashes
            sample_hashes = [
                ('c3ab8ff13720e8ad9047dd39466b3c89', 'md5', 'Sample.Trojan.A'),
                ('5d41402abc4b2a76b9719d911017c592', 'md5', 'Sample.Malware.B'),
                ('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'sha256', 'Sample.Virus.C'),
                ('2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae', 'sha256', 'Sample.Spyware.D')
            ]
            
            conn.executemany('''
                INSERT OR IGNORE INTO malicious_hashes (hash_value, hash_type, threat_name)
                VALUES (?, ?, ?)
            ''', sample_hashes)
            
            conn.commit()
            logging.info(f"Database initialized at {self.db_path}")
    
    def store_file_info(self, scan_id: str, filepath: str, original_name: str, file_size: int, timestamp: float):
        """Store file information"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT OR REPLACE INTO file_storage 
                (scan_id, filepath, original_name, file_size, upload_timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (scan_id, filepath, original_name, file_size, timestamp))
            conn.commit()
    
    def get_file_info(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get file information"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('''
                SELECT * FROM file_storage WHERE scan_id = ?
            ''', (scan_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def update_scan_progress(self, scan_id: str, stage: str, progress: int, message: str):
        """Update scan progress"""
        import time
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT OR REPLACE INTO scan_progress
                (scan_id, stage, progress, message, updated_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (scan_id, stage, progress, message, time.time()))
            conn.commit()
    
    def get_scan_progress(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get scan progress"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('''
                SELECT * FROM scan_progress WHERE scan_id = ?
            ''', (scan_id,))
            row = cursor.fetchone()
            if row:
                return {
                    'stage': row['stage'],
                    'progress': row['progress'],
                    'message': row['message']
                }
            return None
    
    def store_scan_results(self, scan_id: str, results: Dict[str, Any]):
        """Store complete scan results"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT OR REPLACE INTO scan_results 
                (scan_id, file_name, file_size, file_type, scan_timestamp,
                 validation_data, hashes_data, database_lookup_data,
                 sandbox_analysis_data, heuristic_analysis_data,
                 code_analysis_data, gemini_analysis_data, overall_threat_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id,
                results['file_name'],
                results['file_size'],
                results['file_type'],
                results['scan_timestamp'],
                json.dumps(results['validation']),
                json.dumps(results['hashes']),
                json.dumps(results['database_lookup']),
                json.dumps(results['sandbox_analysis']),
                json.dumps(results['heuristic_analysis']),
                json.dumps(results['code_analysis']),
                json.dumps(results['gemini_analysis']),
                json.dumps(results['overall_threat_level'])
            ))
            conn.commit()
    
    def get_scan_results(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get complete scan results"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('''
                SELECT * FROM scan_results WHERE scan_id = ?
            ''', (scan_id,))
            row = cursor.fetchone()
            
            if row:
                return {
                    'scan_id': row['scan_id'],
                    'file_name': row['file_name'],
                    'file_size': row['file_size'],
                    'file_type': row['file_type'],
                    'scan_timestamp': row['scan_timestamp'],
                    'validation': json.loads(row['validation_data']),
                    'hashes': json.loads(row['hashes_data']),
                    'database_lookup': json.loads(row['database_lookup_data']),
                    'sandbox_analysis': json.loads(row['sandbox_analysis_data']),
                    'heuristic_analysis': json.loads(row['heuristic_analysis_data']),
                    'code_analysis': json.loads(row['code_analysis_data']),
                    'gemini_analysis': json.loads(row['gemini_analysis_data']),
                    'overall_threat_level': json.loads(row['overall_threat_data'])
                }
            return None
    
    def check_malicious_hash(self, hash_value: str, hash_type: str) -> Optional[str]:
        """Check if hash is in malicious database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                SELECT threat_name FROM malicious_hashes 
                WHERE hash_value = ? AND hash_type = ?
            ''', (hash_value, hash_type))
            row = cursor.fetchone()
            return row[0] if row else None
    
    def cleanup_old_files(self, max_age_hours: int = 24):
        """Clean up old file records and scan data"""
        import time
        cutoff_time = time.time() - (max_age_hours * 3600)
        
        with sqlite3.connect(self.db_path) as conn:
            # Get old file paths for deletion
            cursor = conn.execute('''
                SELECT filepath FROM file_storage 
                WHERE upload_timestamp < ?
            ''', (cutoff_time,))
            old_files = [row[0] for row in cursor.fetchall()]
            
            # Delete old records
            conn.execute('DELETE FROM file_storage WHERE upload_timestamp < ?', (cutoff_time,))
            conn.execute('DELETE FROM scan_progress WHERE updated_at < ?', (cutoff_time,))
            conn.execute('DELETE FROM scan_results WHERE scan_id NOT IN (SELECT scan_id FROM file_storage)')
            conn.commit()
            
            # Delete actual files
            for filepath in old_files:
                try:
                    if os.path.exists(filepath):
                        os.remove(filepath)
                except Exception as e:
                    logging.error(f"Error removing file {filepath}: {e}")
            
            logging.info(f"Cleaned up {len(old_files)} old files")