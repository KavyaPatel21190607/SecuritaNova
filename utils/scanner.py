import hashlib
import mimetypes
import os
import re
import magic
import logging
from typing import Dict, List, Any

class SecurityScanner:
    """Simulated security scanner with multiple analysis modules"""
    
    def __init__(self, database=None):
        self.database = database
        
        # Risky file extensions
        self.risky_extensions = {
            '.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs', 
            '.js', '.jar', '.app', '.deb', '.rpm', '.dmg', '.pkg'
        }
        
        # Suspicious code patterns
        self.suspicious_patterns = [
            r'eval\s*\(',
            r'exec\s*\(',
            r'system\s*\(',
            r'shell_exec\s*\(',
            r'document\.write\s*\(',
            r'innerHTML\s*=',
            r'outerHTML\s*=',
            r'setTimeout\s*\(',
            r'setInterval\s*\(',
            r'XMLHttpRequest\s*\(',
            r'fetch\s*\(',
            r'crypto\.',
            r'btoa\s*\(',
            r'atob\s*\(',
            r'unescape\s*\(',
            r'String\.fromCharCode\s*\('
        ]
    
    def validate_file(self, filepath: str, original_name: str) -> Dict[str, Any]:
        """Validate file integrity and basic properties"""
        try:
            if not os.path.exists(filepath):
                return {
                    'status': 'failed',
                    'message': 'File not found',
                    'details': {}
                }
            
            file_size = os.path.getsize(filepath)
            if file_size == 0:
                return {
                    'status': 'failed',
                    'message': 'File is empty',
                    'details': {'size': file_size}
                }
            
            # Check file signature vs extension
            try:
                detected_type = magic.from_file(filepath, mime=True)
            except:
                detected_type = mimetypes.guess_type(original_name)[0] or 'unknown'
            
            expected_type = mimetypes.guess_type(original_name)[0] or 'unknown'
            
            type_mismatch = detected_type != expected_type and detected_type != 'unknown'
            
            return {
                'status': 'passed' if not type_mismatch else 'warning',
                'message': 'File validation passed' if not type_mismatch else 'File type mismatch detected',
                'details': {
                    'size': file_size,
                    'detected_type': detected_type,
                    'expected_type': expected_type,
                    'type_mismatch': type_mismatch
                }
            }
            
        except Exception as e:
            logging.error(f"File validation error: {e}")
            return {
                'status': 'error',
                'message': f'Validation failed: {str(e)}',
                'details': {}
            }
    
    def generate_hashes(self, filepath: str) -> Dict[str, str]:
        """Generate MD5 and SHA256 hashes of the file"""
        try:
            md5_hash = hashlib.md5()
            sha256_hash = hashlib.sha256()
            
            with open(filepath, 'rb') as f:
                # Read file in chunks to handle large files
                while chunk := f.read(4096):
                    md5_hash.update(chunk)
                    sha256_hash.update(chunk)
            
            return {
                'md5': md5_hash.hexdigest(),
                'sha256': sha256_hash.hexdigest()
            }
            
        except Exception as e:
            logging.error(f"Hash generation error: {e}")
            return {
                'md5': 'error',
                'sha256': 'error'
            }
    
    def database_lookup(self, hashes: Dict[str, str]) -> Dict[str, Any]:
        """Check hashes against known malicious file database"""
        try:
            md5_hash = hashes.get('md5', '')
            sha256_hash = hashes.get('sha256', '')
            
            # Check against database if available
            if self.database:
                threat_md5 = self.database.check_malicious_hash(md5_hash, 'md5') if md5_hash else None
                threat_sha256 = self.database.check_malicious_hash(sha256_hash, 'sha256') if sha256_hash else None
                
                if threat_md5 or threat_sha256:
                    return {
                        'status': 'malicious',
                        'message': f'File hash matches known malware: {threat_md5 or threat_sha256}',
                        'matched_hash': md5_hash if threat_md5 else sha256_hash
                    }
            
            # Simulate suspicious hash detection (some hashes might be flagged as suspicious)
            if len(md5_hash) == 32 and md5_hash.startswith('a'):
                return {
                    'status': 'suspicious',
                    'message': 'File hash flagged for manual review',
                    'matched_hash': md5_hash
                }
            
            return {
                'status': 'clean',
                'message': 'No matching entries in threat database',
                'matched_hash': None
            }
            
        except Exception as e:
            logging.error(f"Database lookup error: {e}")
            return {
                'status': 'error',
                'message': f'Database lookup failed: {str(e)}',
                'matched_hash': None
            }
    
    def sandbox_analysis(self, filepath: str, filename: str) -> Dict[str, Any]:
        """Simulate sandbox analysis based on file characteristics"""
        try:
            findings = []
            risk_level = 'Low'
            
            # Check file extension
            file_ext = os.path.splitext(filename)[1].lower()
            if file_ext in self.risky_extensions:
                findings.append(f'Potentially dangerous file type: {file_ext}')
                risk_level = 'High'
            
            # Check filename patterns
            suspicious_names = ['temp', 'tmp', 'test', 'backdoor', 'hack', 'virus', 'trojan', 'malware']
            if any(name in filename.lower() for name in suspicious_names):
                findings.append('Suspicious filename pattern detected')
                risk_level = 'Medium' if risk_level == 'Low' else risk_level
            
            # Check file size anomalies
            file_size = os.path.getsize(filepath)
            if file_ext in ['.txt', '.log'] and file_size > 10 * 1024 * 1024:  # >10MB text file
                findings.append('Unusually large text file detected')
                risk_level = 'Medium' if risk_level == 'Low' else risk_level
            
            # Random executable behavior simulation
            if file_ext in ['.exe', '.bat', '.cmd']:
                findings.append('Executable file requires elevated privileges')
                findings.append('Network connection attempts detected')
                risk_level = 'High'
            
            if not findings:
                findings.append('No suspicious behavior detected')
            
            return {
                'risk_level': risk_level,
                'findings': findings,
                'sandbox_time': '30 seconds',
                'network_activity': risk_level == 'High'
            }
            
        except Exception as e:
            logging.error(f"Sandbox analysis error: {e}")
            return {
                'risk_level': 'Unknown',
                'findings': [f'Sandbox analysis failed: {str(e)}'],
                'sandbox_time': '0 seconds',
                'network_activity': False
            }
    
    def heuristic_analysis(self, filepath: str, filename: str, file_size: int) -> Dict[str, Any]:
        """Perform heuristic analysis based on file characteristics"""
        try:
            findings = []
            risk_score = 0
            
            # Filename analysis
            if re.search(r'[a-z]{8,}\.exe$', filename.lower()):
                findings.append('Random-looking executable name')
                risk_score += 25
            
            if any(char in filename for char in ['%', '$', '@', '!', '&']):
                findings.append('Special characters in filename')
                risk_score += 15
            
            # File size analysis
            if file_size > 100 * 1024 * 1024:  # >100MB
                findings.append('Unusually large file size')
                risk_score += 20
            elif file_size < 100:  # <100 bytes
                findings.append('Unusually small file size')
                risk_score += 30
            
            # Extension double-check
            file_ext = os.path.splitext(filename)[1].lower()
            if file_ext in ['.exe', '.scr', '.bat']:
                risk_score += 40
                findings.append('High-risk file extension')
            elif file_ext in ['.js', '.vbs', '.jar']:
                risk_score += 25
                findings.append('Script file detected')
            
            # Entropy check (simplified)
            try:
                with open(filepath, 'rb') as f:
                    sample = f.read(1024)
                    if len(set(sample)) / len(sample) > 0.8:  # High entropy
                        findings.append('High entropy content (possible encryption/packing)')
                        risk_score += 35
            except:
                pass
            
            if not findings:
                findings.append('No heuristic anomalies detected')
            
            return {
                'risk_score': min(risk_score, 100),
                'findings': findings,
                'analysis_type': 'heuristic'
            }
            
        except Exception as e:
            logging.error(f"Heuristic analysis error: {e}")
            return {
                'risk_score': 0,
                'findings': [f'Heuristic analysis failed: {str(e)}'],
                'analysis_type': 'heuristic'
            }
    
    def static_code_analysis(self, filepath: str, filename: str) -> Dict[str, Any]:
        """Perform static code analysis for text-based files"""
        try:
            findings = []
            risk_score = 0
            file_ext = os.path.splitext(filename)[1].lower()
            
            # Only analyze text-based files
            text_extensions = ['.js', '.html', '.htm', '.php', '.py', '.pl', '.sh', '.bat', '.cmd', '.vbs', '.txt', '.sql']
            
            if file_ext not in text_extensions:
                return {
                    'risk_score': 0,
                    'findings': ['Static analysis not applicable for this file type'],
                    'patterns_found': []
                }
            
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(50000)  # Read first 50KB
                
                patterns_found = []
                
                # Check for suspicious patterns
                for pattern in self.suspicious_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        patterns_found.append(pattern)
                        risk_score += 10
                
                # Specific checks
                if 'eval(' in content.lower():
                    findings.append('Dynamic code execution detected (eval)')
                    risk_score += 20
                
                if 'document.write(' in content.lower():
                    findings.append('DOM manipulation detected')
                    risk_score += 15
                
                if re.search(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', content):
                    findings.append('External URLs found')
                    risk_score += 10
                
                if len(content) > 10000 and content.count('\n') < 50:
                    findings.append('Minified or obfuscated code detected')
                    risk_score += 25
                
                if not findings:
                    findings.append('No suspicious code patterns detected')
                
                return {
                    'risk_score': min(risk_score, 100),
                    'findings': findings,
                    'patterns_found': patterns_found
                }
                
            except UnicodeDecodeError:
                return {
                    'risk_score': 20,
                    'findings': ['File contains non-text content or encoding issues'],
                    'patterns_found': []
                }
                
        except Exception as e:
            logging.error(f"Static code analysis error: {e}")
            return {
                'risk_score': 0,
                'findings': [f'Static analysis failed: {str(e)}'],
                'patterns_found': []
            }
