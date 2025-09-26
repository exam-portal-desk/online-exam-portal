import os
import json
import threading
from datetime import datetime, timedelta

_lock = threading.RLock()
LOGIN_ATTEMPTS_FILE_ID = os.environ.get("LOGIN_ATTEMPTS_FILE_ID")

# Cache for login attempts
_login_attempts_cache = {}
_cache_timestamp = None
CACHE_DURATION = 300  # 5 minutes cache

def _get_cache_key(identifier: str, ip: str) -> str:
    """Generate cache key for identifier+IP combination"""
    return f"{identifier.lower()}:{ip}"

def _is_attempt_expired(first_failed_str: str, minutes: int = 15) -> bool:
    """Check if login attempt window has expired"""
    try:
        first_failed = datetime.fromisoformat(first_failed_str)
        return datetime.now() - first_failed > timedelta(minutes=minutes)
    except:
        return True

def _get_cached_login_attempts():
    """Get login attempts from cache if fresh, otherwise from Drive"""
    global _login_attempts_cache, _cache_timestamp
    
    now = datetime.now()
    if (_cache_timestamp and 
        _login_attempts_cache and 
        (now - _cache_timestamp).seconds < CACHE_DURATION):
        return _login_attempts_cache.copy()
    
    # Cache expired or empty, load from Drive
    attempts_data = _load_login_attempts_from_drive()
    _login_attempts_cache = attempts_data
    _cache_timestamp = now
    return attempts_data.copy()

def _invalidate_login_attempts_cache():
    """Clear the login attempts cache"""
    global _login_attempts_cache, _cache_timestamp
    _login_attempts_cache = {}
    _cache_timestamp = None

def _load_login_attempts_from_drive():
    """Load login attempts JSON directly from Google Drive - PERFORMANCE OPTIMIZED"""
    try:
        # PERFORMANCE FIX: Use get_drive_service() instead of create_drive_service()
        from google_drive_service import get_drive_service
        
        service = get_drive_service()  # This reuses the global instance!
        if not service or not LOGIN_ATTEMPTS_FILE_ID:
            return {}
        
        # Download JSON file
        file_content = service.files().get_media(fileId=LOGIN_ATTEMPTS_FILE_ID).execute()
        attempts_data = json.loads(file_content.decode('utf-8'))
        
        # Clean expired attempts automatically
        cleaned_data = {}
        now = datetime.now()
        
        for key, data in attempts_data.items():
            # Check if blocked period has passed
            if data.get('blocked_until'):
                try:
                    blocked_until = datetime.fromisoformat(data['blocked_until'])
                    if now > blocked_until:
                        # Unblock by clearing blocked_until
                        data['blocked_until'] = None
                except:
                    data['blocked_until'] = None
            
            # Remove if attempt window expired (15 minutes)
            if not _is_attempt_expired(data.get('first_failed_at', '2020-01-01T00:00:00')):
                cleaned_data[key] = data
        
        # Save cleaned data if we removed expired attempts
        if len(cleaned_data) != len(attempts_data):
            _save_login_attempts_to_drive(cleaned_data)
            print(f"Cleaned {len(attempts_data) - len(cleaned_data)} expired login attempts")
        
        return cleaned_data
    except Exception as e:
        print(f"Error loading login attempts from Drive: {e}")
        return {}

def _save_login_attempts_to_drive(attempts_data):
    """Save login attempts to Google Drive JSON and invalidate cache - PERFORMANCE OPTIMIZED"""
    try:
        # PERFORMANCE FIX: Use get_drive_service() instead of create_drive_service()
        from google_drive_service import get_drive_service
        from googleapiclient.http import MediaInMemoryUpload
        
        service = get_drive_service()  # This reuses the global instance!
        if not service or not LOGIN_ATTEMPTS_FILE_ID:
            return False
        
        # Convert to JSON
        json_content = json.dumps(attempts_data, indent=2)
        media = MediaInMemoryUpload(json_content.encode('utf-8'), mimetype='application/json')
        
        # Update file on Drive
        service.files().update(fileId=LOGIN_ATTEMPTS_FILE_ID, media_body=media).execute()
        
        # Invalidate cache after save
        _invalidate_login_attempts_cache()
        return True
    except Exception as e:
        print(f"Error saving login attempts to Drive: {e}")
        return False

def check_login_attempts(identifier: str, ip: str) -> tuple:
    """Check if login attempts are within allowed limits - JSON CACHED VERSION"""
    try:
        with _lock:
            attempts_data = _get_cached_login_attempts()
            cache_key = _get_cache_key(identifier, ip)
            
            if cache_key not in attempts_data:
                return True, "", 5  # No previous attempts
            
            attempt_record = attempts_data[cache_key]
            
            # Check if currently blocked (only if blocked_until field exists)
            if 'blocked_until' in attempt_record:
                try:
                    blocked_until = datetime.fromisoformat(attempt_record['blocked_until'])
                    if datetime.now() < blocked_until:
                        minutes_left = int((blocked_until - datetime.now()).total_seconds() / 60) + 1
                        return False, f"Too many failed attempts. Try again in {minutes_left} minutes.", 0
                    else:
                        # Block period expired, remove blocked_until field
                        del attempt_record['blocked_until']
                        _save_login_attempts_to_drive(attempts_data)
                except:
                    # Invalid blocked_until format, remove it
                    del attempt_record['blocked_until']
            
            # Check if attempt window expired (15 minutes)
            if _is_attempt_expired(attempt_record.get('first_failed_at', '2020-01-01T00:00:00')):
                # Remove expired attempt record
                del attempts_data[cache_key]
                _save_login_attempts_to_drive(attempts_data)
                return True, "", 5
            
            failed_count = attempt_record.get('failed_count', 0)
            remaining = max(0, 5 - failed_count)
            
            if remaining <= 0:
                return False, "Too many failed attempts. Account temporarily locked.", 0
            
            return True, "", remaining
            
    except Exception as e:
        print(f"Error checking login attempts: {e}")
        return True, "", 5

def record_failed_login(identifier: str, ip: str) -> bool:
    """Record a failed login attempt - JSON CACHED VERSION"""
    try:
        with _lock:
            attempts_data = _get_cached_login_attempts()
            cache_key = _get_cache_key(identifier, ip)
            
            now = datetime.now()
            now_str = now.isoformat()  # Use ISO format for consistency
            
            if cache_key not in attempts_data:
                # Create new attempt record (no blocked_until field when not blocked)
                attempts_data[cache_key] = {
                    'identifier': identifier.lower(),  # Could be username or email
                    'ip': ip,
                    'failed_count': 1,
                    'first_failed_at': now_str,
                    'last_failed_at': now_str
                }
                print(f"New failed login attempt for {identifier} from {ip}: 1/5")
            else:
                # Update existing record
                attempt_record = attempts_data[cache_key]
                failed_count = attempt_record.get('failed_count', 0) + 1
                
                attempt_record['failed_count'] = failed_count
                attempt_record['last_failed_at'] = now_str
                
                # Block if 5 attempts reached - ONLY THEN add blocked_until field
                if failed_count >= 5:
                    blocked_until = now + timedelta(minutes=15)
                    attempt_record['blocked_until'] = blocked_until.isoformat()
                    print(f"Account blocked for {identifier} from {ip} until {blocked_until}")
                else:
                    # Remove blocked_until field if it exists but user isn't blocked
                    attempt_record.pop('blocked_until', None)
                    print(f"Failed login attempt for {identifier} from {ip}: {failed_count}/5")
            
            return _save_login_attempts_to_drive(attempts_data)
            
    except Exception as e:
        print(f"Error recording failed login: {e}")
        return False

def clear_login_attempts(identifier: str, ip: str) -> bool:
    """Clear login attempts for successful login - JSON CACHED VERSION"""
    try:
        with _lock:
            attempts_data = _get_cached_login_attempts()
            cache_key = _get_cache_key(identifier, ip)
            
            if cache_key in attempts_data:
                del attempts_data[cache_key]
                print(f"Cleared login attempts for {identifier} from {ip}")
                return _save_login_attempts_to_drive(attempts_data)
            
            return True  # No attempts to clear
            
    except Exception as e:
        print(f"Error clearing login attempts: {e}")
        return False

def get_login_attempt_stats(identifier: str = None) -> dict:
    """Get login attempt statistics - useful for debugging"""
    try:
        attempts_data = _get_cached_login_attempts()
        
        if identifier:
            # Stats for specific identifier
            identifier_attempts = {k: v for k, v in attempts_data.items() if v.get('identifier') == identifier.lower()}
            return {
                'total_attempts': len(identifier_attempts),
                'attempts': identifier_attempts
            }
        else:
            # Global stats
            total_attempts = len(attempts_data)
            blocked_count = sum(1 for v in attempts_data.values() if 'blocked_until' in v)
            
            return {
                'total_records': total_attempts,
                'blocked_ips': blocked_count,
                'active_attempts': total_attempts - blocked_count
            }
    except Exception as e:
        print(f"Error getting login attempt stats: {e}")
        return {}

print("✅ Login attempts JSON caching module loaded")