import os
import json
import threading
from datetime import datetime, timedelta
from functools import wraps
from flask import session, redirect, url_for, flash
import threading
import time

_session_cache = {}
_cache_lock = threading.RLock()
_cache_size_limit = 1000
_cache_ttl = 30

def _get_cached_session(token):
    with _cache_lock:
        if token in _session_cache:
            session_data, timestamp = _session_cache[token]
            if (datetime.now() - timestamp).seconds < _cache_ttl:
                return session_data
            else:
                del _session_cache[token]
    return None

def _cache_session(token, session_data):
    with _cache_lock:
        if len(_session_cache) >= _cache_size_limit:
            oldest_tokens = sorted(_session_cache.keys(), 
                                 key=lambda k: _session_cache[k][1])[:50]
            for old_token in oldest_tokens:
                del _session_cache[old_token]
        
        _session_cache[token] = (session_data, datetime.now())

_lock = threading.RLock()
SESSIONS_FILE_ID = os.environ.get("SESSIONS_FILE_ID")

# Add local cache with expiry
_sessions_cache = {}
_cache_timestamp = None
CACHE_DURATION = 300  # 5 minutes cache

def _is_token_expired(last_seen_str, hours=3):
    """Check if token is expired based on last seen time"""
    try:
        last_seen = datetime.fromisoformat(last_seen_str)
        return datetime.now() - last_seen > timedelta(hours=hours)
    except:
        return True

def _get_cached_sessions():
    """Get sessions from cache if fresh, otherwise from Drive"""
    global _sessions_cache, _cache_timestamp
    
    now = datetime.now()
    if (_cache_timestamp and 
        _sessions_cache and 
        (now - _cache_timestamp).seconds < CACHE_DURATION):
        return _sessions_cache.copy()
    
    # Cache expired or empty, load from Drive
    sessions = _load_sessions_from_drive()
    _sessions_cache = sessions
    _cache_timestamp = now
    return sessions.copy()

def _invalidate_cache():
    """Clear the cache"""
    global _sessions_cache, _cache_timestamp
    _sessions_cache = {}
    _cache_timestamp = None

def _load_sessions_from_drive():
    """Load sessions directly from Google Drive"""
    try:
        from google_drive_service import create_drive_service
        
        service = create_drive_service()
        if not service or not SESSIONS_FILE_ID:
            return {}
        
        # Download JSON file
        file_content = service.files().get_media(fileId=SESSIONS_FILE_ID).execute()
        sessions_data = json.loads(file_content.decode('utf-8'))
        
        return sessions_data
    except Exception as e:
        print(f"Error loading sessions from Drive: {e}")
        return {}

def _load_active_sessions():
    """Load sessions with caching and auto-cleanup"""
    try:
        sessions_data = _get_cached_sessions()
        
        # Filter expired sessions
        active_sessions = {}
        for token, data in sessions_data.items():
            if not _is_token_expired(data.get('last_seen', '2020-01-01T00:00:00')):
                active_sessions[token] = data
        
        # Save cleaned sessions if we removed any expired ones
        if len(active_sessions) != len(sessions_data):
            _save_sessions(active_sessions)
            print(f"Cleaned {len(sessions_data) - len(active_sessions)} expired sessions")
        
        return active_sessions
    except Exception as e:
        print(f"Error loading sessions: {e}")
        return {}

def _save_sessions(sessions_data):
    try:
        from google_drive_service import create_drive_service
        from googleapiclient.http import MediaInMemoryUpload
        
        service = create_drive_service()
        if not service or not SESSIONS_FILE_ID:
            print("[_save_sessions] No Drive service or file ID available")
            return False
        
        json_content = json.dumps(sessions_data, indent=2)
        media = MediaInMemoryUpload(json_content.encode('utf-8'), mimetype='application/json')
        
        service.files().update(fileId=SESSIONS_FILE_ID, media_body=media).execute()
        
        _invalidate_cache()
        return True
    except Exception as e:
        error_msg = str(e).lower()
        if "ssl" in error_msg or "connection" in error_msg or "timeout" in error_msg:
            print(f"[_save_sessions] Connection error (will retry): {e}")
        else:
            print(f"[_save_sessions] Error saving sessions to Drive: {e}")
        return False

def generate_session_token():
    import secrets
    return secrets.token_urlsafe(32)

def save_session_record(session_data):
    with _lock:
        try:
            sessions = _load_active_sessions()
        except Exception:
            sessions = {}
        
        user_id = str(session_data.get('user_id')) if session_data.get('user_id') is not None else None
        new_token = session_data.get('token')
        if not new_token or not user_id:
            return False
        
        is_admin_session = session_data.get('admin_session', False)
        print(f"[save_session_record] Creating session for user {user_id}, admin_session={is_admin_session}")
        
        # SIMPLE SOLUTION: Remove ALL existing sessions for this user (like user login does)
        existing_sessions = [token for token, data in sessions.items() if str(data.get('user_id')) == user_id]
        print(f"[save_session_record] Found {len(existing_sessions)} existing sessions for user {user_id}")
        print(f"[save_session_record] Removing ALL {len(existing_sessions)} existing sessions")
        
        for old_token in existing_sessions:
            print(f"[save_session_record] Removing session: {old_token}")
            sessions.pop(old_token, None)
            try:
                with _cache_lock:
                    _session_cache.pop(old_token, None)
            except Exception:
                pass
        
        # Create the new session
        sessions[new_token] = {
            'user_id': user_id,
            'device_info': session_data.get('device_info', 'unknown'),
            'last_seen': datetime.now().isoformat(),
            'is_exam_active': session_data.get('is_exam_active', False),
            'admin_session': is_admin_session,
            'active': True
        }
        
        print(f"[save_session_record] Created new session: {sessions[new_token]}")
        print(f"[save_session_record] Total sessions after cleanup: {len(sessions)}")
        
        # Save to Drive
        for attempt in range(3):
            try:
                ok = _save_sessions(sessions)
                if ok:
                    try:
                        _invalidate_cache()
                    except Exception:
                        pass
                    print(f"[save_session_record] Successfully saved sessions to Drive")
                    return True
            except Exception as e:
                print(f"save_session_record: attempt {attempt+1} failed: {e}")
            time.sleep(0.5 * (2 ** attempt))
        
        # Fallback to local save
        try:
            local_path = os.path.join(os.getcwd(), "sessions_local.json")
            with open(local_path, "w", encoding="utf-8") as fh:
                json.dump(sessions, fh, indent=2)
            try:
                with _cache_lock:
                    global _sessions_cache, _cache_timestamp
                    _sessions_cache = sessions.copy()
                    _cache_timestamp = datetime.now()
            except Exception:
                pass
            print("save_session_record: fallback saved to sessions_local.json")
            return True
        except Exception as e:
            print(f"save_session_record: fallback write failed: {e}")
            return False

def get_session_by_token(token):
    if not token:
        return None
    
    cached_session = _get_cached_session(token)
    if cached_session:
        return cached_session
    
    sessions = _load_active_sessions()
    session_data = sessions.get(token)
    
    if session_data:
        _cache_session(token, session_data)
    
    return session_data

def invalidate_session(user_id, token=None):
    with _lock:
        sessions = _load_active_sessions()
        user_id = str(user_id)
        removed = False
        
        if token:
            if token in sessions and str(sessions[token].get('user_id')) == user_id:
                del sessions[token]
                removed = True
                with _cache_lock:
                    _session_cache.pop(token, None)
        else:
            to_remove = [t for t, data in sessions.items() 
                        if str(data.get('user_id')) == user_id]
            for t in to_remove:
                del sessions[t]
                with _cache_lock:
                    _session_cache.pop(t, None)
            removed = len(to_remove) > 0
        
        if removed:
            return _save_sessions(sessions)
    return False

def update_last_seen(user_id, token):
    """Update last seen timestamp"""
    with _lock:
        sessions = _load_active_sessions()
        if token in sessions and str(sessions[token].get('user_id')) == str(user_id):
            sessions[token]['last_seen'] = datetime.now().isoformat()
            return _save_sessions(sessions)
    return False

def set_exam_active(user_id, token, exam_id=None, result_id=None, is_active=True):
    """Set exam active status"""
    with _lock:
        sessions = _load_active_sessions()
        if token in sessions and str(sessions[token].get('user_id')) == str(user_id):
            sessions[token]['is_exam_active'] = is_active
            if exam_id is not None:
                sessions[token]['exam_id'] = exam_id
            if result_id is not None:
                sessions[token]['result_id'] = result_id
            return _save_sessions(sessions)
    return False

def get_active_session_count(user_id):
    """Get number of active sessions for a user (should be 1 or 0)"""
    sessions = _load_active_sessions()
    user_id = str(user_id)
    count = sum(1 for data in sessions.values() if str(data.get('user_id')) == user_id)
    return count

def get_user_role(user_id):
    """Get user role from users.csv cache"""
    try:
        from main import load_csv_with_cache
        users_df = load_csv_with_cache('users.csv')
        if users_df is not None and not users_df.empty:
            user_row = users_df[users_df['id'].astype(str) == str(user_id)]
            if not user_row.empty:
                role = user_row.iloc[0].get('role', '')
                return str(role).lower().strip()
    except Exception as e:
        print(f"Error getting user role: {e}")
    return None

# Ultra-lightweight decorators
def require_valid_session(f):
    """Basic session validation"""
    @wraps(f)
    def wrapped(*args, **kwargs):
        uid = session.get("user_id")
        tok = session.get("token")
        
        if not uid or not tok:
            return redirect(url_for("login"))
        
        # Quick check - expired tokens are auto-removed by _load_active_sessions
        if not get_session_by_token(tok):
            session.clear()
            flash("Session expired. Please login again.", "warning")
            return redirect(url_for("login"))
        
        return f(*args, **kwargs)
    return wrapped

def require_user_role(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        uid = session.get("user_id")
        tok = session.get("token")
        
        if not uid or not tok:
            flash("Please login to access this page.", "warning")
            return redirect(url_for("login"))
        
        session_data = get_session_by_token(tok)
        if not session_data:
            session.clear()
            flash("Your session has expired or you've been logged out from another device.", "warning")
            return redirect(url_for("login"))
        
        if session_data.get('admin_session', False):
            flash("You are logged in as Admin. Please logout to access User portal.", "warning")
            return redirect(url_for("admin.dashboard"))
        
        admin_id = session.get("admin_id")
        if admin_id:
            flash("You are logged in as Admin. Please logout to access User portal.", "warning")
            return redirect(url_for("admin.dashboard"))
        
        return f(*args, **kwargs)
    return wrapped

def require_admin_role(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        uid = session.get("user_id")
        tok = session.get("token")
        admin_id = session.get("admin_id")
        
        if not uid or not tok or not admin_id:
            flash("Admin login required.", "warning")
            return redirect(url_for("admin.admin_login"))
        
        # Load ALL current sessions and check if this user has multiple admin sessions
        try:
            sessions = _load_active_sessions()
            user_admin_sessions = []
            for token, data in sessions.items():
                if (str(data.get('user_id')) == str(uid) and 
                    data.get('admin_session', False)):
                    user_admin_sessions.append(token)
            
            print(f"[require_admin_role] Found {len(user_admin_sessions)} admin sessions for user {uid}")
            print(f"[require_admin_role] Current token: {tok}")
            print(f"[require_admin_role] Admin session tokens: {user_admin_sessions}")
            
            # If there are multiple admin sessions, keep only the current one
            if len(user_admin_sessions) > 1:
                print(f"[require_admin_role] MULTIPLE ADMIN SESSIONS DETECTED - Removing others")
                for token_to_remove in user_admin_sessions:
                    if token_to_remove != tok:  # Keep current session
                        print(f"[require_admin_role] Removing admin session: {token_to_remove}")
                        sessions.pop(token_to_remove, None)
                        try:
                            with _cache_lock:
                                _session_cache.pop(token_to_remove, None)
                        except Exception:
                            pass
                
                # Save cleaned sessions
                try:
                    _save_sessions(sessions)
                    _invalidate_cache()
                    print("[require_admin_role] Cleaned up multiple admin sessions")
                except Exception as e:
                    print(f"[require_admin_role] Error saving cleaned sessions: {e}")
            
            # Verify current session is still valid
            session_data = sessions.get(tok)
            if not session_data:
                session.clear()
                flash("Session expired. Please login again.", "warning")
                return redirect(url_for("admin.admin_login"))
            
            if not session_data.get('admin_session', False):
                session.clear()
                flash("Invalid admin session. Please login as admin.", "warning")
                return redirect(url_for("admin.admin_login"))
                
        except Exception as e:
            print(f"[require_admin_role] Error checking sessions: {e}")
        
        return f(*args, **kwargs)
    return wrapped

# Optional: Force cleanup every hour (lightweight since we auto-clean on load)
def periodic_maintenance():
    """Light maintenance - just touch the cache to trigger auto-cleanup"""
    try:
        _load_active_sessions()  # This will auto-clean expired tokens
    except:
        pass
    threading.Timer(3600, periodic_maintenance).start()  # 1 hour

# Start periodic maintenance
periodic_maintenance()

print("✅ Sessions module loaded with Google Drive caching and single session enforcement")