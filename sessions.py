import os
from functools import wraps
from flask import session, redirect, url_for, flash
from datetime import time

# ✅ Import Supabase functions
from supabase_db import (
    create_session as db_create_session,
    get_session_by_token as db_get_session,
    invalidate_session as db_invalidate_session,
    update_session_last_seen
)

def generate_session_token():
    import secrets
    return secrets.token_urlsafe(32)

def save_session_record(session_data):
    """Save session to Supabase"""
    try:
        print(f"[save_session_record] Creating session for user {session_data.get('user_id')}, admin={session_data.get('admin_session', False)}")
        
        # ✅ Invalidate old sessions first
        user_id = session_data.get('user_id')
        if user_id:
            db_invalidate_session(int(user_id))
        
        # ✅ Create new session in Supabase
        result = db_create_session(session_data)
        
        if result:
            print(f"[save_session_record] ✅ Session saved successfully")
            return True
        else:
            print(f"[save_session_record] ❌ Failed to save session")
            return False
            
    except Exception as e:
        print(f"[save_session_record] Error: {e}")
        import traceback
        traceback.print_exc()
        return False

def get_session_by_token(token):
    """Get session from Supabase"""
    if not token:
        return None
    
    try:
        session_data = db_get_session(token)
        
        if session_data:
            # ✅ Update last seen
            update_session_last_seen(token)
            
        return session_data
        
    except Exception as e:
        print(f"[get_session_by_token] Error: {e}")
        return None

def invalidate_session(user_id, token=None):
    """Invalidate session in Supabase"""
    try:
        return db_invalidate_session(int(user_id), token)
    except Exception as e:
        print(f"[invalidate_session] Error: {e}")
        return False

def set_exam_active(user_id, token, exam_id=None, result_id=None, is_active=True):
    """Set exam active status"""
    try:
        from supabase_db import supabase
        
        update_data = {'is_exam_active': is_active}
        if exam_id is not None:
            update_data['exam_id'] = exam_id
        if result_id is not None:
            update_data['result_id'] = result_id
        
        supabase.table('sessions').update(update_data).eq('token', token).execute()
        return True
    except Exception as e:
        print(f"[set_exam_active] Error: {e}")
        return False

# ==========================================
# DECORATORS
# ==========================================

def require_valid_session(f):
    """Basic session validation"""
    @wraps(f)
    def wrapped(*args, **kwargs):
        uid = session.get("user_id")
        tok = session.get("token")
        
        if not uid or not tok:
            return redirect(url_for("login"))
        
        # Check if session exists in Supabase
        session_data = get_session_by_token(tok)
        if not session_data:
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
            flash("Your session has expired.", "warning")
            return redirect(url_for("login"))
        
        # ✅ Check if admin session (prevent admin accessing user portal)
        if session_data.get('admin_session', False):
            flash("You are logged in as Admin. Please logout to access User portal.", "warning")
            return redirect(url_for("admin.dashboard"))
        
        return f(*args, **kwargs)
    return wrapped

def require_admin_role(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        token = session.get('token')
        user_id = session.get('user_id')
        
        if not token or not user_id:
            return redirect(url_for('admin.admin_login'))
        
        # ✅ RETRY LOGIC for Supabase
        session_data = None
        for attempt in range(3):
            try:
                session_data = get_session_by_token(token)
                if session_data:
                    break
            except Exception as e:
                print(f"[require_admin_role] Retry {attempt + 1}: {e}")
                time.sleep(0.5 * (attempt + 1))
        
        if not session_data:
            print(f"[require_admin_role] Session data: None (after retries)")
            session.clear()
            flash("Session expired. Please login again.", "warning")
            return redirect(url_for('admin.admin_login'))
        
        print(f"[require_admin_role] Session data: {session_data}")
        
        if not session_data:
            session.clear()
            flash("Session expired. Please login again.", "warning")
            return redirect(url_for("admin.admin_login"))
        
        # ✅ Check admin_session flag
        if not session_data.get('admin_session', False):
            session.clear()
            flash("Invalid admin session. Please login as admin.", "warning")
            return redirect(url_for("admin.admin_login"))
        
        return f(*args, **kwargs)
    return wrapped

print("✅ Sessions module loaded with Supabase support")