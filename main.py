from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import pandas as pd

# ✅ Supabase imports (complete migration)
from supabase_db import (
    get_user_by_username, get_user_by_id, get_user_by_email,
    get_all_users, create_user, update_user,
    get_all_exams, get_exam_by_id, create_exam,
    get_questions_by_exam, create_question,
    create_session, get_session_by_token, invalidate_session,
    update_session_last_seen, check_login_attempts,
    record_failed_login, clear_login_attempts,
    get_all_results, get_result_by_id, get_results_by_user, get_results_by_exam,
    get_responses_by_result, create_result, create_response, create_responses_bulk,
    get_latest_attempt, get_completed_attempts_count, create_exam_attempt, update_exam_attempt,
    get_password_token, create_password_token as db_create_password_token, mark_token_used,
    get_chat_history, save_chat_message, delete_user_chat_history,
    get_today_usage, increment_usage,
    supabase
)
import os
from datetime import datetime
from functools import wraps
import json
import time
import secrets
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets
import re
import tempfile
from reportlab.lib.pagesizes import letter
from dotenv import load_dotenv
from admin import admin_bp
from discussion import discussion_bp
import queue
from collections import deque
import uuid
from flask_session import Session
import tempfile
from sessions import generate_session_token, save_session_record, invalidate_session, set_exam_active, require_user_role, require_admin_role
from email_utils import send_password_setup_email, send_password_reset_email
import threading
cache_lock = threading.RLock()
import gc
gc.set_threshold(700, 10, 10) 
from flask import Response
import math
import bcrypt
import secrets
from datetime import datetime
import re
from google_drive_service import create_drive_service, load_csv_from_drive, save_csv_to_drive, find_file_by_name, get_public_url, get_drive_service
from login_attempts_cache import check_login_attempts, record_failed_login, clear_login_attempts


def safe_concurrent_csv_access(func):
    """Decorator to prevent concurrent CSV access conflicts - Windows compatible"""
    def wrapper(*args, **kwargs):
        lock_file_path = None
        try:
            # Create a simple lock file approach for Windows
            lock_file_path = os.path.join(os.getcwd(), 'csv_access.lock')
            
            # Try to create lock file (exclusive)
            if not os.path.exists(lock_file_path):
                with open(lock_file_path, 'w') as f:
                    f.write(str(os.getpid()))
                
                # Execute the function
                result = func(*args, **kwargs)
                return result
            else:
                # Lock exists, wait briefly and retry
                time.sleep(0.1)
                return func(*args, **kwargs)
                
        except Exception as e:
            # If any error, just proceed without locking
            return func(*args, **kwargs)
        finally:
            # Clean up lock file
            try:
                if lock_file_path and os.path.exists(lock_file_path):
                    os.remove(lock_file_path)
            except:
                pass
    return wrapper


# CRITICAL: Load environment variables FIRST
load_dotenv()

# CRITICAL: Check if running on Render or local
IS_PRODUCTION = os.environ.get('RENDER') is not None  
if IS_PRODUCTION:
    print("🌐 Running on Render (Production)")
else:
    print("💻 Running locally")


# AI Configuration from .env
AI_MODEL_NAME = os.environ.get('AI_MODEL_NAME', 'llama-3.3-70b-versatile')
AI_DAILY_LIMIT = int(os.environ.get('AI_DAILY_LIMIT_PER_STUDENT', 50))
AI_MAX_MESSAGE_LENGTH = int(os.environ.get('AI_MAX_MESSAGE_LENGTH', 500))
AI_REQUEST_TIMEOUT = int(os.environ.get('AI_REQUEST_TIMEOUT', 30))

print(f"✅ AI Config: Model={AI_MODEL_NAME}, Limit={AI_DAILY_LIMIT}, MaxLen={AI_MAX_MESSAGE_LENGTH}, Timeout={AI_REQUEST_TIMEOUT}")


# Import Google Drive service


app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 7200  # 2 hours


@app.before_request
def before_request_security_check():
    """Minimal security check"""
    
    # Skip static files and auth pages
    skip_paths = [
        '/static/', '/login', '/admin/login', '/admin/admin_login', 
        '/', '/home', '/forgot-password', '/reset-password', 
        '/request-admin-access', '/favicon.ico', '/api/',
        '/dashboard'  # ADD THIS to prevent interference
    ]
    
    if any(request.path.startswith(path) for path in skip_paths):
        return
    
    # Simple portal conflict check ONLY for wrong portal access
    if request.path.startswith('/admin/') and session.get('user_id') and not session.get('admin_id'):
        flash("Please login as Admin to access Admin portal.", "warning")
        return redirect(url_for("login"))


from latex_editor import latex_bp
app.register_blueprint(latex_bp) 

# Use filesystem for Render single-instance free tier. For multi-instance use Redis.
SESSION_TYPE = os.environ.get("SESSION_TYPE", "filesystem")  
# session files dir
SESSION_FILE_DIR = os.environ.get("SESSION_FILE_DIR",
                                  os.path.join(tempfile.gettempdir(), "flask_session"))
os.makedirs(SESSION_FILE_DIR, exist_ok=True)

app.config['SESSION_TYPE'] = SESSION_TYPE
app.config['SESSION_FILE_DIR'] = SESSION_FILE_DIR
app.config['SESSION_PERMANENT'] = False  # keep sessions non-permanent by default
# set lifetime if you want (seconds) — keep > exam duration, e.g., 3 hours (10800)
from datetime import timedelta
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=int(os.environ.get("PERMANENT_SESSION_LIFETIME", 10800)))
# security cookies
app.config['SESSION_COOKIE_HTTPONLY'] = True
# In production set SESSION_COOKIE_SECURE = True if using HTTPS (Render provides HTTPS)
app.config['SESSION_COOKIE_SECURE'] = True if os.environ.get("FORCE_SECURE_COOKIES", "1") == "1" else False

# Initialize server-side session
Session(app)

print(f"✅ Server-side sessions enabled: type={app.config['SESSION_TYPE']}, dir={app.config.get('SESSION_FILE_DIR')}")

@app.after_request
def add_cache_control_headers(response):
    """Disable browser caching for all pages to prevent back button access after logout"""
    # Skip cache headers for static files
    if not request.path.startswith('/static/'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

# Register admin blueprint
app.register_blueprint(admin_bp, url_prefix="/admin")
app.register_blueprint(discussion_bp)

# Configuration
USERS_CSV = 'users.csv'
EXAMS_CSV = 'exams.csv'
QUESTIONS_CSV = 'questions.csv'
RESULTS_CSV = 'results.csv'
RESPONSES_CSV = 'responses.csv'

# CRITICAL: Debug environment variables
print("🔍 Checking environment variables...")
required_env_vars = [
    'SECRET_KEY', 
    'GOOGLE_SERVICE_ACCOUNT_JSON',  
]

for var in required_env_vars:
    value = os.environ.get(var)
    if value:
        if var == 'GOOGLE_SERVICE_ACCOUNT_JSON':
            print(f"✅ {var}: Present (length: {len(value)} chars)")
        elif var == 'SECRET_KEY':
            print(f"✅ {var}: Present")
        else:
            print(f"✅ {var}: {value}")
    else:
        print(f"❌ {var}: MISSING!")



# Keep only file-based Drive IDs (sessions, login_attempts)
LOGIN_ATTEMPTS_FILE_ID = os.environ.get('LOGIN_ATTEMPTS_FILE_ID')
SESSIONS_FILE_ID = os.environ.get('SESSIONS_FILE_ID')

DRIVE_FILE_IDS = {
    'login_attempts': LOGIN_ATTEMPTS_FILE_ID,
    'sessions': SESSIONS_FILE_ID
}



# Google Drive Folder IDs
ROOT_FOLDER_ID = os.environ.get('ROOT_FOLDER_ID')
IMAGES_FOLDER_ID = os.environ.get('IMAGES_FOLDER_ID')
PHYSICS_FOLDER_ID = os.environ.get('PHYSICS_FOLDER_ID')
CHEMISTRY_FOLDER_ID = os.environ.get('CHEMISTRY_FOLDER_ID')
MATH_FOLDER_ID = os.environ.get('MATH_FOLDER_ID')
CIVIL_FOLDER_ID = os.environ.get('CIVIL_FOLDER_ID')

DRIVE_FOLDER_IDS = {
    'root': ROOT_FOLDER_ID,
    'images': IMAGES_FOLDER_ID,
    'physics': PHYSICS_FOLDER_ID,
    'chemistry': CHEMISTRY_FOLDER_ID,
    'math': MATH_FOLDER_ID,
    'civil': CIVIL_FOLDER_ID
}

# Global drive service instance
drive_service = None

# ============================
# Global In-Memory Cache
# ============================
app_cache = {
    'data': {},
    'images': {},
    'timestamps': {},
    'force_refresh': False   # Flag for forcing reload
}





from flask import current_app
# Cache optimization
app_cache['max_size'] = 100  # Limit cache size
app_cache['cleanup_interval'] = 300  # 5 minutes

# Enhanced logging decorator for key functions
def debug_logging(func_name):
    """Decorator to add detailed logging to functions"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            print(f"[DEBUG] {func_name} - START - Args: {len(args)}, Kwargs: {list(kwargs.keys())}")
            
            try:
                result = func(*args, **kwargs)
                end_time = time.time()
                
                # Log result summary
                if hasattr(result, '__len__'):
                    result_info = f"Length: {len(result)}"
                elif isinstance(result, tuple) and len(result) == 2:
                    result_info = f"Tuple: ({result[0]}, '{result[1][:50]}...')"
                else:
                    result_info = f"Type: {type(result).__name__}"
                
                print(f"[DEBUG] {func_name} - SUCCESS - {result_info} - Time: {end_time - start_time:.3f}s")
                return result
                
            except Exception as e:
                end_time = time.time()
                print(f"[DEBUG] {func_name} - ERROR - {str(e)} - Time: {end_time - start_time:.3f}s")
                raise
                
        return wrapper
    return decorator 






def cleanup_stale_attempts():
    try:
        from flask import has_request_context
        if not has_request_context():
            return
            
        attempts_df = safe_csv_load_with_recovery('exam_attempts.csv')
        exams_df = load_csv_with_cache('exams.csv')
        
        if attempts_df.empty or exams_df.empty:
            return
        
        current_time = datetime.now()
        cleaned_count = 0
        
        for idx, attempt in attempts_df.iterrows():
            if str(attempt['status']).lower() != 'in_progress':
                continue
                
            try:
                exam_id = str(attempt['exam_id'])
                exam_info = exams_df[exams_df['id'].astype(str) == exam_id]
                
                if exam_info.empty:
                    continue
                    
                duration_mins = int(exam_info.iloc[0].get('duration_minutes', 60))
                start_time = pd.to_datetime(attempt['start_time'])
                
                if (current_time - start_time).total_seconds() > (duration_mins + 30) * 60:
                    attempts_df.at[idx, 'status'] = 'abandoned'
                    attempts_df.at[idx, 'end_time'] = current_time.strftime('%Y-%m-%d %H:%M:%S')
                    cleaned_count += 1
                    
            except Exception as e:
                print(f"Error processing attempt {attempt.get('id')}: {e}")
                continue
        
        if cleaned_count > 0:
            persist_attempts_df(attempts_df)
            print(f"Cleaned {cleaned_count} stale attempts")
            
    except Exception as e:
        print(f"Error in cleanup_stale_attempts: {e}")



def clear_user_cache():
    """Enhanced cache clearing for Supabase + Drive images"""
    global app_cache
    
    try:
        print("🧹 [CACHE] Clearing user cache...")
        
        # ✅ 1. Clear all app cache data
        cache_keys = list(app_cache.get('data', {}).keys())
        for key in cache_keys:
            app_cache['data'].pop(key, None)
            app_cache['timestamps'].pop(key, None)
        
        print(f"✅ [CACHE] Cleared {len(cache_keys)} data cache entries")
        
        # ✅ 2. Clear image cache
        image_keys = list(app_cache.get('images', {}).keys())
        for key in image_keys:
            app_cache['images'].pop(key, None)
        
        print(f"✅ [CACHE] Cleared {len(image_keys)} image cache entries")
        
        # ✅ 3. Force refresh flag
        app_cache['force_refresh'] = True
        
        # ✅ 4. Clear session cache (if in request context)
        try:
            from flask import session, has_request_context
            if has_request_context():
                # Clear exam data and cached keys
                keys_to_clear = [k for k in list(session.keys()) 
                               if 'exam_data_' in k or 'cached_' in k or 'csv_' in k]
                for k in keys_to_clear:
                    session.pop(k, None)
                print(f"✅ [CACHE] Cleared {len(keys_to_clear)} session keys")
        except Exception as e:
            print(f"⚠️ [CACHE] Session clear skipped: {e}")
        
        # ✅ 5. Clear Drive cache
        try:
            from google_drive_service import clear_cache
            clear_cache()
            print("✅ [CACHE] Drive cache cleared")
        except Exception as e:
            print(f"⚠️ [CACHE] Drive skip: {e}")
        
        print("🎉 [CACHE] Cache clear completed!")
        
    except Exception as e:
        print(f"❌ [CACHE] Error: {e}")
        import traceback
        traceback.print_exc()



# =============================================
# CONCURRENT SAFETY SYSTEM
# =============================================

# Global file locks
file_locks = {}
lock_registry = threading.RLock()



def should_force_refresh():
    """Check if force refresh is needed - checks multiple sources"""
    try:
        # Check 1: App cache flag
        if app_cache.get('force_refresh', False):
            print("🔥 [REFRESH] App cache force_refresh=True")
            return True
        
        # Check 2: Session flag
        if session.get('force_refresh', False):
            print("🔥 [REFRESH] Session force_refresh=True")
            return True
        
        # Check 3: Global timestamp (within last 5 minutes)
        try:
            from flask import current_app
            global_ts = current_app.config.get('FORCE_REFRESH_TIMESTAMP', 0)
            if global_ts and (time.time() - global_ts) < 300:  # 5 minutes
                print("🔥 [REFRESH] Global refresh timestamp active")
                return True
        except:
            pass
        
        return False
        
    except Exception as e:
        print(f"⚠️ [REFRESH] Check error: {e}")
        return False
    


def get_file_lock(file_key):
    """Get or create a lock for a specific file"""
    with lock_registry:
        if file_key not in file_locks:
            file_locks[file_key] = threading.RLock()
        return file_locks[file_key]

def generate_operation_id():
    """Generate unique operation ID"""
    return f"op_{int(time.time())}_{uuid.uuid4().hex[:8]}"

def safe_csv_save_with_retry(df, csv_type, operation_id=None, max_retries=5):
    """Save CSV with retry mechanism - PERFORMANCE OPTIMIZED"""
    if not operation_id:
        operation_id = generate_operation_id()
    
    global drive_service
    file_id = DRIVE_FILE_IDS.get(csv_type)
    
    if not file_id:
        print(f"[{operation_id}] No file ID for {csv_type}")
        return False
    
    # PERFORMANCE FIX: Reuse global service instead of creating new ones
    if drive_service is None:
        print(f"[{operation_id}] No global drive service, initializing once...")
        drive_service = create_drive_service()
        
    if not drive_service:
        print(f"[{operation_id}] Still no drive service for {csv_type}")
        return False
    
    for attempt in range(max_retries):
        try:
            print(f"[{operation_id}] Attempt {attempt + 1} saving {csv_type}")
            # Use the global service instance (no new initialization!)
            success = save_csv_to_drive(drive_service, df, file_id)
            
            if success:
                # Clear cache
                cache_key = f'csv_{csv_type}.csv'
                app_cache['data'].pop(cache_key, None)
                app_cache['timestamps'].pop(cache_key, None)
                print(f"[{operation_id}] ⚡ Successfully saved {csv_type} on attempt {attempt + 1}")
                return True
            else:
                print(f"[{operation_id}] Save failed for {csv_type} on attempt {attempt + 1}")
                
        except Exception as e:
            print(f"[{operation_id}] Exception on attempt {attempt + 1} for {csv_type}: {e}")
        
        # Wait before retry (exponential backoff)
        if attempt < max_retries - 1:
            wait_time = (2 ** attempt) * 0.5  # 0.5, 1, 2, 4, 8 seconds
            print(f"[{operation_id}] Waiting {wait_time}s before retry...")
            time.sleep(wait_time)
    
    print(f"[{operation_id}] FAILED to save {csv_type} after {max_retries} attempts")
    return False

def safe_csv_load(filename, operation_id=None):
    """Safe CSV loading with file locking"""
    if not operation_id:
        operation_id = generate_operation_id()
    
    file_lock = get_file_lock(filename.replace('.csv', ''))
    
    with file_lock:
        print(f"[{operation_id}] Loading {filename} safely")
        return load_csv_from_drive_direct(filename)

def safe_dual_file_save(results_df, responses_df, new_result, response_records):
    """Atomically save both results and responses with retry"""
    operation_id = generate_operation_id()
    
    # Lock both files together
    with get_file_lock('results'):
        with get_file_lock('responses'):
            print(f"[{operation_id}] Starting dual file save with retry mechanism")
            
            # Prepare dataframes
            new_results_df = pd.concat([results_df, pd.DataFrame([new_result])], ignore_index=True)
            new_responses_df = pd.concat([responses_df, pd.DataFrame(response_records)], ignore_index=True)
            
            # Save results with retry
            print(f"[{operation_id}] Saving results...")
            results_success = safe_csv_save_with_retry(new_results_df, 'results', f"{operation_id}_results")
            
            if results_success:
                print(f"[{operation_id}] Results saved! Now saving responses...")
                # Save responses with retry
                responses_success = safe_csv_save_with_retry(new_responses_df, 'responses', f"{operation_id}_responses")
                
                if responses_success:
                    print(f"[{operation_id}] Both files saved successfully!")
                    return True, "Both results and responses saved successfully"
                else:
                    print(f"[{operation_id}] Responses failed even after retries!")
                    return False, "Failed to save responses after multiple attempts"
            else:
                print(f"[{operation_id}] Results failed even after retries!")
                return False, "Failed to save results after multiple attempts"

def safe_user_register(email, full_name):
    """Safe user registration with retry mechanism"""
    operation_id = generate_operation_id()
    
    with get_file_lock('users'):
        print(f"[{operation_id}] Registering user safely: {email}")
        
        # Load current users
        users_df = safe_csv_load('users.csv', operation_id)
        
        # Check if email exists
        if not users_df.empty and email.lower() in users_df['email'].str.lower().values:
            existing_user = users_df[users_df['email'].str.lower() == email.lower()].iloc[0]
            return False, "exists", {
                'username': existing_user['username'],
                'password': existing_user['password'],
                'full_name': existing_user['full_name']
            }
        
        # Create new user
        existing_usernames = users_df['username'].tolist() if not users_df.empty else []
        username = generate_username(full_name, existing_usernames)
        password = generate_password()
        
        next_id = 1
        if not users_df.empty and 'id' in users_df.columns:
            next_id = int(users_df['id'].fillna(0).astype(int).max()) + 1
        
        new_user = {
            'id': next_id,
            'full_name': full_name,
            'username': username,
            'email': email.lower(),
            'password': password,
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'role': 'user'
        }
        
        # Prepare new dataframe
        if users_df.empty:
            new_df = pd.DataFrame([new_user])
        else:
            new_df = pd.concat([users_df, pd.DataFrame([new_user])], ignore_index=True)
        
        # Save with retry mechanism
        if safe_csv_save_with_retry(new_df, 'users', operation_id):
            return True, "success", {
                'username': username,
                'password': password,
                'full_name': full_name
            }
        else:
            return False, "save_failed", None


def ensure_required_files():
    """Ensure all required CSV files exist in Google Drive"""
    global drive_service

    if not drive_service:
        print("❌ No Google Drive service for file verification")
        return

    required_files = {
        'login_attempts.csv': LOGIN_ATTEMPTS_FILE_ID,
        'sessions.csv': SESSIONS_FILE_ID
    }

    for filename, file_id in required_files.items():
        if not file_id or file_id.startswith('YOUR_'):
            print(f"⚠️ {filename}: File ID not configured properly")
            continue
            
        try:
            meta = drive_service.files().get(fileId=file_id, fields="id,name,size").execute()
            print(f"✅ Verified {filename}: {meta.get('name')} ({meta.get('size', '0')} bytes)")
        except Exception as e:
            print(f"❌ Error verifying {filename} (ID: {file_id}): {e}")


# -------------------------
# Helper Functions
# -------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def parse_correct_answers(correct_answer_str, question_type):
    """Parse correct answers based on question type"""
    if pd.isna(correct_answer_str) or str(correct_answer_str).strip() == '':
        if question_type == 'MSQ':
            return []
        else:
            return None

    if question_type == 'MSQ':
        # Multiple correct answers (comma separated)
        return [ans.strip().upper() for ans in str(correct_answer_str).split(',') if ans.strip()]
    elif question_type == 'NUMERIC':
        # Numerical answer
        try:
            return float(str(correct_answer_str).strip())
        except (ValueError, TypeError):
            return None
    else:  # MCQ
        # Single correct answer
        return str(correct_answer_str).strip().upper()


def init_drive_service():
    """Initialize the Google Drive service - OPTIMIZED"""
    global drive_service
    try:
        print("🔧 Initializing Google Drive service...")
        drive_service = create_drive_service()  # This now reuses global instance
        if drive_service:
            print("✅ Google Drive service initialized successfully!")
            ensure_required_files()
            return True
        else:
            print("❌ Failed to initialize Google Drive service")
            return False
    except Exception as e:
        print(f"❌ Failed to initialize Google Drive service: {e}")
        return False





# main.py - replace load_csv_with_cache with this
@debug_logging("load_csv_with_cache")
def load_csv_with_cache(filename, force_reload=False):
    """Load CSV with smart caching - fixed cache validation and DataFrame consistency."""
    global app_cache

    cache_key = f'csv_{filename}'
    cache_duration = 300  # 5 minutes

    # Force reload conditions
    force_conditions = [
        app_cache.get('force_refresh', False),
        session.get('force_refresh', False),
        force_reload,
        filename == 'exam_attempts.csv'  # Keep attempts fresh
    ]
    
    if any(force_conditions):
        print(f"Force refresh triggered for {filename}")
        app_cache['force_refresh'] = False
        session.pop('force_refresh', None)
        force_reload = True

    # Check cache validity
    if not force_reload and cache_key in app_cache['data']:
        cached_time = app_cache['timestamps'].get(cache_key, 0)
        if time.time() - cached_time < cache_duration:
            cached_df = app_cache['data'][cache_key]
            # CRITICAL: Validate cached DataFrame
            if cached_df is not None and hasattr(cached_df, 'empty'):
                print(f"Using cached data for {filename} ({len(cached_df)} rows)")
                return cached_df.copy()
            else:
                print(f"Invalid cached data for {filename}, reloading...")

    # Load fresh data
    print(f"Loading fresh data for {filename}")
    df = load_csv_from_drive_direct(filename)

    # Validate loaded DataFrame
    if df is None:
        print(f"WARNING: load_csv_from_drive_direct returned None for {filename}")
        df = pd.DataFrame()
    elif not hasattr(df, 'empty'):
        print(f"ERROR: Invalid DataFrame type for {filename}: {type(df)}")
        df = pd.DataFrame()

    # Special handling for exam_attempts
    if filename == 'exam_attempts.csv':
        expected_cols = ['id','student_id','exam_id','attempt_number','status','start_time','end_time']
        if df.empty and len(df.columns) == 0:
            df = pd.DataFrame(columns=expected_cols)
            print(f"Created empty exam_attempts DataFrame with headers")
        elif not df.empty:
            for col in expected_cols:
                if col not in df.columns:
                    df[col] = pd.NA

    # Cache the validated result
    try:
        with cache_lock:
            app_cache['data'][cache_key] = df.copy()
            app_cache['timestamps'][cache_key] = time.time()
        print(f"Cached {len(df)} records for {filename}")
    except Exception as e:
        print(f"Error caching {filename}: {e}")

    return df




def load_csv_from_drive_direct(filename):
    """
    PERFORMANCE OPTIMIZED: Use global service instance to avoid multiple initializations
    """
    global drive_service
    
    cache_key = f'csv_{filename}'
    file_id_key = filename.replace('.csv', '')
    file_id = DRIVE_FILE_IDS.get(file_id_key)

    # 1) Use the global service instance instead of creating new ones
    if drive_service is None:
        print(f"load_csv_from_drive_direct: No global drive service available for {filename}")
        drive_service = create_drive_service()  # Try to initialize once
        
    if drive_service is None or not file_id:
        print(f"load_csv_from_drive_direct: Still no drive service or file_id for {filename}")
        # try in-memory cache
        try:
            cached = app_cache.get('data', {}).get(cache_key)
            if cached is not None:
                print(f"📋 Returning cached copy for {filename} (drive unavailable).")
                return cached.copy()
        except Exception:
            pass
        # try local file fallback
        local_path = os.path.join(os.getcwd(), filename)
        if os.path.exists(local_path):
            try:
                df_local = pd.read_csv(local_path, dtype=str)
                df_local.columns = df_local.columns.str.strip()
                print(f"📥 Loaded local fallback for {filename} ({len(df_local)} rows).")
                return df_local
            except Exception as e:
                print(f"❌ Failed to read local fallback {filename}: {e}")
        return pd.DataFrame()

    # 2) Use the existing global service (no new initialization!)
    try:
        df = safe_drive_csv_load(drive_service, file_id, friendly_name=filename, max_retries=3)
        if df is not None and not df.empty:
            try:
                df.columns = df.columns.str.strip()
            except Exception:
                pass
            print(f"⚡ Loaded {len(df)} rows from {filename} using cached service")
            # update in-memory cache
            try:
                app_cache.setdefault('data', {})[cache_key] = df.copy()
                app_cache.setdefault('timestamps', {})[cache_key] = time.time()
            except Exception:
                pass
            return df
            
        if df is not None and hasattr(df, "columns") and len(df.columns) > 0:
            try:
                df.columns = df.columns.str.strip()
            except Exception:
                pass
            print(f"⚡ Loaded header-only data for {filename} using cached service")
            try:
                app_cache.setdefault('data', {})[cache_key] = df.copy()
                app_cache.setdefault('timestamps', {})[cache_key] = time.time()
            except Exception:
                pass
            return df
    except Exception as e:
        err = str(e).lower()
        print(f"Error loading {filename} from Drive: {e}")
        # If SSL/connection transient error, prefer cached copy rather than crash/retry loop
        if 'ssl' in err or 'wrong version number' in err or 'sslv3' in err:
            print(f"⚠️ Transient SSL/Drive error while loading {filename}. Will fallback to cache/local.")

    # 3) Fallback to cache/local (same as before)
    try:
        cached = app_cache.get('data', {}).get(cache_key)
        if cached is not None:
            print(f"📋 Falling back to cached copy for {filename} ({len(cached)} rows).")
            return cached.copy()
    except Exception:
        pass

    try:
        local_path = os.path.join(os.getcwd(), filename)
        if os.path.exists(local_path):
            df_local = pd.read_csv(local_path, dtype=str)
            try:
                df_local.columns = df_local.columns.str.strip()
            except Exception:
                pass
            print(f"📥 Loaded local fallback for {filename} ({len(df_local)} rows).")
            return df_local
    except Exception as e:
        print(f"❌ Local fallback read failed for {filename}: {e}")

    print(f"⚠️ Returning empty DataFrame for {filename} after failures.")
    return pd.DataFrame()



def process_question_image_fixed_ssl_safe(question):
    """Process image path using Supabase subjects - FIXED WITH FORCE REFRESH"""
    global drive_service, app_cache

    image_path = question.get("image_path")
    
    # Enhanced validation
    if not image_path or pd.isna(image_path):
        return False, None
    
    image_path_str = str(image_path).strip()
    
    if not image_path_str or image_path_str.lower() in ["", "nan", "none", "null"]:
        return False, None

    print(f"\n🖼️ [IMAGE] Processing: {image_path_str}")

    # ✅ DON'T check cache here - let get_public_url handle it with force_refresh
    # This ensures force_refresh works properly

    if drive_service is None:
        print(f"❌ [IMAGE] No Drive service available")
        return False, None

    try:
        # Parse path: "Electrostatics/elec-1.jpg" → subject="Electrostatics", file="elec-1.jpg"
        if '/' in image_path_str:
            parts = image_path_str.split('/')
            subject_raw = parts[0].strip()
            filename = parts[-1].strip()
        else:
            subject_raw = None
            filename = image_path_str.strip()

        print(f"📂 [IMAGE] Parsed - Subject: {subject_raw}, File: {filename}")

        # ✅ Get folder ID from Supabase
        folder_id = None
        
        if subject_raw:
            try:
                from supabase_db import supabase
                
                print(f"🔍 [IMAGE] Searching Supabase for subject: {subject_raw}")
                
                response = supabase.table('subjects')\
                    .select('id, subject_name, subject_folder_id')\
                    .execute()
                
                all_subjects = response.data if response.data else []
                print(f"📋 [IMAGE] Found {len(all_subjects)} subjects in Supabase")
                
                # Manual case-insensitive match
                matched_subject = None
                for subj in all_subjects:
                    subj_name = str(subj.get('subject_name', '')).strip()
                    if subj_name.lower() == subject_raw.lower():
                        matched_subject = subj
                        break
                
                if matched_subject:
                    folder_id = str(matched_subject.get('subject_folder_id', '')).strip()
                    print(f"✅ [IMAGE] Found folder for '{matched_subject['subject_name']}': {folder_id}")
                else:
                    print(f"⚠️ [IMAGE] Subject '{subject_raw}' not found in Supabase")
            
            except Exception as e:
                print(f"❌ [IMAGE] Supabase query error: {e}")
                import traceback
                traceback.print_exc()

        # Fallback to IMAGES_FOLDER_ID
        if not folder_id:
            folder_id = os.environ.get("IMAGES_FOLDER_ID", "").strip()
            if folder_id:
                print(f"📂 [IMAGE] Using fallback IMAGES_FOLDER_ID: {folder_id}")
            else:
                print(f"❌ [IMAGE] No folder ID available")
                return False, None

        # Search for file in Drive
        print(f"🔍 [IMAGE] Searching Drive folder {folder_id} for: {filename}")
        
        try:
            image_file_id = find_file_by_name(drive_service, filename, folder_id)
            
            if not image_file_id:
                print(f"❌ [IMAGE] File not found in Drive: {filename}")
                return False, None
            
            print(f"✅ [IMAGE] Found file ID: {image_file_id}")
            
        except Exception as e:
            print(f"❌ [IMAGE] Drive search error: {e}")
            import traceback
            traceback.print_exc()
            return False, None

        # Get public URL with force refresh check
        try:
            print(f"🔗 [IMAGE] Getting public URL for file: {image_file_id}")
            
            # ✅ Check if force refresh is active
            force_refresh = should_force_refresh()
            
            # ✅ CRITICAL: Pass force_refresh to get_public_url
            image_url = get_public_url(drive_service, image_file_id, force_refresh=force_refresh)
            
            if not image_url:
                print(f"❌ [IMAGE] Failed to generate public URL")
                return False, None
            
            print(f"✅ [IMAGE] SUCCESS! URL: {image_url[:80]}...")
            return True, image_url
            
        except Exception as e:
            print(f"❌ [IMAGE] URL generation error: {e}")
            import traceback
            traceback.print_exc()
            return False, None

    except Exception as e:
        print(f"❌ [IMAGE] Critical error: {e}")
        import traceback
        traceback.print_exc()
        return False, None
    


def preload_exam_data_fixed(exam_id):
    """Exam data preloading from Supabase - WITH ENHANCED FORCE REFRESH"""
    start_time = time.time()
    print(f"🔄 Preloading exam data for exam_id: {exam_id}")

    try:
        # ✅ CHECK FORCE REFRESH from multiple sources
        force_refresh = should_force_refresh()
        
        if force_refresh:
            print(f"🔥 [PRELOAD] Force refresh ACTIVE - clearing all caches")
            
            # Clear exam session cache
            cache_key = f'exam_data_{exam_id}'
            session.pop(cache_key, None)
            
            # Clear ALL image caches
            try:
                from google_drive_service import clear_image_cache_immediate
                clear_image_cache_immediate()
                print(f"🧹 [PRELOAD] Cleared ALL image caches")
            except Exception as e:
                print(f"⚠️ [PRELOAD] Cache clear error: {e}")
        else:
            print(f"ℹ️ [PRELOAD] Normal load (no force refresh)")
            
            # Check if already cached
            cache_key = f'exam_data_{exam_id}'
            cached_data = session.get(cache_key)
            if cached_data:
                print(f"💾 [PRELOAD] Using cached data")
                return True, "Using cached data"

        # Load questions from Supabase
        try:
            questions = get_questions_by_exam(exam_id)
            
            if not questions:
                print(f"❌ No questions found for exam {exam_id}")
                return False, f"No questions found for exam ID {exam_id}"
            
            print(f"✅ Loaded {len(questions)} questions")
            
        except Exception as e:
            print(f"❌ Error loading questions: {e}")
            return False, f"Failed to load questions: {str(e)}"

        # Load exam info
        try:
            exam_data = get_exam_by_id(exam_id)
            if not exam_data:
                return False, "Exam metadata not found"
            print(f"✅ Loaded exam metadata")
        except Exception as e:
            print(f"❌ Error loading exam: {e}")
            return False, f"Failed to load exam metadata: {str(e)}"

        # Process questions WITH FORCE REFRESH
        processed_questions = []
        
        for question in questions:
            try:
                if 'id' not in question or not question['id']:
                    continue

                processed_question = {
                    'id': question.get('id'),
                    'question_text': question.get('question_text', ''),
                    'option_a': question.get('option_a', ''),
                    'option_b': question.get('option_b', ''),
                    'option_c': question.get('option_c', ''),
                    'option_d': question.get('option_d', ''),
                    'question_type': question.get('question_type', 'MCQ'),
                    'correct_answer': question.get('correct_answer', ''),
                    'positive_marks': question.get('positive_marks', 1),
                    'negative_marks': question.get('negative_marks', 0),
                    'image_path': question.get('image_path', '')
                }
                
                # ✅ PROCESS IMAGES
                image_path = question.get('image_path')
                if image_path and str(image_path).strip() not in ['', 'nan', 'None']:
                    print(f"🖼️ [PRELOAD] Q{question.get('id')}: {image_path} (force={force_refresh})")
                    
                    # Process image (force_refresh already handled in get_public_url)
                    has_image, image_url = process_question_image_fixed_ssl_safe(question)
                    processed_question['has_image'] = has_image
                    processed_question['image_url'] = image_url
                    
                    if has_image:
                        print(f"✅ [PRELOAD] Image URL: {image_url[:80]}...")
                    else:
                        print(f"❌ [PRELOAD] Failed to get image URL")
                else:
                    processed_question['has_image'] = False
                    processed_question['image_url'] = None                
                
                processed_questions.append(processed_question)

            except Exception as e:
                print(f"❌ Error processing question: {e}")
                continue

        if not processed_questions:
            return False, "No questions could be processed"

        # Store in session
        try:
            cache_key = f'exam_data_{exam_id}'
            session_data = {
                'exam_info': exam_data,
                'questions': processed_questions,
                'total_questions': len(processed_questions),
                'exam_id': exam_id
            }
            
            session[cache_key] = session_data
            session.permanent = True
            
            print(f"✅ Cached exam data in session")

        except Exception as e:
            print(f"❌ Error storing session data: {e}")
            return False, f"Error caching exam data: {str(e)}"

        # ✅ CLEAR FORCE REFRESH FLAGS AFTER SUCCESSFUL PRELOAD
        if force_refresh:
            app_cache['force_refresh'] = False
            session.pop('force_refresh', None)
            
            # Clear global timestamp
            try:
                from flask import current_app
                current_app.config.pop('FORCE_REFRESH_TIMESTAMP', None)
                print("✅ [PRELOAD] Cleared global refresh timestamp")
            except:
                pass
            
            session.modified = True
            print(f"✅ [PRELOAD] Cleared all force_refresh flags")

        load_time = time.time() - start_time
        print(f"⚡ Preloaded exam in {load_time:.2f}s")

        return True, f"Successfully loaded {len(processed_questions)} questions"

    except Exception as e:
        print(f"❌ Critical error: {e}")
        import traceback
        traceback.print_exc()
        return False, f"Critical error: {str(e)}"
    
    
    

def safe_csv_load_with_recovery(filename, max_retries=2):
    """
    Ultra-safe CSV loader with multiple fallback strategies
    """
    operation_id = generate_operation_id()
    
    for attempt in range(max_retries):
        try:
            print(f"[{operation_id}] Safe load attempt {attempt + 1} for {filename}")
            
            # Try main loader first
            try:
                df = safe_csv_load(filename, operation_id)
                if df is not None:
                    return df
            except Exception as e:
                print(f"[{operation_id}] safe_csv_load failed: {e}")
            
            # Try cache loader
            try:
                df = load_csv_with_cache(filename, force_reload=(attempt > 0))
                if df is not None:
                    return df
            except Exception as e:
                print(f"[{operation_id}] load_csv_with_cache failed: {e}")
            
            # Try direct file read
            try:
                local_path = os.path.join(os.getcwd(), filename)
                if os.path.exists(local_path):
                    df = pd.read_csv(local_path, dtype=str)
                    if df is not None:
                        return df
            except Exception as e:
                print(f"[{operation_id}] Local file read failed: {e}")
            
            # Brief delay before retry
            if attempt < max_retries - 1:
                time.sleep(0.5 * (attempt + 1))
                
        except Exception as e:
            print(f"[{operation_id}] Critical error in attempt {attempt + 1}: {e}")
    
    print(f"[{operation_id}] All attempts failed for {filename}, returning empty DataFrame")
    return pd.DataFrame()    


def get_cached_exam_data(exam_id):
    """Get cached exam data with comprehensive validation"""
    cache_key = f'exam_data_{exam_id}'
    cached_data = session.get(cache_key)

    # Respect force-refresh flags: if a cache-clear was requested (publish/upload),
    # invalidate session cache so preload will rebuild fresh URLs.
    try:
        if app_cache.get('force_refresh', False) or session.get('force_refresh', False):
            print(f"🔥 Force refresh requested - invalidating cached exam data for {exam_id}")
            session.pop(cache_key, None)
            # Clear flags to avoid repeated invalidations
            try:
                session.pop('force_refresh', None)
            except Exception:
                pass
            try:
                app_cache['force_refresh'] = False
            except Exception:
                pass
            return None
    except Exception as e:
        print(f"⚠️ get_cached_exam_data force-refresh check failed: {e}")
    if not cached_data:
        print(f"No cached data found for exam {exam_id}")
        return None

    # Validate cached data structure
    required_keys = ['exam_info', 'questions', 'total_questions', 'exam_id']
    missing_keys = [key for key in required_keys if key not in cached_data]
    
    if missing_keys:
        print(f"Invalid cached data structure for exam {exam_id}, missing keys: {missing_keys}")
        session.pop(cache_key, None)
        return None
        
    # Validate exam_id matches
    if cached_data.get('exam_id') != exam_id:
        print(f"Cached exam_id mismatch: expected {exam_id}, got {cached_data.get('exam_id')}")
        session.pop(cache_key, None)
        return None
        
    # Validate questions list
    questions = cached_data.get('questions', [])
    if not isinstance(questions, list) or len(questions) == 0:
        print(f"Invalid or empty questions list for exam {exam_id}")
        session.pop(cache_key, None)
        return None

    print(f"Found valid cached data for exam {exam_id}: {len(questions)} questions")
    return cached_data


def check_answer(given_answer, correct_answer, question_type, tolerance=0.1):
    """Enhanced answer checking with better validation"""
    if question_type == 'MCQ':
        if given_answer is None or correct_answer is None:
            return False
        return str(given_answer).strip().upper() == str(correct_answer).strip().upper()

    elif question_type == 'MSQ':
        if not given_answer or not correct_answer:
            return False

        # Convert to lists if needed
        if isinstance(given_answer, str):
            given_list = [x.strip().upper() for x in given_answer.split(',') if x.strip()]
        else:
            given_list = [str(x).strip().upper() for x in given_answer if x]

        if isinstance(correct_answer, str):
            correct_list = [x.strip().upper() for x in correct_answer.split(',') if x.strip()]
        else:
            correct_list = [str(x).strip().upper() for x in correct_answer if x]

        return set(given_list) == set(correct_list)

    elif question_type == 'NUMERIC':
        if given_answer is None or correct_answer is None:
            return False

        try:
            given_val = float(str(given_answer).strip())
            correct_val = float(str(correct_answer).strip())
            return abs(given_val - correct_val) <= tolerance
        except (ValueError, TypeError):
            return False

    return False


def calculate_question_score(is_correct, question_type, positive_marks, negative_marks):
    def safe_float(val, default=0.0):
        try:
            return float(val)
        except:
            return default

    pos = safe_float(positive_marks, 1.0)
    neg = safe_float(negative_marks, 0.0)

    if is_correct:
        return pos
    else:
        return -neg if neg else 0.0



def save_csv_to_drive_batch(df, csv_type):
    """Batch save CSV to Google Drive - FIXED"""
    global drive_service

    if drive_service is None:
        print("No Google Drive service for batch save")
        return False

    file_id = DRIVE_FILE_IDS.get(csv_type)
    if not file_id:
        print(f"No file ID found for {csv_type}")
        return False

    try:
        success = save_csv_to_drive(drive_service, df, file_id)
        if success:
            # Clear cache for this CSV type
            cache_key = f'csv_{csv_type}.csv'
            app_cache['data'].pop(cache_key, None)
            app_cache['timestamps'].pop(cache_key, None)
            print(f"Successfully saved and cleared cache for {csv_type}")
        return success
    except Exception as e:
        print(f"Error in batch save for {csv_type}: {e}")
        return False


def batch_save_responses(response_records):
    """Batch save responses to Google Drive - FIXED"""
    try:
        # Load existing responses
        responses_df = load_csv_with_cache('responses.csv')

        # Create DataFrame from new records
        new_responses_df = pd.DataFrame(response_records)

        # Combine with existing data
        if not responses_df.empty:
            combined_df = pd.concat([responses_df, new_responses_df], ignore_index=True)
        else:
            combined_df = new_responses_df

        return save_csv_to_drive_batch(combined_df, 'responses')
    except Exception as e:
        print(f"Error batch saving responses: {e}")
        return False

# -----------------------
# Safe Drive CSV wrapper
# -----------------------
import traceback

def safe_drive_csv_load(drive_service, file_id, friendly_name='csv', max_retries=3):
    """
    PERFORMANCE OPTIMIZED: Use existing service instance instead of creating new ones
    """
    try:
        if not drive_service or not file_id:
            print(f"safe_drive_csv_load: no drive service or file_id for {friendly_name}")
            return pd.DataFrame()

        # Call library loader but catch odd return types - using EXISTING service
        df = load_csv_from_drive(drive_service, file_id, max_retries=max_retries)
        if df is None:
            return pd.DataFrame()

        # Some earlier bugs produced string returns in the stack; detect and handle
        if isinstance(df, str):
            print(f"safe_drive_csv_load: Unexpected string returned while loading {friendly_name}")
            return pd.DataFrame()

        # ensure df is DataFrame
        if not hasattr(df, "empty"):
            print(f"safe_drive_csv_load: Unexpected type returned for {friendly_name}: {type(df)}")
            return pd.DataFrame()

        return df.copy()
    except Exception as e:
        print(f"safe_drive_csv_load: drive load failed for {friendly_name}: {e}")
        # fallback to reading local file if present
        try:
            local_path = os.path.join(os.getcwd(), friendly_name)
            if os.path.exists(local_path):
                return pd.read_csv(local_path, dtype=str)
        except Exception as e2:
            print(f"safe_drive_csv_load: local fallback also failed: {e2}")

        return pd.DataFrame()



# -------------------------
# Routes - COMPLETELY FIXED VERSION
# -------------------------


print("🔧 Module loading - checking execution context...")
print(f"📍 __name__ = {__name__}")
print(f"🌐 RENDER environment: {os.environ.get('RENDER', 'Not set')}")

# MINIMAL FIX: Replace only the validation section in force_drive_initialization()

def force_drive_initialization():
    """Force Google Drive initialization for all execution contexts"""
    global drive_service
    
    print("🚀 Force initializing Google Drive service...")
    
    # Debug environment variables first
    json_env = os.environ.get('GOOGLE_SERVICE_ACCOUNT_JSON')
    if json_env:
        print(f"✅ GOOGLE_SERVICE_ACCOUNT_JSON found: {len(json_env)} characters")
        
        # UPDATED VALIDATION: Handle both JSON content and file paths
        if json_env.strip().startswith('{'):
            # It's JSON content - validate it
            try:
                test_json = json.loads(json_env)
                print(f"✅ JSON content is valid. Client email: {test_json.get('client_email', 'Not found')}")
            except json.JSONDecodeError as e:
                print(f"❌ JSON parsing failed: {e}")
                print(f"📄 First 100 chars: {json_env[:100]}")
                return False
        else:
            # It's a file path - validate file exists and is valid JSON
            print(f"📁 File path detected: {json_env}")
            if os.path.exists(json_env):
                try:
                    with open(json_env, 'r', encoding='utf-8') as f:
                        test_json = json.load(f)
                    print(f"✅ JSON file is valid. Client email: {test_json.get('client_email', 'Not found')}")
                except json.JSONDecodeError as e:
                    print(f"❌ JSON file parsing failed: {e}")
                    return False
                except Exception as e:
                    print(f"❌ Error reading JSON file: {e}")
                    return False
            else:
                print(f"❌ JSON file not found: {json_env}")
                return False
    else:
        print("❌ GOOGLE_SERVICE_ACCOUNT_JSON not found in environment")
        print("📋 Available environment variables with 'GOOGLE' or 'SERVICE':")
        for key in os.environ.keys():
            if 'GOOGLE' in key.upper() or 'SERVICE' in key.upper():
                print(f"   - {key}")
        return False
    
    # Initialize the service (UNCHANGED)
    try:
        success = init_drive_service()
        if success:
            print("✅ Force initialization successful!")
            return True
        else:
            print("❌ Force initialization failed")
            return False
    except Exception as e:
        print(f"❌ Exception during force initialization: {e}")
        import traceback
        traceback.print_exc()
        return False



def get_active_attempt(user_id, exam_id):
    """Get active attempt from Supabase"""
    try:
        # Get in_progress attempts
        response = supabase.table('exam_attempts').select('*')\
            .eq('student_id', user_id)\
            .eq('exam_id', exam_id)\
            .eq('status', 'in_progress')\
            .order('id', desc=True)\
            .limit(1)\
            .execute()
        
        if not response.data:
            return None
        
        attempt = response.data[0]
        
        return {
            'id': int(attempt.get('id', 0)),
            'student_id': int(attempt.get('student_id', user_id)),
            'exam_id': int(attempt.get('exam_id', exam_id)),
            'attempt_number': int(attempt.get('attempt_number', 1)),
            'status': str(attempt.get('status', 'in_progress')),
            'start_time': str(attempt.get('start_time', '')),
            'end_time': str(attempt.get('end_time', '')) if attempt.get('end_time') else None
        }
        
    except Exception as e:
        print(f"Error getting active attempt: {e}")
        import traceback
        traceback.print_exc()
        return None



def error_boundary(func):
    """
    Decorator to wrap functions with error boundaries
    """
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            func_name = getattr(func, '__name__', 'unknown')
            print(f"ERROR BOUNDARY caught exception in {func_name}: {e}")
            import traceback
            traceback.print_exc()
            
            # Return appropriate default based on expected return type
            if 'json' in func_name.lower() or 'api' in func_name.lower():
                return jsonify({"success": False, "message": "System error occurred"}), 500
            else:
                flash("A system error occurred. Please try again or contact support.", "error")
                return redirect(url_for('dashboard'))
    
    return wrapper




def persist_results_df(df):
    """Save results dataframe to Drive with retry mechanism"""
    try:
        operation_id = generate_operation_id()
        print(f"[{operation_id}] Persisting results DataFrame with {len(df)} records")
        return safe_csv_save_with_retry(df, 'results', operation_id)
    except Exception as e:
        print(f"Error persisting results DataFrame: {e}")
        return False

def persist_responses_df(df):
    """Save responses dataframe to Drive with retry mechanism"""
    try:
        operation_id = generate_operation_id()
        print(f"[{operation_id}] Persisting responses DataFrame with {len(df)} records")
        return safe_csv_save_with_retry(df, 'responses', operation_id)
    except Exception as e:
        print(f"Error persisting responses DataFrame: {e}")
        return False



def persist_attempts_df(attempts_df):
    """
    CRASH-SAFE attempts persistence with multiple fallback strategies
    """
    operation_id = generate_operation_id()
    
    # Input validation
    if attempts_df is None:
        return False, "attempts_df is None"
    
    try:
        attempts_df = attempts_df.copy()
        
        # Ensure required columns
        required_cols = ['id', 'student_id', 'exam_id', 'attempt_number', 'status', 'start_time', 'end_time']
        for col in required_cols:
            if col not in attempts_df.columns:
                attempts_df[col] = ''
        
        # Strategy 1: Try Google Drive
        file_id = DRIVE_FILE_IDS.get('exam_attempts')
        if drive_service and file_id:
            try:
                success = save_csv_to_drive(drive_service, attempts_df, file_id)
                if success:
                    # Clear caches on success
                    try:
                        app_cache['data'].pop('csv_exam_attempts.csv', None)
                        app_cache['timestamps'].pop('csv_exam_attempts.csv', None)
                    except Exception:
                        pass
                    
                    try:
                        from google_drive_service import clear_csv_cache
                        clear_csv_cache(file_id)
                    except Exception:
                        pass
                    
                    print(f"[{operation_id}] Successfully saved to Google Drive")
                    return True, "saved_to_drive"
                else:
                    print(f"[{operation_id}] Google Drive save returned False")
            except Exception as e:
                print(f"[{operation_id}] Google Drive save failed: {e}")
        
        # Strategy 2: Local file fallback
        try:
            local_path = os.path.join(os.getcwd(), 'exam_attempts.csv')
            attempts_df.to_csv(local_path, index=False)
            
            # Clear app cache
            try:
                app_cache['data'].pop('csv_exam_attempts.csv', None)
                app_cache['timestamps'].pop('csv_exam_attempts.csv', None)
            except Exception:
                pass
            
            print(f"[{operation_id}] Successfully saved to local file")
            return True, f"saved_to_local:{local_path}"
            
        except Exception as e:
            print(f"[{operation_id}] Local file save failed: {e}")
        
        # Strategy 3: Emergency in-memory backup (last resort)
        try:
            backup_key = f'emergency_attempts_backup_{int(time.time())}'
            app_cache['data'][backup_key] = attempts_df.copy()
            app_cache['timestamps'][backup_key] = time.time()
            print(f"[{operation_id}] Created emergency in-memory backup: {backup_key}")
            return True, f"emergency_backup:{backup_key}"
        except Exception as e:
            print(f"[{operation_id}] Emergency backup failed: {e}")
        
        return False, "all_strategies_failed"
        
    except Exception as e:
        print(f"[{operation_id}] Critical error in persist_attempts_df: {e}")
        import traceback
        traceback.print_exc()
        return False, f"critical_error:{str(e)}"





def ensure_drive_csv_exists(csv_type, filename):
    """
    Ensure the DRIVE_FILE_IDS[csv_type] points to a real downloadable file.
    If missing or points to a folder, try to create a new CSV file in Drive and
    update DRIVE_FILE_IDS[csv_type] in memory (won't persist env var).
    Returns (file_id, reason)
    """
    global drive_service, DRIVE_FILE_IDS
    file_id = DRIVE_FILE_IDS.get(csv_type)
    # Quick sanity: if no drive service, bail
    if not drive_service:
        return None, "no_drive_service"

    def is_folder(fid):
        try:
            meta = drive_service.files().get(fileId=fid, fields="id,name,mimeType").execute()
            mime = meta.get("mimeType", "")
            return 'folder' in mime
        except Exception as e:
            return False

    try:
        if file_id:
            # check if it's a folder or otherwise not downloadable
            try:
                meta = drive_service.files().get(fileId=file_id, fields="id,name,mimeType,size").execute()
                mime = meta.get("mimeType","")
                if 'folder' in mime or meta.get("size") in [None, "0"]:
                    # treat as invalid
                    print(f"ensure_drive_csv_exists: configured file id {file_id} for {csv_type} appears to be a folder or empty ({mime}).")
                    file_id = None
            except Exception as e:
                print(f"ensure_drive_csv_exists: error getting metadata for {file_id}: {e}")
                file_id = None

        if not file_id:
            # Create a new empty CSV file in Drive under root or configured folder
            # Use create_file_if_not_exists if available; else try a simple create
            upload_name = filename
            try:
                # create empty local tempfile and upload it via save_csv_to_drive helper pattern
                import pandas as pd
                tmp_df = pd.DataFrame(columns=['id','student_id','exam_id','attempt_number','status','start_time','end_time'])
                # Use a helper in google_drive_service if exists to create files; else use save_csv_to_drive 
                # save_csv_to_drive(service, df, file_id) expects a file id - but we need create new file
                # Try to create using files().create
                from googleapiclient.http import MediaIoBaseUpload
                from io import BytesIO
                csv_bytes = tmp_df.to_csv(index=False).encode('utf-8')
                fh = BytesIO(csv_bytes)
                media = MediaIoBaseUpload(fh, mimetype='text/csv', resumable=False)
                file_metadata = {'name': upload_name}
                created = drive_service.files().create(body=file_metadata, media_body=media, fields='id,name').execute()
                new_id = created.get('id')
                print(f"ensure_drive_csv_exists: created new csv for {csv_type} id={new_id}")
                DRIVE_FILE_IDS[csv_type] = new_id
                return new_id, "created_new"
            except Exception as e:
                print(f"ensure_drive_csv_exists: failed to create drive csv for {csv_type}: {e}")
                return None, f"create_failed:{e}"

        return file_id, "ok"
    except Exception as e:
        print(f"ensure_drive_csv_exists unexpected error: {e}")
        return None, f"error:{e}"




def update_exam_attempt_status(user_id, exam_id, status):
    """
    CRASH-SAFE helper to update exam attempt status
    """
    try:
        attempts_df = safe_csv_load_with_recovery('exam_attempts.csv')
        
        if attempts_df is None or attempts_df.empty:
            print("No attempts data to update")
            return False, "no_data"

        # Find the in_progress attempt
        mask = (
            (attempts_df['student_id'].astype(str) == str(user_id)) &
            (attempts_df['exam_id'].astype(str) == str(exam_id)) &
            (attempts_df['status'].astype(str).str.lower() == 'in_progress')
        )

        if not mask.any():
            print("No in_progress attempt found to update")
            return False, "not_found"

        # Update the most recent one
        idx_list = attempts_df[mask].index.tolist()
        if idx_list:
            idx = idx_list[-1]
            attempts_df.at[idx, 'status'] = status
            attempts_df.at[idx, 'end_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Persist the changes
            ok, info = persist_attempts_df(attempts_df)
            return ok, info
        
        return False, "update_failed"
        
    except Exception as e:
        print(f"Error updating exam attempt status: {e}")
        return False, str(e)
    

# Helper function to validate password strength (optional)
def validate_password_strength(password):
    """
    Validate password strength and return feedback
    Returns: (is_valid, feedback_message)
    """
    if len(password) < 6:
        return False, "Password must be at least 6 characters long"
    
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    
    strength_score = sum([has_lower, has_upper, has_digit, len(password) >= 8])
    
    if strength_score < 2:
        return False, "Password should contain a mix of letters, numbers, and cases"
    
    return True, "Password strength is acceptable"


# Enhanced user registration function that handles password validation
def safe_user_register_enhanced(email, full_name, custom_password=None):
    """Enhanced user registration with optional custom password"""
    operation_id = generate_operation_id()
    
    with get_file_lock('users'):
        print(f"[{operation_id}] Enhanced user registration: {email}")
        
        # Load current users
        users_df = safe_csv_load('users.csv', operation_id)
        
        # Check if email exists
        if not users_df.empty and email.lower() in users_df['email'].str.lower().values:
            existing_user = users_df[users_df['email'].str.lower() == email.lower()].iloc[0]
            return False, "exists", {
                'username': existing_user['username'],
                'password': existing_user['password'],
                'full_name': existing_user['full_name']
            }
        
        # Create new user
        existing_usernames = users_df['username'].tolist() if not users_df.empty else []
        username = generate_username(full_name, existing_usernames)
        password = custom_password if custom_password else generate_password()
        
        # Validate password if custom
        if custom_password:
            is_valid, message = validate_password_strength(custom_password)
            if not is_valid:
                return False, "invalid_password", {'message': message}
        
        next_id = 1
        if not users_df.empty and 'id' in users_df.columns:
            next_id = int(users_df['id'].fillna(0).astype(int).max()) + 1
        
        new_user = {
            'id': next_id,
            'full_name': full_name,
            'username': username,
            'email': email.lower(),
            'password': password,
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'role': 'user'
        }
        
        # Prepare new dataframe
        if users_df.empty:
            new_df = pd.DataFrame([new_user])
        else:
            new_df = pd.concat([users_df, pd.DataFrame([new_user])], ignore_index=True)
        
        # Save with retry mechanism
        if safe_csv_save_with_retry(new_df, 'users', operation_id):
            return True, "success", {
                'username': username,
                'password': password,
                'full_name': full_name
            }
        else:
            return False, "save_failed", None


# ENHANCED CSV save function with immediate verification
def enhanced_csv_save_with_verification(df, csv_type, operation_id):
    """Save CSV and immediately verify the save worked"""
    
    # Save using existing function
    success = safe_csv_save_with_retry(df, csv_type, operation_id)
    
    if success:
        # Clear cache immediately
        clear_user_cache()
        
        # Wait a moment for Drive to process
        time.sleep(1)
        
        # Verify by loading fresh data
        try:
            verification_df = load_csv_from_drive_direct(f'{csv_type}.csv')
            if verification_df is not None and len(verification_df) == len(df):
                print(f"[{operation_id}] Save verification successful for {csv_type}")
                return True
            else:
                print(f"[{operation_id}] Save verification failed for {csv_type}")
                return False
        except Exception as e:
            print(f"[{operation_id}] Save verification error: {e}")
            return success  # Return original result if verification fails
    
    return success   



# Add this function to your main.py file, around line 200 after other helper functions

def initialize_requests_raised_csv():
    """Initialize requests_raised.csv if it doesn't exist"""
    try:
        # Check if file exists and has data
        existing_df = load_csv_with_cache('requests_raised.csv')
        if existing_df is not None and not existing_df.empty:
            print("✅ requests_raised.csv already exists with data")
            return True
            
        # Create new file with proper headers
        headers_df = pd.DataFrame(columns=[
            'request_id', 'username', 'email', 'current_access',
            'requested_access', 'request_date', 'request_status', 
            'reason', 'processed_by', 'processed_date'
        ])
        
        # Save to Drive
        success = safe_csv_save_with_retry(headers_df, 'requests_raised')
        
        if success:
            print("✅ Created requests_raised.csv with headers")
            return True
        else:
            print("❌ Failed to create requests_raised.csv")
            return False
            
    except Exception as e:
        print(f"Error initializing requests_raised.csv: {e}")
        return False



# Update the force_drive_initialization function to include the new CSV
def force_drive_initialization():
    """Force Google Drive initialization for all execution contexts"""
    global drive_service
    
    print("🚀 Force initializing Google Drive service...")
    
    # Debug environment variables first
    json_env = os.environ.get('GOOGLE_SERVICE_ACCOUNT_JSON')
    if json_env:
        print(f"✅ GOOGLE_SERVICE_ACCOUNT_JSON found: {len(json_env)} characters")
        
        # Test JSON parsing
        try:
            test_json = json.loads(json_env)
            print(f"✅ JSON is valid. Client email: {test_json.get('client_email', 'Not found')}")
        except json.JSONDecodeError as e:
            print(f"❌ JSON parsing failed: {e}")
            print(f"📄 First 100 chars: {json_env[:100]}")
            return False
    else:
        print("❌ GOOGLE_SERVICE_ACCOUNT_JSON not found in environment")
        return False
    
    # Initialize the service
    try:
        success = init_drive_service()
        if success:
            print("✅ Force initialization successful!")
            
            # Initialize the new CSV file
            initialize_requests_raised_csv()
            
            return True
        else:
            print("❌ Force initialization failed")
            return False
    except Exception as e:
        print(f"❌ Exception during force initialization: {e}")
        import traceback
        traceback.print_exc()
        return False



# =============================================
# SECURITY FUNCTIONS - ADD TO main.py
# =============================================

def hash_password(password: str) -> str:
    """Hash a password using bcrypt with cost factor 12."""
    if not password:
        raise ValueError("Password cannot be empty")
    
    password_bytes = password.encode('utf-8')
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt(rounds=12))
    return hashed.decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its bcrypt hash."""
    if not password or not hashed:
        return False
    
    try:
        password_bytes = password.encode('utf-8')
        hashed_bytes = hashed.encode('utf-8')
        return bcrypt.checkpw(password_bytes, hashed_bytes)
    except Exception as e:
        print(f"Password verification error: {e}")
        return False

def is_password_hashed(password: str) -> bool:
    """Check if a password is already bcrypt hashed."""
    if not password:
        return False
    return (password.startswith(('$2a$', '$2b$', '$2y$')) and len(password) == 60)

def validate_password_strength(password: str) -> tuple:
    """Validate password strength according to security requirements."""
    if len(password) < 10:
        return False, "Password must be at least 10 characters long"
    
    if len(password) > 128:
        return False, "Password must be less than 128 characters"
    
    # Check for required character types
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    # Check for common weak passwords
    weak_passwords = ['password123', '123456789', 'qwerty123', 'admin123', 'welcome123']
    if password.lower() in weak_passwords:
        return False, "This password is too common. Please choose a stronger password"
    
    return True, "Password is strong"

def create_password_token(email: str, token_type: str) -> str:
    """Create a secure token for password operations - SUPABASE VERSION"""
    from datetime import timedelta
    from supabase_db import create_password_token_db
    
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.now() + timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
    
    if create_password_token_db(email, token_type, token, expires_at):
        print(f"✅ Created {token_type} token for {email}")
        return token
    else:
        raise Exception("Failed to save token to database")

def validate_and_use_token(token: str) -> tuple:
    """Validate a token and mark it as used - SUPABASE VERSION"""
    from supabase_db import get_password_token_db, mark_token_used_db
    
    try:
        # Get token from Supabase
        token_data = get_password_token_db(token)
        
        if not token_data:
            return False, "Invalid token", {}
        
        # Check if already used
        if token_data.get('used'):
            return False, "Token has already been used", {}
        
        # Check expiration
        expires_at = datetime.fromisoformat(token_data['expires_at'])
        if datetime.now() > expires_at:
            return False, "Token has expired", {}
        
        # Mark as used
        if mark_token_used_db(token):
            print(f"✅ Token validated and marked as used")
            return True, "Token valid", token_data
        else:
            return False, "Failed to mark token as used", {}
        
    except Exception as e:
        print(f"❌ Error validating token: {e}")
        import traceback
        traceback.print_exc()
        return False, "Token validation error", {}





def get_client_ip():
    """Get client IP address for rate limiting."""
    return request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)

def migrate_plaintext_passwords():
    """One-time migration to convert existing plaintext passwords to bcrypt."""
    try:
        users_df = load_csv_with_cache('users.csv')
        if users_df is None or users_df.empty:
            return False, "No users found"
        
        migrated_count = 0
        
        for index, user in users_df.iterrows():
            current_password = str(user.get('password', ''))
            
            # Skip if already hashed or empty
            if not current_password or is_password_hashed(current_password):
                continue
            
            try:
                hashed_password = hash_password(current_password)
                users_df.at[index, 'password'] = hashed_password
                users_df.at[index, 'updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                migrated_count += 1
                print(f"Migrated password for user: {user.get('username', 'Unknown')}")
            except Exception as e:
                print(f"Error migrating password for user {user.get('username', 'Unknown')}: {e}")
        
        if migrated_count > 0:
            if safe_csv_save_with_retry(users_df, 'users'):
                return True, f"Successfully migrated {migrated_count} passwords to bcrypt hashes"
            else:
                return False, "Failed to save migrated passwords"
        else:
            return True, "No passwords needed migration"
            
    except Exception as e:
        print(f"Error during password migration: {e}")
        return False, f"Migration failed: {str(e)}"



def update_exam_attempt_by_id(attempt_id, status):
    try:
        attempts_df = safe_csv_load_with_recovery('exam_attempts.csv')
        if attempts_df is None or attempts_df.empty:
            return False, "no_data"
        attempts_df = attempts_df.copy()
        attempts_df['id'] = attempts_df['id'].astype(str)
        mask = (attempts_df['id'] == str(attempt_id))
        if not mask.any():
            return False, "not_found"
        idx = attempts_df[mask].index[-1]
        attempts_df.at[idx, 'status'] = status
        attempts_df.at[idx, 'end_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ok, info = persist_attempts_df(attempts_df)
        return ok, info
    except Exception as e:
        print(f"Error in update_exam_attempt_by_id: {e}")
        return False, str(e)


def calculate_student_analytics(results_list, exams_list, user_id):
    """Calculate analytics data for student - Supabase version"""
    try:
        analytics = {}
        
        if not results_list:
            return {}
        
        # Convert to DataFrame for easier analysis
        results_df = pd.DataFrame(results_list)
        results_df['completed_at'] = pd.to_datetime(results_df['completed_at'], errors='coerce')
        results_df['percentage'] = results_df['percentage'].astype(float)
        results_df = results_df.sort_values('completed_at')
        
        # ✅ Convert exams_list to DataFrame
        exams_df = pd.DataFrame(exams_list) if exams_list else pd.DataFrame()
        
        analytics['total_exams'] = len(results_df)
        analytics['average_score'] = round(results_df['percentage'].mean(), 2)
        analytics['highest_score'] = round(results_df['percentage'].max(), 2)
        analytics['lowest_score'] = round(results_df['percentage'].min(), 2)
        
        grade_counts = results_df['grade'].value_counts().to_dict()
        total_grades = sum(grade_counts.values())
        analytics['grade_distribution'] = {
            grade: {
                'count': count,
                'percentage': round((count / total_grades) * 100, 1)
            }
            for grade, count in grade_counts.items()
        }
        
        analytics['score_trend'] = []
        for _, row in results_df.iterrows():
            exam_name = 'Unknown Exam'
            if not exams_df.empty:
                exam_info = exams_df[exams_df['id'].astype(str) == str(row['exam_id'])]
                if not exam_info.empty:
                    exam_name = exam_info.iloc[0]['name']
            
            analytics['score_trend'].append({
                'exam_name': exam_name,
                'score': float(row['percentage']),
                'grade': row['grade'],
                'date': row['completed_at'].strftime('%Y-%m-%d') if pd.notna(row['completed_at']) else 'Unknown'
            })
        
        recent_results = results_df.tail(5)
        analytics['recent_performance'] = []
        for _, row in recent_results.iterrows():
            exam_name = 'Unknown Exam'
            if not exams_df.empty:
                exam_info = exams_df[exams_df['id'].astype(str) == str(row['exam_id'])]
                if not exam_info.empty:
                    exam_name = exam_info.iloc[0]['name']
            
            analytics['recent_performance'].append({
                'exam_name': exam_name,
                'score': f"{row['score']}/{row['max_score']}",
                'percentage': float(row['percentage']),
                'grade': row['grade'],
                'date': row['completed_at'].strftime('%Y-%m-%d %H:%M') if pd.notna(row['completed_at']) else 'Unknown'
            })
        
        if len(results_df) >= 2:
            recent_avg = results_df.tail(3)['percentage'].mean()
            earlier_avg = results_df.head(len(results_df)-3)['percentage'].mean() if len(results_df) > 3 else results_df.iloc[0]['percentage']
            analytics['improvement_trend'] = round(recent_avg - earlier_avg, 2)
        else:
            analytics['improvement_trend'] = 0
            
        return analytics
        
    except Exception as e:
        print(f"Error calculating analytics: {e}")
        return {}


# =============================================
# AI ASSISTANT HELPER FUNCTIONS
# =============================================

def get_user_chat_limits(user_id):
    """Get user's chat usage and limits from Supabase"""
    try:
        today = datetime.now().strftime('%Y-%m-%d')
        usage_data = get_today_usage(user_id)
        
        questions_used = 0
        if usage_data:
            questions_used = int(usage_data.get('questions_used', 0))
        
        return {
            'daily_limit': AI_DAILY_LIMIT,
            'questions_used': questions_used,
            'reset_date': today
        }
        
    except Exception as e:
        print(f"Error getting chat limits: {e}")
        return {
            'daily_limit': AI_DAILY_LIMIT,
            'questions_used': 0,
            'reset_date': datetime.now().strftime('%Y-%m-%d')
        }


def get_user_chat_history(user_id, limit=50):
    """Get user's chat history from Supabase"""
    try:
        user_chats = get_chat_history(user_id, limit=limit)
        
        if not user_chats:
            return []
        
        user_chats.sort(key=lambda x: x.get('timestamp', ''))
        
        history = []
        for chat in user_chats:
            history.append({
                'text': chat.get('message', ''),
                'isUser': bool(chat.get('is_user', False)),
                'timestamp': chat.get('timestamp', '')
            })
        
        return history
        
    except Exception as e:
        print(f"Error getting chat history: {e}")
        return []


def get_groq_response(user_message, chat_history=None):
    """Get AI response from Groq API"""
    try:
        import requests
        
        groq_api_key = os.environ.get('GROQ_API_KEY')
        if not groq_api_key:
            return "AI service is currently unavailable. Please contact administrator to configure GROQ_API_KEY."
        
        messages = [
            {
                "role": "system",
                "content": """You are an expert tutor specializing in physics, chemistry, mathematics, biology, computer science, and engineering.

═══════════════════════════════════════════════════
LATEX NOTATION GUIDE (Auto-detect subject)
═══════════════════════════════════════════════════

MATHEMATICS:
- Inline: $x^2$, $\\frac{a}{b}$, $\\sqrt{x}$, $\\int_a^b f(x)dx$
- Display: $$E = mc^2$$
- Greek: $\\alpha$, $\\beta$, $\\gamma$, $\\theta$, $\\mu$, $\\Delta$, $\\Sigma$, $\\pi$
- Vectors: $\\vec{F}$, $\\vec{v}$, $\\hat{i}$, $\\hat{j}$, $\\hat{k}$

CHEMISTRY:
- Formulas: \\ce{H2O}, \\ce{C6H5CHO}, \\ce{CH3COOH}
- Reactions: \\ce{A + B -> C}, \\ce{2H2 + O2 -> 2H2O}
- Equilibrium: \\ce{A <=> B}
- Ions: \\ce{Na+}, \\ce{SO4^2-}

PHYSICS:
- Units: $5\\text{ m/s}$, $10\\text{ kg}$, $9.8\\text{ m/s}^2$
- Vectors: $\\vec{F} = m\\vec{a}$

═══════════════════════════════════════════════════
RESPONSE FORMAT
═══════════════════════════════════════════════════

━━━ FINAL ANSWER ━━━
[Direct answer]

━━━ GIVEN INFORMATION ━━━
[Known values]

━━━ SOLUTION STEPS ━━━
[Step-by-step with equations]

━━━ EXPLANATION ━━━
[Brief concept summary]

RULES:
1. NEVER use ** for bold
2. Always write complete LaTeX
3. Show ALL steps
4. Explain WHY, not just HOW"""
            }
        ]
        
        if chat_history:
            for msg in chat_history[-4:]:
                messages.append({
                    "role": "user" if msg.get('isUser') else "assistant",
                    "content": msg.get('text', '')
                })
        
        messages.append({
            "role": "user",
            "content": user_message
        })
        
        response = requests.post(
            'https://api.groq.com/openai/v1/chat/completions',
            headers={
                'Authorization': f'Bearer {groq_api_key}',
                'Content-Type': 'application/json'
            },
            json={
                'model': AI_MODEL_NAME,
                'messages': messages,
                'temperature': 0.2,
                'max_tokens': 4000,
                'top_p': 0.95,
                'frequency_penalty': 0.5,
                'presence_penalty': 0.3
            },
            timeout=AI_REQUEST_TIMEOUT
        )
        
        if response.status_code == 200:
            data = response.json()
            return data['choices'][0]['message']['content']
        else:
            print(f"Groq API error: {response.status_code} - {response.text}")
            return "I'm having trouble connecting to my AI service. Please try again."
            
    except requests.exceptions.Timeout:
        return "Request timed out. Please try asking your question again."
    except Exception as e:
        print(f"Error getting Groq response: {e}")
        return "I encountered an error. Please try again."



def ensure_ai_csv_structure():
    """Ensure AI Supabase tables have correct structure - NO-OP for Supabase"""
    try:
        # Supabase tables are already created with proper schemas
        # This function is kept for compatibility but does nothing
        print("✅ AI Supabase tables structure check (using existing schema)")
        return True
        
    except Exception as e:
        print(f"❌ Error in AI structure check: {e}")
        return False


def safe_int(value, default=0):
    """Safely convert to int"""
    if value is None or str(value).strip() in ['', 'None', 'null']:
        return default
    try:
        return int(float(value))  # Handle "5.0" strings
    except (ValueError, TypeError):
        return default

# -------------------------
# Routes - Add explicit initialization before first route
# -------------------------


# Footer page routes
@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')

@app.route('/terms-of-service') 
def terms_of_service():
    return render_template('terms_of_service.html')

@app.route('/support')
def support():
    return render_template('support.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/about')
def about():
    return render_template('about.html')



# 6. ADD DEBUG ROUTE HERE (BEFORE MAIN ROUTES):
@app.route('/debug/env-check')
def debug_env_check():
    """Debug endpoint to check environment variables"""
    
    env_status = {}
    
    # Check all required environment variables
    required_vars = [
        'SECRET_KEY',
        'GOOGLE_SERVICE_ACCOUNT_JSON',
        'USERS_FILE_ID',
        'EXAMS_FILE_ID', 
        'QUESTIONS_FILE_ID',
        'RESULTS_FILE_ID',
        'RESPONSES_FILE_ID',
        'ROOT_FOLDER_ID',
        'IMAGES_FOLDER_ID'
    ]
    
    for var in required_vars:
        value = os.environ.get(var)
        if value:
            if var == 'GOOGLE_SERVICE_ACCOUNT_JSON':
                # Check JSON validity without exposing content
                try:
                    json_data = json.loads(value)
                    env_status[var] = {
                        'status': 'Present and Valid JSON',
                        'length': len(value),
                        'has_private_key': 'private_key' in json_data,
                        'has_client_email': 'client_email' in json_data,
                        'client_email': json_data.get('client_email', 'Not found')[:50] + '...'
                    }
                except json.JSONDecodeError as e:
                    env_status[var] = {
                        'status': 'Present but INVALID JSON',
                        'error': str(e),
                        'length': len(value),
                        'first_100_chars': value[:100]
                    }
            elif 'SECRET' in var:
                env_status[var] = {'status': 'Present', 'length': len(value)}
            else:
                env_status[var] = {'status': 'Present', 'value': value}
        else:
            env_status[var] = {'status': 'MISSING'}
    
    # Check if we're on Render
    render_detected = os.environ.get('RENDER') is not None
    
    # Try to initialize Google Drive service
    drive_init_status = "Not attempted"
    try:
        test_service = create_drive_service()
        if test_service:
            drive_init_status = "SUCCESS"
            try:
                about = test_service.about().get(fields="user").execute()
                drive_init_status += f" - Connected as: {about.get('user', {}).get('emailAddress', 'Unknown')}"
            except:
                drive_init_status += " - Service created but test failed"
        else:
            drive_init_status = "FAILED - Service is None"
    except Exception as e:
        drive_init_status = f"FAILED - Exception: {str(e)}"
    
    return jsonify({
        'platform': 'Render' if render_detected else 'Local/Other',
        'environment_variables': env_status,
        'google_drive_init': drive_init_status,
        'python_version': os.sys.version,
        'working_directory': os.getcwd(),
        'file_ids_configured': DRIVE_FILE_IDS,
        'folder_ids_configured': DRIVE_FOLDER_IDS,
        'drive_service_status': 'Initialized' if drive_service else 'Not Initialized'
    })



@app.route('/clear-stuck-attempt/<int:exam_id>', methods=['POST'])
@require_user_role  
def clear_stuck_attempt(exam_id):
    """Clear stuck exam attempt to allow fresh start"""
    try:
        user_id = session.get('user_id')
        
        # Clear session data
        session.pop('latest_attempt_id', None)
        session.pop('exam_start_time', None) 
        session.pop('exam_answers', None)
        session.pop('marked_for_review', None)
        session.pop(f'exam_data_{exam_id}', None)
        session.modified = True
        
        # Mark any in-progress attempts as abandoned
        attempts_df = safe_csv_load_with_recovery('exam_attempts.csv')
        if attempts_df is not None and not attempts_df.empty:
            mask = (
                (attempts_df['student_id'].astype(str) == str(user_id)) &
                (attempts_df['exam_id'].astype(str) == str(exam_id)) &
                (attempts_df['status'].astype(str) == 'in_progress')
            )
            if mask.any():
                attempts_df.loc[mask, 'status'] = 'abandoned'
                attempts_df.loc[mask, 'end_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                persist_attempts_df(attempts_df)
                print(f"Marked stuck attempts as abandoned for user {user_id}, exam {exam_id}")
        
        return jsonify({
            "success": True,
            "message": "Stuck attempt cleared successfully"
        })
        
    except Exception as e:
        print(f"Error clearing stuck attempt: {e}")
        return jsonify({
            "success": False, 
            "message": str(e)
        }), 500


@app.route('/')
def home():
    # Clear any conflicting session data when going to home
    admin_id = session.get('admin_id')
    user_id = session.get('user_id')
    
    # If both admin and user sessions exist, it's invalid state
    if admin_id and user_id and str(admin_id) == str(user_id):
        # Keep admin session, clear user session parts
        session.pop('admin_id', None)
        session.pop('admin_name', None)
    
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        ip_address = request.remote_addr
        
        if not username or not password:
            flash('Username and password required!', 'error')
            return redirect(url_for('login'))
        
        # ✅ Check login attempts
        allowed, error_msg, remaining = check_login_attempts(username, ip_address)
        if not allowed:
            flash(error_msg, 'error')
            return redirect(url_for('login'))
        
        # ✅ Get user from Supabase
        user = get_user_by_username(username)
        
        if not user:
            record_failed_login(username, ip_address)
            flash('Invalid username or password!', 'error')
            return redirect(url_for('login'))
        
        # ✅ VERIFY PASSWORD - Handle both hashed and plain
        stored_password = str(user.get('password', '')).strip()
        
        if not stored_password:
            flash('Account setup incomplete. Please check your email for setup link.', 'warning')
            return redirect(url_for('login'))
        
        # Check if password is hashed (bcrypt format)
        password_valid = False
        
        if is_password_hashed(stored_password):
            # ✅ BCRYPT VERIFICATION
            password_valid = verify_password(password, stored_password)
            print(f"🔐 [LOGIN] Bcrypt verification for {username}: {password_valid}")
        else:
            # ✅ PLAIN TEXT (backward compatibility - will be removed after migration)
            password_valid = (stored_password == password)
            print(f"⚠️ [LOGIN] Plain text verification for {username}: {password_valid}")
        
        if not password_valid:
            record_failed_login(username, ip_address)
            
            # ✅ Get updated remaining attempts AFTER recording
            allowed, error_msg, remaining = check_login_attempts(username, ip_address)
            
            if not allowed:
                # Account locked
                flash(error_msg, 'error')
            elif remaining > 0:
                flash(f'Invalid username or password! {remaining} attempts remaining.', 'error')
            else:
                flash('Invalid username or password!', 'error')
            
            return redirect(url_for('login'))
        
        # ✅ Clear failed attempts
        clear_login_attempts(username, ip_address)
        
        # ✅ Check if admin trying to login as user
        role = str(user.get('role', '')).lower()
        if 'admin' in role:
            flash('Please use admin login portal.', 'error')
            return redirect(url_for('admin.admin_login'))
        
        # ✅ Invalidate old sessions
        invalidate_session(int(user['id']))
        
        # ✅ Create new session
        import secrets
        token = secrets.token_urlsafe(32)
        
        session_data = {
            'token': token,
            'user_id': int(user['id']),
            'device_info': request.headers.get('User-Agent', 'unknown'),
            'is_exam_active': False,
            'admin_session': False,
            'active': True
        }
        
        create_session(session_data)
        
        # ✅ Set Flask session
        session.permanent = True
        session['user_id'] = int(user['id'])
        session['token'] = token
        session['username'] = user.get('username')
        session['full_name'] = user.get('full_name', user.get('username'))
        session['role'] = user.get('role', 'user')
        session.modified = True
        
        flash(f'Welcome {user.get("full_name")}!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')






def generate_username(full_name, existing_usernames):
    """Generate username from full name using firstname.lastname format"""
    # Clean the full name and create FirstName.LastName format
    clean_name = ' '.join(full_name.strip().split()).lower()
    
    # Replace spaces with dots for username format
    base_username = clean_name.replace(' ', '.')
    
    # If not taken, return as-is
    if base_username not in existing_usernames:
        return base_username
    
    # If taken, add numbers
    counter = 1
    username = f"{base_username}{counter}"
    
    while username in existing_usernames:
        counter += 1
        username = f"{base_username}{counter}"
    
    return username


def generate_password(length=8):
    """Generate a random password"""
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))


def is_valid_email(email):
    """Simple email validation"""
    return '@' in email and '.' in email.split('@')[1] and len(email) > 5


def verify_email_exists(email):
    """Simple email verification"""
    if not is_valid_email(email):
        return False, "Invalid email format"

    # Just check if it has @ and domain
    domain = email.split('@')[1].lower()
    if len(domain) > 3 and '.' in domain:
        return True, "Valid email format"
    else:
        return False, "Invalid email domain"



# ALSO UPDATE THE CREATE ACCOUNT ROUTE IN main.py WITH THIS PATTERN:

@app.route('/create_account', methods=['GET', 'POST'])
def create_account():
    """Enhanced user registration with Supabase and secure password setup via email."""
    if request.method == 'POST':
        try:
            # Get form data
            email = request.form['email'].strip().lower()
            first_name = request.form.get('first_name', '').strip()
            last_name = request.form.get('last_name', '').strip()

            # Validate inputs
            if not email:
                flash('Please enter your email address.', 'error')
                return redirect(url_for('create_account'))

            if not first_name:
                flash('Please enter your first name.', 'error')
                return redirect(url_for('create_account'))

            if not last_name:
                flash('Please enter your last name.', 'error')
                return redirect(url_for('create_account'))

            # Create full name from first and last name
            full_name = f"{first_name} {last_name}".strip()

            is_valid, error_message = verify_email_exists(email)
            if not is_valid:
                flash(f'Invalid email: {error_message}', 'error')
                return redirect(url_for('create_account'))

            # ✅ USE SUPABASE FUNCTIONS
            try:
                from supabase_db import get_all_users, create_user
                
                # Check if email exists
                all_users = get_all_users()
                
                for u in all_users:
                    if str(u.get('email', '')).lower() == email.lower():
                        flash('If this email is not already registered, a setup link has been sent. Please check your inbox and spam folder.', 'success')
                        return redirect(url_for('registration_success_generic'))

                # Get existing usernames
                existing_usernames = set(str(u.get('username', '')).lower() for u in all_users)

                # Generate unique username using firstname.lastname format
                username = generate_username(full_name, existing_usernames)

                # ✅ CREATE USER IN SUPABASE
                new_user_data = {
                    'username': username,
                    'email': email,
                    'full_name': full_name,
                    'password': '',  # Empty until setup
                    'role': 'user'
                }

                created_user = create_user(new_user_data)
                
                if created_user:
                    try:
                        # ✅ GENERATE SETUP TOKEN
                        setup_token = create_password_token(email, 'setup')

                        # ✅ SEND SETUP EMAIL WITH USERNAME
                        from email_utils import send_password_setup_email
                        email_sent, email_message = send_password_setup_email(email, full_name, username, setup_token)

                        if email_sent:
                            print(f"✅ Setup email sent to {email} with username: {username}")
                            flash('Account created successfully! Please check your email for setup instructions.', 'success')
                        else:
                            print(f"❌ Failed to send setup email to {email}: {email_message}")
                            flash('Account created, but email sending failed. Please contact admin.', 'warning')

                        return redirect(url_for('registration_success_generic'))

                    except Exception as e:
                        print(f"❌ Error sending setup email: {e}")
                        import traceback
                        traceback.print_exc()
                        flash('Account created, but email sending failed. Please contact admin.', 'warning')
                        return redirect(url_for('registration_success_generic'))
                else:
                    flash('Registration failed. Please try again.', 'error')
                    return redirect(url_for('create_account'))

            except Exception as e:
                print(f"❌ Registration error: {e}")
                import traceback
                traceback.print_exc()
                flash('System error occurred. Please try again.', 'error')
                return redirect(url_for('create_account'))

        except Exception as e:
            print(f"❌ Registration error: {e}")
            import traceback
            traceback.print_exc()
            flash('System error occurred. Please try again.', 'error')
            return redirect(url_for('create_account'))

    # GET request - render form with any preserved values
    return render_template('create_account.html',
                          email=request.args.get('email', ''),
                          first_name=request.args.get('first_name', ''),
                          last_name=request.args.get('last_name', ''))

    
    
    

@app.route('/registration-success')
def registration_success_generic():
    """Generic registration success page."""
    return render_template('registration_success.html')



# =============================================
# NEW PASSWORD ROUTES - ADD TO main.py
# =============================================

@app.route('/setup-password/<token>', methods=['GET', 'POST'])
def setup_password(token):
    """Password setup route for new users - SUPABASE VERSION"""
    if request.method == 'POST':
        try:
            new_password = request.form.get('new_password', '').strip()
            confirm_password = request.form.get('confirm_password', '').strip()

            # Validate passwords
            if not new_password or not confirm_password:
                flash('Both password fields are required.', 'error')
                return render_template('password_setup_form.html', token=token)

            if new_password != confirm_password:
                flash('Passwords do not match.', 'error')
                return render_template('password_setup_form.html', token=token)

            # Validate password strength
            is_strong, strength_message = validate_password_strength(new_password)
            if not is_strong:
                flash(strength_message, 'error')
                return render_template('password_setup_form.html', token=token)

            # Validate and use token
            token_valid, message, token_data = validate_and_use_token(token)
            if not token_valid:
                flash(message, 'error')
                return redirect(url_for('login'))

            if token_data.get('type') != 'setup':
                flash('Invalid setup token.', 'error')
                return redirect(url_for('login'))

            # ✅ UPDATE: Get user from Supabase
            from supabase_db import get_user_by_email, update_user
            
            email = token_data['email']
            user = get_user_by_email(email)
            
            if not user:
                flash('User not found.', 'error')
                return redirect(url_for('login'))

            # Hash new password and update
            hashed_password = hash_password(new_password)
            
            # ✅ UPDATE: Save to Supabase
            if update_user(user['id'], {
                'password': hashed_password,
                'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }):
                flash(f'Password set successfully! You can now login with username: {user["username"]}', 'success')
                return redirect(url_for('login'))
            else:
                flash('Failed to set password. Please try again.', 'error')
                return render_template('password_setup_form.html', token=token)

        except Exception as e:
            print(f"Error setting up password: {e}")
            import traceback
            traceback.print_exc()
            flash('An error occurred. Please try again.', 'error')
            return render_template('password_setup_form.html', token=token)

    # GET request - show form
    # Validate token first (but don't mark as used)
    try:
        from supabase_db import get_password_token_db
        
        token_data = get_password_token_db(token)
        
        if not token_data:
            flash('Invalid setup link.', 'error')
            return redirect(url_for('login'))
        
        if token_data.get('used'):
            flash('This setup link has already been used.', 'error')
            return redirect(url_for('login'))
        
        # ✅ FIX: Handle datetime parsing
        try:
            expires_at = datetime.fromisoformat(token_data['expires_at'])
        except:
            expires_at = datetime.strptime(token_data['expires_at'], '%Y-%m-%d %H:%M:%S')
        
        if datetime.now() > expires_at:
            flash('This setup link has expired.', 'error')
            return redirect(url_for('login'))
        
        if token_data.get('type') != 'setup':
            flash('Invalid setup link type.', 'error')
            return redirect(url_for('login'))
    
    except Exception as e:
        print(f"Error validating setup token: {e}")
        import traceback
        traceback.print_exc()
        flash('Error validating setup link.', 'error')
        return redirect(url_for('login'))
    
    return render_template('password_setup_form.html', token=token, email=token_data.get('email', ''))



@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password_with_token(token):
    """Password reset route for existing users - SUPABASE VERSION"""
    if request.method == 'POST':
        try:
            new_password = request.form.get('new_password', '').strip()
            confirm_password = request.form.get('confirm_password', '').strip()

            # Validate passwords
            if not new_password or not confirm_password:
                flash('Both password fields are required.', 'error')
                return render_template('password_reset_form.html', token=token)

            if new_password != confirm_password:
                flash('Passwords do not match.', 'error')
                return render_template('password_reset_form.html', token=token)

            # Validate password strength
            is_valid, error_message = validate_password_strength(new_password)
            if not is_valid:
                flash(error_message, 'error')
                return render_template('password_reset_form.html', token=token)

            # Validate and use token
            token_valid, message, token_data = validate_and_use_token(token)
            if not token_valid:
                flash(message, 'error')
                return redirect(url_for('login'))

            # Verify token type
            if token_data.get('type') != 'reset':
                flash('Invalid reset token.', 'error')
                return redirect(url_for('login'))

            # ✅ UPDATE: Get user from Supabase
            from supabase_db import get_user_by_email, update_user
            
            email = token_data['email']
            user = get_user_by_email(email)
            
            if not user:
                flash('User not found.', 'error')
                return redirect(url_for('login'))

            # Hash new password and update
            hashed_password = hash_password(new_password)
            
            # ✅ UPDATE: Save to Supabase
            if update_user(user['id'], {
                'password': hashed_password,
                'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }):
                flash('Password updated successfully! You can now login with your new password.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Failed to update password. Please try again.', 'error')
                return render_template('password_reset_form.html', token=token)

        except Exception as e:
            print(f"Error resetting password: {e}")
            import traceback
            traceback.print_exc()
            flash('An error occurred. Please try again.', 'error')
            return render_template('password_reset_form.html', token=token)

    # GET request - show form
    # Validate token first (but don't mark as used)
    try:
        from supabase_db import get_password_token_db
        
        token_data = get_password_token_db(token)
        
        if not token_data:
            flash('Invalid reset link.', 'error')
            return redirect(url_for('login'))
        
        if token_data.get('used'):
            flash('This reset link has already been used.', 'error')
            return redirect(url_for('login'))
        
        # ✅ FIX: Handle datetime parsing
        try:
            expires_at = datetime.fromisoformat(token_data['expires_at'])
        except:
            expires_at = datetime.strptime(token_data['expires_at'], '%Y-%m-%d %H:%M:%S')
        
        if datetime.now() > expires_at:
            flash('This reset link has expired.', 'error')
            return redirect(url_for('login'))
        
        if token_data.get('type') != 'reset':
            flash('Invalid reset link type.', 'error')
            return redirect(url_for('login'))
    
    except Exception as e:
        print(f"Error validating reset token: {e}")
        import traceback
        traceback.print_exc()
        flash('Error validating reset link.', 'error')
        return redirect(url_for('login'))
    
    return render_template('password_reset_form.html', token=token, email=token_data.get('email', ''))



@app.route('/registration-success')
def registration_success():
    """Show registration success page"""
    # Get data from session
    success_type = session.get('reg_success_type')
    email = session.get('reg_email')
    username = session.get('reg_username')
    password = session.get('reg_password')
    full_name = session.get('reg_fullname')
    
    # Verify we have the necessary data
    if not all([success_type, email, username, password]):
        flash('Session expired or invalid access.', 'error')
        return redirect(url_for('create_account'))
    
    # Create credentials dictionary
    credentials = {
        'username': username,
        'password': password,
        'full_name': full_name
    }
    
    # Clear session data after use
    session.pop('reg_success_type', None)
    session.pop('reg_email', None)
    session.pop('reg_username', None)
    session.pop('reg_password', None)
    session.pop('reg_fullname', None)
    
    # Render the template with the success data
    return render_template('create_account.html', 
                           success=success_type, 
                           email=email, 
                           credentials=credentials)




@app.route('/dashboard')
@require_user_role
def dashboard():
    """User dashboard route - Supabase version"""
    try:
        user_id = session.get('user_id')
        print(f"[DASHBOARD] User ID: {user_id}")
        
        # ✅ Get exams from Supabase
        all_exams = get_all_exams()
        
        # ✅ Get user results from Supabase
        user_results = get_results_by_user(user_id)
        
        upcoming_exams = []
        ongoing_exams = []
        completed_exams = []
        
        if not all_exams:
            print("[DASHBOARD] No exams found in database")
            return render_template('dashboard.html',
                                 upcoming_exams=[],
                                 ongoing_exams=[],
                                 completed_exams=[])
        
        # ✅ Categorize exams by status (matching CSV logic)
        for exam in all_exams:
            exam_status = str(exam.get('status', 'draft')).lower().strip()
            
            # Convert to dict for template compatibility
            exam_dict = {
                'id': int(exam.get('id', 0)),
                'name': exam.get('name', 'Unnamed Exam'),
                'date': exam.get('date', ''),
                'start_time': exam.get('start_time', ''),
                'duration': exam.get('duration', 60),
                'total_questions': exam.get('total_questions', 0),
                'status': exam_status,
                'instructions': exam.get('instructions', ''),
                'positive_marks': exam.get('positive_marks', '1'),
                'negative_marks': exam.get('negative_marks', '0')
            }
            
            # Categorize based on status column
            if exam_status == 'upcoming':
                upcoming_exams.append(exam_dict)
            elif exam_status == 'ongoing':
                ongoing_exams.append(exam_dict)
            elif exam_status == 'completed':
                completed_exams.append(exam_dict)
        
        # ✅ Process results for completed exams (matching CSV logic)
        if user_results:
            # Build result map: exam_id -> result data
            result_map = {}
            for result in user_results:
                exam_id = int(result.get('exam_id', 0))
                if exam_id not in result_map:
                    result_map[exam_id] = result
                else:
                    # Keep latest result (by completed_at)
                    if result.get('completed_at', '') > result_map[exam_id].get('completed_at', ''):
                        result_map[exam_id] = result
            
            # Add result info to completed exams
            for exam in completed_exams:
                exam_id = int(exam.get('id', 0))
                if exam_id in result_map:
                    result = result_map[exam_id]
                    score = result.get('score', 0)
                    max_score = result.get('max_score', 0)
                    grade = result.get('grade', 'N/A')
                    
                    # Match CSV format: "score/max_score (grade)"
                    if score is not None and max_score is not None:
                        exam['result'] = f"{score}/{max_score} ({grade})"
                    else:
                        exam['result'] = 'Recorded'
                else:
                    exam['result'] = 'Pending'
        else:
            # No results - mark all as pending
            for exam in completed_exams:
                exam['result'] = 'Pending'
        
        print(f"[DASHBOARD] Categorized: {len(upcoming_exams)} upcoming, {len(ongoing_exams)} ongoing, {len(completed_exams)} completed")
        
        return render_template('dashboard.html',
                             upcoming_exams=upcoming_exams,
                             ongoing_exams=ongoing_exams,
                             completed_exams=completed_exams)
        
    except Exception as e:
        print(f"[DASHBOARD] Error: {e}")
        import traceback
        traceback.print_exc()
        flash("Error loading dashboard. Please try again.", "error")
        return redirect(url_for('login'))




# =============================================
# AI ASSISTANT ROUTES
# =============================================

@app.route('/ai-assistant')
@require_user_role
def ai_assistant():
    """AI Study Assistant page"""
    try:
        user_id = session.get('user_id')
        username = session.get('username', 'Student')
        full_name = session.get('full_name', username)
        
        return render_template('ai_assistant.html',
                             username=username,
                             full_name=full_name)
        
    except Exception as e:
        print(f"[AI_ASSISTANT] Error: {e}")
        flash("Error loading AI Assistant. Please try again.", "error")
        return redirect(url_for('dashboard'))


@app.route('/api/study-chat', methods=['POST'])
@require_user_role
def api_study_chat():
    """API endpoint for AI chat interactions"""
    try:
        data = request.get_json()
        if not data or not data.get('message'):
            return jsonify({
                'success': False,
                'message': 'No message provided'
            }), 400

        user_message = data['message'].strip()
        
        if len(user_message) > AI_MAX_MESSAGE_LENGTH:
            return jsonify({
                'success': False,
                'message': f'Message too long. Maximum {AI_MAX_MESSAGE_LENGTH} characters allowed.'
            }), 400

        if len(user_message) < 3:
            return jsonify({
                'success': False,
                'message': 'Message too short. Minimum 3 characters required.'
            }), 400
            
        user_id = session.get('user_id')
        
        limits = get_user_chat_limits(user_id)
        if limits['questions_used'] >= limits['daily_limit']:
            return jsonify({
                'success': False,
                'message': 'Daily limit reached. Resets at midnight.',
                'limit_reached': True
            }), 429

        chat_history = get_user_chat_history(user_id, limit=6)
        
        print(f"💬 [CHAT] User {user_id} asking: {user_message[:50]}...")
        
        user_msg_data = {
            'user_id': user_id,
            'message': user_message,
            'is_user': True,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        if not save_chat_message(user_msg_data):
            print(f"⚠️ [CHAT] Failed to save user message")

        ai_response = get_groq_response(user_message, chat_history)
        
        print(f"🤖 [CHAT] AI responding: {ai_response[:50]}...")

        ai_msg_data = {
            'user_id': user_id,
            'message': ai_response,
            'is_user': False,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        if not save_chat_message(ai_msg_data):
            print(f"⚠️ [CHAT] Failed to save AI message")
        
        if not increment_usage(user_id):
            print(f"⚠️ [CHAT] Failed to increment usage")
        
        updated_limits = get_user_chat_limits(user_id)
        
        print(f"✅ [CHAT] Chat completed. Usage: {updated_limits['questions_used']}/{updated_limits['daily_limit']}")
        
        return jsonify({
            'success': True,
            'response': ai_response,
            'questions_remaining': updated_limits['daily_limit'] - updated_limits['questions_used']
        })
        
    except Exception as e:
        print(f"[API_STUDY_CHAT] Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'message': 'Error processing your request'
        }), 500


@app.route('/api/get-chat-history')
@require_user_role
def api_get_chat_history():
    """Get user's chat history"""
    try:
        user_id = session.get('user_id')
        history = get_user_chat_history(user_id, limit=50)
        
        return jsonify({
            'success': True,
            'history': history
        })
        
    except Exception as e:
        print(f"[API_GET_CHAT_HISTORY] Error: {e}")
        return jsonify({
            'success': False,
            'message': 'Error fetching history'
        }), 500


@app.route('/api/clear-chat-history', methods=['POST'])
@require_user_role
def api_clear_chat_history():
    """Clear user's chat history from Supabase"""
    try:
        user_id = session.get('user_id')
        
        if delete_user_chat_history(user_id):
            return jsonify({
                'success': True,
                'message': 'Chat history cleared successfully'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to clear history'
            }), 500
        
    except Exception as e:
        print(f"[API_CLEAR_CHAT_HISTORY] Error: {e}")
        return jsonify({
            'success': False,
            'message': 'Error clearing history'
        }), 500


@app.route('/api/get-user-limits')
@require_user_role
def api_get_user_limits():
    """Get user's daily chat limits"""
    try:
        user_id = session.get('user_id')
        limits = get_user_chat_limits(user_id)
        
        return jsonify({
            'success': True,
            'dailyLimit': limits['daily_limit'],
            'questionsUsed': limits['questions_used'],
            'questionsRemaining': limits['daily_limit'] - limits['questions_used']
        })
        
    except Exception as e:
        print(f"[API_GET_USER_LIMITS] Error: {e}")
        return jsonify({
            'success': False,
            'message': 'Error fetching limits'
        }), 500



@app.route('/analytics')
@require_user_role
def student_analytics():
    """Student performance analytics dashboard"""
    try:
        user_id = session.get('user_id')
        username = session.get('username', 'Student')
        
        # ✅ Get data from Supabase
        results = get_results_by_user(user_id)
        exams = get_all_exams()
        
        if not results:
            flash("No results data available yet.", "info")
            return render_template('student_analytics.html', 
                                 analytics_data={}, 
                                 has_data=False)
        
        analytics_data = calculate_student_analytics(results, exams, user_id)
        
        return render_template('student_analytics.html', 
                             analytics_data=analytics_data, 
                             has_data=True,
                             username=username)
        
    except Exception as e:
        print(f"[ANALYTICS] Error: {e}")
        flash("Error loading analytics. Please try again.", "error")
        return redirect(url_for('dashboard'))

@app.route("/results_history")
@require_user_role
def results_history():
    if "user_id" not in session:
        flash("Please login to view your results history.", "danger")
        return redirect(url_for("login"))

    try:
        user_id = session["user_id"]
        
        # ✅ Get results from Supabase
        results = get_results_by_user(user_id)
        
        if not results:
            flash("No results found for your account yet.", "info")
            return render_template("results_history.html", results=[])

        # ✅ Get exams from Supabase
        exams = get_all_exams()

        if not exams:
            flash("Exam metadata missing. Contact admin.", "warning")
            return render_template("results_history.html", results=[])

        # ✅ Create exam dictionary for fast lookup
        exam_dict = {int(e.get('id')): e for e in exams}

        # ✅ Build result list
        result_list = []
        for result in results:
            exam_id = int(result.get("exam_id", 0))
            exam_data = exam_dict.get(exam_id, {})
            exam_name = exam_data.get("name") or f"Exam {exam_id}"
            
            result_list.append({
                "id": int(result.get("id", 0)),
                "exam_id": exam_id,
                "exam_name": exam_name,
                "subject": exam_name,
                "completed_at": result.get("completed_at", ""),
                "score": result.get("score", 0),
                "max_score": result.get("max_score", 0),
                "percentage": round(float(result.get("percentage", 0)), 2),
                "grade": result.get("grade", "N/A"),
                "time_taken_minutes": result.get("time_taken_minutes", 0),
                "correct_answers": int(result.get("correct_answers", 0)),
                "incorrect_answers": int(result.get("incorrect_answers", 0)),
                "unanswered_questions": int(result.get("unanswered_questions", 0)),
            })

        # Sort by completed_at
        result_list.sort(key=lambda r: r.get("completed_at", ""), reverse=True)

        return render_template("results_history.html", results=result_list)

    except Exception as e:
        print("Error in results_history:", str(e))
        import traceback
        traceback.print_exc()
        flash("Could not load results history.", "danger")
        return render_template("results_history.html", results=[])




@app.route('/exam-instructions/<int:exam_id>')
@require_user_role
def exam_instructions(exam_id):
    try:
        # Load exam from Supabase
        try:
            exam_data = get_exam_by_id(exam_id)
        except Exception as e:
            print(f"Error loading exam: {e}")
            flash('Error loading exam.', 'error')
            return redirect(url_for('dashboard'))

        if not exam_data:
            flash('Exam not found!', 'error')
            return redirect(url_for('dashboard'))

        # Set defaults
        if 'positive_marks' not in exam_data or exam_data.get('positive_marks') is None:
            exam_data['positive_marks'] = 1
        if 'negative_marks' not in exam_data or exam_data.get('negative_marks') is None:
            exam_data['negative_marks'] = 0

        user_id = session.get('user_id')
        
        # Check for active attempt
        active_attempt = get_active_attempt(user_id, exam_id)
        
        print(f"📋 Instructions: user={user_id}, exam={exam_id}, active_attempt={active_attempt}")

        # Count completed attempts
        try:
            completed_count = get_completed_attempts_count(user_id, exam_id)
            print(f"📊 Completed attempts: {completed_count}")
            
        except Exception as e:
            print(f"Error counting attempts: {e}")
            completed_count = 0

        try:
            max_attempts = safe_int(exam_data.get('max_attempts'), 0)
        except Exception:
            max_attempts = 0

        attempts_left = None
        attempts_exhausted = False
        can_start = True

        if max_attempts > 0:
            attempts_left = max_attempts - completed_count
            if attempts_left <= 0:
                attempts_exhausted = True
                attempts_left = 0
                can_start = False
        else:
            attempts_left = None
            can_start = True

        # Override if active attempt exists
        if active_attempt:
            can_start = False
            print(f"✅ Active attempt found - showing RESUME button")
        else:
            print(f"✅ No active attempt - showing START button (can_start={can_start})")

        return render_template(
            'exam_instructions.html',
            exam=exam_data,
            active_attempt=active_attempt,
            attempts_left=attempts_left,
            max_attempts=max_attempts,
            attempts_exhausted=attempts_exhausted,
            can_start=can_start
        )
        
    except Exception as e:
        print(f"Error in exam_instructions: {e}")
        import traceback
        traceback.print_exc()
        flash('Error loading exam instructions.', 'error')
        return redirect(url_for('dashboard'))



@app.route('/start-exam/<int:exam_id>', methods=['POST'])
@require_user_role
def start_exam(exam_id):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"success": False, "message": "Authentication error."})

    try:
        # Load exam from Supabase
        exam_data = get_exam_by_id(exam_id)
        if not exam_data:
            return jsonify({"success": False, "message": "Exam not found."})

        # Check for active attempt
        active_attempt = get_active_attempt(user_id, exam_id)
        
        if active_attempt:
            session['latest_attempt_id'] = int(active_attempt.get('id', 0))
            session['exam_start_time'] = active_attempt.get('start_time')
            session['exam_answers'] = {}
            session['marked_for_review'] = []
            session.permanent = True
            
            return jsonify({
                "success": True, 
                "redirect_url": url_for('exam_page', exam_id=exam_id),
                "resumed": True,
                "message": "Resuming existing attempt",
                "attempt_id": active_attempt.get('id')
            })

        # Check max attempts
        completed_count = get_completed_attempts_count(user_id, exam_id)
        max_attempts = safe_int(exam_data.get('max_attempts'), 0)
        
        if max_attempts > 0 and completed_count >= max_attempts:
            return jsonify({
                "success": False,
                "message": f"Maximum attempts ({max_attempts}) reached."
            })

        # Calculate next IDs
        all_attempts_response = supabase.table('exam_attempts').select('id, attempt_number')\
            .eq('student_id', user_id)\
            .eq('exam_id', exam_id)\
            .execute()
        
        existing_attempts = all_attempts_response.data if all_attempts_response.data else []
        
        next_attempt_number = max([int(a.get('attempt_number', 0)) for a in existing_attempts], default=0) + 1
        
        # Create new attempt
        start_iso = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        new_attempt = {
            'student_id': int(user_id),
            'exam_id': int(exam_id),
            'attempt_number': int(next_attempt_number),
            'status': 'in_progress',
            'start_time': start_iso,
            'end_time': None
        }

        created_attempt = create_exam_attempt(new_attempt)
        
        if not created_attempt:
            return jsonify({
                "success": False, 
                "message": "Failed to create exam attempt"
            }), 500

        new_attempt_id = int(created_attempt['id'])

        # Set session data
        session['latest_attempt_id'] = new_attempt_id
        session['exam_start_time'] = start_iso
        session['exam_answers'] = {}
        session['marked_for_review'] = []
        session['timer_reset_flag'] = True
        session['attempt_number'] = int(next_attempt_number)
        session.permanent = True
        session.modified = True

        # Mark exam as active
        try:
            set_exam_active(user_id, session.get('token'), exam_id=exam_id, result_id=new_attempt_id, is_active=True)
        except Exception as e:
            print(f"Error setting exam active: {e}")

        print(f"✅ Created attempt {new_attempt_id} (#{next_attempt_number}) for user {user_id}, exam {exam_id}")
        
        return jsonify({
            "success": True, 
            "redirect_url": url_for('exam_page', exam_id=exam_id), 
            "resumed": False,
            "message": "Exam started successfully",
            "attempt_id": new_attempt_id,
            "attempt_number": next_attempt_number,
            "fresh_start": True
        })

    except Exception as e:
        print(f"Critical error in start_exam: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False, 
            "message": "System error occurred"
        }), 500


@app.route('/api/exam-attempts-status/<int:exam_id>')
@require_user_role
def api_exam_attempts_status(exam_id):
    """Get exam attempts status from Supabase"""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'not_authenticated'}), 401

    try:
        # Get exam data
        exam_data = get_exam_by_id(exam_id)
        if not exam_data:
            return jsonify({'error': 'exam_not_found'}), 404

        max_attempts = safe_int(exam_data.get('max_attempts'), 0)

        # Get latest attempt
        latest_attempt = get_latest_attempt(user_id, exam_id)
        
        # Get completed attempts count
        completed_count = get_completed_attempts_count(user_id, exam_id)

        # Check if latest attempt is in_progress
        has_active = False
        if latest_attempt and latest_attempt.get('status') == 'in_progress':
            has_active = True

        if has_active:
            return jsonify({
                'has_active_attempt': True,
                'attempt_id': int(latest_attempt.get('id')),
                'attempt_number': int(latest_attempt.get('attempt_number', 0)),
                'start_time': latest_attempt.get('start_time'),
                'completed_count': completed_count,
                'max_attempts': max_attempts,
                'attempts_remaining': max_attempts - completed_count if max_attempts > 0 else -1
            })

        # No active attempt
        return jsonify({
            'has_active_attempt': False,
            'completed_count': completed_count,
            'max_attempts': max_attempts,
            'attempts_remaining': max_attempts - completed_count if max_attempts > 0 else -1,
            'can_start_new': (max_attempts == 0 or completed_count < max_attempts)
        })

    except Exception as e:
        print(f"Error in api_exam_attempts_status: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'server_error'}), 500



@app.route('/exam/mark-abandoned/<int:exam_id>', methods=['POST'])
@require_user_role
def mark_exam_abandoned(exam_id):

    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"success": False, "message": "Not authenticated"}), 401

    lock = get_file_lock('exam_attempts')
    with lock:
        try:
            file_id = DRIVE_FILE_IDS.get('exam_attempts')
            attempts_df = pd.DataFrame()
            if file_id and drive_service:
                try:
                    attempts_df = safe_drive_csv_load(drive_service, file_id, friendly_name='exam_attempts.csv')
                except Exception:
                    attempts_df = pd.DataFrame()
            if attempts_df is None or attempts_df.empty:
                local_path = os.path.join(os.getcwd(), "exam_attempts.csv")
                if os.path.exists(local_path):
                    attempts_df = pd.read_csv(local_path, dtype=str)
                else:
                    return jsonify({"success": False, "message": "No attempts file"}), 400

            # Find the latest in_progress row
            mask = (
                (attempts_df['student_id'].astype(str) == str(user_id)) &
                (attempts_df['exam_id'].astype(str) == str(exam_id)) &
                (attempts_df['status'].astype(str) == 'in_progress')
            )
            if not mask.any():
                return jsonify({"success": False, "message": "No in-progress attempt found"}), 404

            idxs = attempts_df[mask].index.tolist()
            latest_idx = idxs[-1]
            attempts_df.at[latest_idx, 'status'] = 'abandoned'
            attempts_df.at[latest_idx, 'end_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            ok, info = persist_attempts_df(attempts_df)
            if ok:
                return jsonify({"success": True, "message": "Marked as abandoned"})
            else:
                return jsonify({"success": False, "message": f"Save failed: {info}"}), 500
        except Exception as e:
            print(f"mark_exam_abandoned error: {e}")
            return jsonify({"success": False, "message": "Server error"}), 500




@app.route('/preload-exam/<int:exam_id>')
@require_user_role
def preload_exam_route(exam_id):
    """API endpoint to preload exam data - WITH FORCE REFRESH SUPPORT"""
    try:
        # ✅ CHECK FORCE REFRESH FLAG FIRST!
        force_refresh = app_cache.get('force_refresh', False) or session.get('force_refresh', False)
        
        if force_refresh:
            print(f"🔥 [PRELOAD_ROUTE] Force refresh detected - skipping cache check")
            # Clear session cache
            cache_key = f'exam_data_{exam_id}'
            session.pop(cache_key, None)
            session.modified = True
        else:
            # ✅ ONLY CHECK CACHE IF NOT FORCE REFRESH
            cached_data = get_cached_exam_data(exam_id)
            if cached_data and cached_data.get('exam_id') == exam_id:
                print(f"💾 [PRELOAD_ROUTE] Using cached data for exam {exam_id}")
                return jsonify({
                    'success': True,
                    'message': f"Using cached data with {cached_data['total_questions']} questions",
                    'exam_id': exam_id,
                    'cached': True,
                    'question_count': cached_data['total_questions']
                })

        # ✅ CALL PRELOAD FUNCTION (will handle force refresh internally)
        print(f"🔄 [PRELOAD_ROUTE] Calling preload_exam_data_fixed for exam {exam_id}")
        success, message = preload_exam_data_fixed(exam_id)
        
        status_code = 200 if success else 400
        response_data = {
            'success': success,
            'message': message,
            'exam_id': exam_id,
            'cached': False,
            'force_refresh': force_refresh
        }
        
        # Add diagnostic info for failures
        if not success:
            try:
                questions_df = load_csv_with_cache('questions.csv')
                if questions_df is not None and not questions_df.empty:
                    available_exams = sorted(questions_df['exam_id'].unique().tolist()) if 'exam_id' in questions_df.columns else []
                    response_data['available_exam_ids'] = available_exams
                    response_data['total_questions_in_db'] = len(questions_df)
                else:
                    response_data['diagnostic'] = 'Questions database is empty or inaccessible'
            except Exception as e:
                response_data['diagnostic'] = f'Error checking questions database: {str(e)}'
        
        return jsonify(response_data), status_code
        
    except Exception as e:
        print(f"❌ Error in preload route: {e}")
        import traceback
        traceback.print_exc()
        
        return jsonify({
            'success': False,
            'message': f"Server error during preload: {str(e)}",
            'exam_id': exam_id,
            'error_type': 'server_error'
        }), 500


from markupsafe import Markup, escape
from datetime import datetime
from flask import render_template, request, session, flash, redirect, url_for

def sanitize_for_display(s):
    """
    Escape HTML-special characters but preserve safe <br>.
    Convert newlines to actual <br> tags so they render correctly.
    """
    from markupsafe import Markup, escape
    if s is None:
        return Markup("")
    s = str(s)

    # Normalize CRLF -> LF
    s = s.replace("\r\n", "\n").replace("\r", "\n")

    # Escape HTML to prevent injection
    escaped = escape(s)

    # ✅ Fix: Convert newlines to real <br> tags
    with_breaks = escaped.replace("\n", Markup("<br>"))

    return Markup(with_breaks)



@app.route('/api/sync-exam-answers/<int:exam_id>', methods=['POST'])
@require_user_role
def sync_exam_answers(exam_id):
    """Sync exam answers from SPA to server session"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400

        answers = data.get('answers', {})
        marked_for_review = data.get('markedForReview', [])

        # Update server session
        session['exam_answers'] = answers
        session['marked_for_review'] = marked_for_review
        session.modified = True

        return jsonify({
            'success': True,
            'message': 'Answers synced successfully',
            'answers_count': len(answers),
            'review_count': len(marked_for_review)
        })

    except Exception as e:
        print(f"Error syncing answers: {e}")
        return jsonify({
            'success': False,
            'message': 'Error syncing answers'
        }), 500


@app.route('/exam/<int:exam_id>')
@require_user_role
def exam_page(exam_id):
    user_id = session.get('user_id')
    
    try:
        print(f"📄 Loading exam page for exam_id: {exam_id}, user_id: {user_id}")

        # Check for active attempt
        active_attempt = get_active_attempt(user_id, exam_id)
        
        if active_attempt:
            print(f"✅ Found active attempt: {active_attempt}")
            session['latest_attempt_id'] = int(active_attempt.get('id', 0))
            session['exam_start_time'] = active_attempt.get('start_time')
            if 'exam_answers' not in session:
                session['exam_answers'] = {}
            if 'marked_for_review' not in session:
                session['marked_for_review'] = []
            session.modified = True
        else:
            print(f"⚠️ No active attempt - redirect to instructions")
            flash("Please start the exam first.", "warning")
            return redirect(url_for('exam_instructions', exam_id=exam_id))

        # Get cached exam data
        cached_data = get_cached_exam_data(exam_id)
        if not cached_data:
            print(f"❌ No cached data, preloading...")
            success, message = preload_exam_data_fixed(exam_id)
            if not success:
                flash(f"Unable to load exam: {message}", "error")
                return redirect(url_for('dashboard'))
            cached_data = get_cached_exam_data(exam_id)

        if not cached_data:
            flash("Unable to load exam data.", "error")
            return redirect(url_for('dashboard'))

        exam_data = cached_data.get('exam_info', {})
        questions = cached_data.get('questions', [])

        if not questions:
            flash("No questions found.", "error") 
            return redirect(url_for('dashboard'))

        # Initialize session data
        if 'exam_answers' not in session:
            session['exam_answers'] = {}
        if 'marked_for_review' not in session:
            session['marked_for_review'] = []

        # Calculate remaining time
        duration_mins = int(float(exam_data.get('duration', 60)))
        duration_secs = duration_mins * 60
        remaining_seconds = duration_secs
        is_fresh_start = False
        
        session_start_time = session.get('exam_start_time')
        
        if active_attempt and session_start_time:
            try:
                # ✅ Handle both ISO and datetime formats
                try:
                    # Try ISO format first (Supabase)
                    start_dt = datetime.fromisoformat(session_start_time.replace('Z', '+00:00'))
                except:
                    # Fallback to standard format
                    start_dt = datetime.strptime(session_start_time, '%Y-%m-%d %H:%M:%S')
                
                now_dt = datetime.now()
                
                elapsed_secs = (now_dt - start_dt).total_seconds()
                remaining_seconds = max(0, duration_secs - int(elapsed_secs))
                
                print(f"⏱️ Timer: duration={duration_mins}m, elapsed={int(elapsed_secs)}s, remaining={remaining_seconds}s")
                
                if remaining_seconds <= 0:
                    print("❌ Time expired - auto submitting")
                    update_exam_attempt(int(active_attempt['id']), {
                        'status': 'completed',
                        'end_time': now_dt.strftime('%Y-%m-%d %H:%M:%S')
                    })
                    session.pop('latest_attempt_id', None)
                    session.pop('exam_start_time', None)
                    flash("Your exam time has expired.", "warning")
                    return redirect(url_for('exam_instructions', exam_id=exam_id))
                    
            except Exception as e:
                print(f"⚠️ Timer calculation error: {e}")
                remaining_seconds = duration_secs
                is_fresh_start = True
        else:
            is_fresh_start = True

        # Build question palette
        palette = {}
        for i, q in enumerate(questions):
            qid = str(q.get('id', ''))
            if qid in session.get('marked_for_review', []):
                palette[i] = 'review'
            elif qid in session.get('exam_answers', {}):
                palette[i] = 'answered'
            else:
                palette[i] = 'not-visited'

        print(f"✅ Loaded exam: {len(questions)} questions, {remaining_seconds}s remaining")

        return render_template(
            'exam_page.html',
            exam=exam_data,
            question=questions[0] if questions else {},
            current_index=0,
            selected_answer=session.get('exam_answers', {}).get(str(questions[0].get('id'))) if questions else None,
            total_questions=len(questions),
            palette=palette,
            questions=questions,
            remaining_seconds=int(remaining_seconds),
            active_attempt=active_attempt,
            attempts_left=-1,
            attempts_exhausted=False,
            show_start_button=False,
            show_resume_button=bool(active_attempt),
            is_fresh_start=is_fresh_start
        )

    except Exception as e:
        print(f"❌ ERROR in exam_page: {e}")
        import traceback
        traceback.print_exc()
        flash("Error loading exam.", "error")
        return redirect(url_for('dashboard'))   



@app.route('/submit-exam/<int:exam_id>', methods=['POST'])
@require_user_role
def submit_exam(exam_id):
    try:
        user_id = session.get('user_id')
        username = session.get('username', 'Student')
        full_name = session.get('full_name', username)
        
        print(f"📝 [SUBMIT] Starting exam submission for user {user_id}, exam {exam_id}")
        
        # ✅ Get exam from Supabase
        exam = get_exam_by_id(exam_id)
        if not exam:
            print(f"❌ [SUBMIT] Exam {exam_id} not found")
            flash('Exam not found.', 'error')
            return redirect(url_for('dashboard'))

        # ✅ Get questions from Supabase
        questions = get_questions_by_exam(exam_id)
        if not questions:
            print(f"❌ [SUBMIT] No questions for exam {exam_id}")
            flash('No questions found for this exam.', 'error')
            return redirect(url_for('dashboard'))

        print(f"✅ [SUBMIT] Loaded {len(questions)} questions")

        # ✅ Calculate results
        answers = session.get('exam_answers', {})
        total_questions = len(questions)
        correct_answers = 0
        incorrect_answers = 0
        total_score = 0.0
        max_score = 0.0

        positive_marks_str = str(exam.get('positive_marks', '1')).strip()
        negative_marks_str = str(exam.get('negative_marks', '0')).strip()

        response_batch = []

        for question in questions:
            qid = str(question.get('id'))
            qtype = question.get('question_type', 'MCQ')
            marks = float(question.get('positive_marks', 1) or 1)
            max_score += marks

            given_answer = answers.get(qid)
            correct_answer = question.get('correct_answer')

            is_attempted = given_answer is not None and given_answer != ''
            is_correct = False
            marks_obtained = 0.0

            if is_attempted:
                # Check answer correctness
                if qtype == 'MSQ':
                    given_set = set(given_answer) if isinstance(given_answer, list) else set()
                    try:
                        correct_set = set(json.loads(correct_answer)) if isinstance(correct_answer, str) else set(correct_answer)
                    except:
                        correct_set = set(str(correct_answer).split(','))
                    is_correct = (given_set == correct_set)
                else:
                    is_correct = (str(given_answer).strip() == str(correct_answer).strip())

                if is_correct:
                    correct_answers += 1
                    marks_obtained = marks
                else:
                    incorrect_answers += 1
                    try:
                        neg_marks = float(negative_marks_str.split(',')[0]) if ',' in negative_marks_str else float(negative_marks_str)
                    except:
                        neg_marks = 0.0
                    marks_obtained = -neg_marks

                total_score += marks_obtained

            # ✅ Build response record with exam_id
            response_batch.append({
                'question_id': int(qid),
                'exam_id': int(exam_id),  # ✅ CRITICAL: Include exam_id
                'question_type': qtype,
                'given_answer': json.dumps(given_answer) if isinstance(given_answer, list) else str(given_answer or ''),
                'correct_answer': json.dumps(correct_answer) if isinstance(correct_answer, list) else str(correct_answer or ''),
                'is_correct': is_correct,
                'is_attempted': is_attempted,
                'marks_obtained': round(float(marks_obtained), 2)
            })

        unanswered = total_questions - (correct_answers + incorrect_answers)
        percentage = (total_score / max_score * 100) if max_score > 0 else 0

        # Calculate grade
        if percentage >= 90:
            grade = 'A+'
        elif percentage >= 80:
            grade = 'A'
        elif percentage >= 70:
            grade = 'B'
        elif percentage >= 60:
            grade = 'C'
        elif percentage >= 50:
            grade = 'D'
        else:
            grade = 'F'

        print(f"📊 [SUBMIT] Results: {correct_answers}/{total_questions} correct, Score: {total_score}/{max_score} ({percentage:.2f}%)")

        # ✅ Calculate time taken
        start_time_str = session.get('exam_start_time')
        if start_time_str:
            try:
                # Handle both ISO and datetime formats
                try:
                    start_dt = datetime.fromisoformat(start_time_str.replace('Z', '+00:00'))
                except:
                    start_dt = datetime.strptime(start_time_str, "%Y-%m-%d %H:%M:%S")
                
                time_taken_minutes = int((datetime.now() - start_dt).total_seconds() / 60)
            except Exception as e:
                print(f"⚠️ [SUBMIT] Error calculating time: {e}")
                time_taken_minutes = 0
        else:
            time_taken_minutes = 0

        # ✅ Create result record
        new_result = {
            'student_id': int(user_id),
            'exam_id': int(exam_id),
            'score': int(round(total_score)),  # ✅ INTEGER BHEJO
            'max_score': int(round(max_score)),  # ✅ INTEGER BHEJO
            'percentage': round(percentage, 2), 
            'grade': grade,
            'completed_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'time_taken_minutes': int(time_taken_minutes),
            'correct_answers': int(correct_answers),
            'incorrect_answers': int(incorrect_answers),
            'unanswered_questions': int(unanswered),
            'total_questions': int(total_questions)
        }

        print(f"💾 [SUBMIT] Saving result to Supabase...")

        # ✅ Save result to Supabase
        created_result = create_result(new_result)
        if not created_result:
            print(f"❌ [SUBMIT] Failed to save result")
            flash('Error saving result. Please contact support.', 'error')
            return redirect(url_for('exam_page', exam_id=exam_id))

        new_result_id = int(created_result['id'])
        print(f"✅ [SUBMIT] Result saved with ID: {new_result_id}")

        # ✅ Add result_id to all responses
        for resp in response_batch:
            resp['result_id'] = int(new_result_id)

        print(f"💾 [SUBMIT] Saving {len(response_batch)} responses...")

        # ✅ Save responses to Supabase
        if not create_responses_bulk(response_batch):
            print(f"❌ [SUBMIT] Failed to save responses")
            flash('Error saving responses. Please contact support.', 'error')
            return redirect(url_for('exam_page', exam_id=exam_id))

        print(f"✅ [SUBMIT] Responses saved successfully")

        # ✅ Update attempt status
        attempt_id = session.get('latest_attempt_id')
        if attempt_id:
            try:
                print(f"📝 [SUBMIT] Marking attempt {attempt_id} as completed")
                success = update_exam_attempt(int(attempt_id), {
                    'status': 'completed',
                    'end_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
                if success:
                    print(f"✅ [SUBMIT] Attempt marked as completed")
                else:
                    print(f"⚠️ [SUBMIT] Failed to update attempt status")
            except Exception as e:
                print(f"❌ [SUBMIT] Error updating attempt: {e}")

        # ✅ Clear session data
        session['latest_result_id'] = int(new_result_id)
        session.pop('exam_answers', None)
        session.pop('marked_for_review', None)
        session.pop('exam_start_time', None)
        session.pop('timer_reset_flag', None)
        session.pop('latest_attempt_id', None)
        session.modified = True

        # ✅ Mark exam as inactive
        try:
            set_exam_active(user_id, session.get('token'), exam_id=exam_id, is_active=False)
        except Exception as e:
            print(f"⚠️ [SUBMIT] Error setting exam inactive: {e}")

        print(f"🎉 [SUBMIT] Exam submission completed successfully!")
        flash('Exam submitted successfully!', 'success')
        return redirect(url_for('result', exam_id=exam_id))

    except Exception as e:
        print(f"❌ [SUBMIT] Critical error: {e}")
        import traceback
        traceback.print_exc()
        flash('Error submitting exam. Please try again.', 'error')
        return redirect(url_for('dashboard'))



@app.route('/result/<int:exam_id>', defaults={'result_id': None})
@app.route('/result/<int:exam_id>/<int:result_id>')
@require_user_role
def result(exam_id, result_id):
    try:
        user_id = int(session['user_id'])
        
        # ✅ Load exam from Supabase
        exam_data = get_exam_by_id(exam_id)
        if not exam_data:
            flash("Exam details not found.", "error")
            return redirect(url_for('dashboard'))
        
        # Find result
        result_data = None
        
        if result_id:
            # Specific result ID provided
            result_data = get_result_by_id(result_id)
            if result_data and int(result_data.get('student_id')) != user_id:
                flash('Unauthorized access.', 'error')
                return redirect(url_for('dashboard'))
        else:
            # Get latest result for this user and exam
            latest_result_id = session.get('latest_result_id')
            
            if latest_result_id:
                result_data = get_result_by_id(latest_result_id)
                if result_data and int(result_data.get('exam_id')) != exam_id:
                    result_data = None
            
            if not result_data:
                # Get most recent result for this exam
                all_results = get_results_by_user(user_id)
                exam_results = [r for r in all_results if int(r.get('exam_id')) == exam_id]
                if exam_results:
                    exam_results.sort(key=lambda x: x.get('completed_at', ''), reverse=True)
                    result_data = exam_results[0]
        
        if not result_data:
            flash('Result not found!', 'error')
            return redirect(url_for('dashboard'))
        
        return render_template('result.html', 
                             result=result_data, 
                             exam=exam_data, 
                             from_history=(request.args.get("from_history", "0") == "1"))
                             
    except Exception as e:
        print(f"Error loading result: {e}")
        import traceback
        traceback.print_exc()
        flash("Error loading result page.", "error")
        return redirect(url_for('dashboard'))


@app.route('/response/<int:exam_id>', defaults={'result_id': None})
@app.route('/response/<int:exam_id>/<int:result_id>')
@require_user_role
def response_page(exam_id, result_id):
    from_history = request.args.get("from_history", "0") == "1"
    
    try:
        user_id = int(session['user_id'])
        
        # ✅ Load exam from Supabase
        exam_data = get_exam_by_id(exam_id)
        if not exam_data:
            flash('Exam not found!', 'error')
            return redirect(url_for('dashboard'))
        
        # ✅ Determine result_id
        actual_result_id = result_id or session.get('latest_result_id')
        
        if not actual_result_id:
            # Fallback: Get latest result
            user_results = get_results_by_exam(exam_id)
            user_results = [r for r in user_results if int(r.get('student_id')) == user_id]
            
            if user_results:
                user_results.sort(key=lambda x: x.get('completed_at', ''), reverse=True)
                actual_result_id = int(user_results[0].get('id'))
                session['latest_result_id'] = actual_result_id
            else:
                flash('No results found.', 'error')
                return redirect(url_for('results_history'))
        
        # ✅ Load result from Supabase
        result_data = get_result_by_id(actual_result_id)
        
        if not result_data or int(result_data.get('student_id')) != user_id:
            flash('Result not found!', 'error')
            return redirect(url_for('results_history'))
        
        # ✅ Load responses from Supabase
        user_responses = get_responses_by_result(actual_result_id)
        
        if not user_responses:
            flash('No responses found.', 'info')
            return redirect(url_for('results_history'))
        
        user_responses.sort(key=lambda x: int(x.get('question_id', 0)))
        
        # ✅ Load questions from Supabase
        questions = get_questions_by_exam(exam_id)
        questions_dict = {int(q.get('id')): q for q in questions}

        # Build response data
        question_responses = []
        for response in user_responses:
            qid = int(response.get('question_id', 0))
            qdata = questions_dict.get(qid, {})
            if not qdata:
                continue

            given_answer_str = str(response.get('given_answer') or '')
            correct_answer_str = str(response.get('correct_answer') or '')
            qtype = str(response.get('question_type') or 'MCQ')

            # Parse answers
            try:
                if qtype == 'MSQ' and given_answer_str.strip():
                    given_answer = json.loads(given_answer_str) if given_answer_str.startswith('[') else [ans.strip() for ans in given_answer_str.split(',')]
                else:
                    given_answer = given_answer_str if given_answer_str not in ['None', '', None] else None
            except:
                given_answer = given_answer_str

            try:
                if qtype == 'MSQ' and correct_answer_str.strip():
                    correct_answer = json.loads(correct_answer_str) if correct_answer_str.startswith('[') else [ans.strip() for ans in correct_answer_str.split(',')]
                else:
                    correct_answer = correct_answer_str if correct_answer_str not in ['None', '', None] else None
            except:
                correct_answer = correct_answer_str

            is_attempted = bool(response.get('is_attempted', True))
            is_correct = bool(response.get('is_correct', False))
            marks_obtained = float(response.get('marks_obtained', 0) or 0)

            question_responses.append({
                'question': qdata,
                'given_answer': given_answer,
                'correct_answer': correct_answer,
                'is_correct': is_correct,
                'is_attempted': is_attempted,
                'marks_obtained': marks_obtained,
                'question_type': qtype
            })

        return render_template(
            'response.html',
            exam=exam_data,
            result=result_data,
            responses=question_responses,
            from_history=from_history
        )

    except Exception as e:
        print(f"Error in response page: {e}")
        import traceback
        traceback.print_exc()
        flash('Error loading responses.', 'error')
        return redirect(url_for('results_history'))


@app.route('/response-pdf/<int:exam_id>')
@require_user_role
def response_pdf(exam_id):
    """Complete PDF using ReportLab with BigQuery - FIXED VERSION"""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from io import BytesIO
        
        user_id = session.get('user_id')
        username = session.get('username', 'Student')
        full_name = session.get('full_name', username)
        
        # Get exam data
        # ✅ Get exam data from Supabase
        exam = get_exam_by_id(exam_id)
        if not exam:
            flash('Exam not found.', 'error')
            return redirect(url_for('dashboard'))
        
        # ✅ FIX: Get result_id from session
        result_id = session.get('latest_result_id')
        
        if not result_id:
            flash('Result ID not found. Please view responses first.', 'error')
            return redirect(url_for('results_history'))
        
        print(f"📊 Generating PDF for result_id: {result_id}")
        
        # Get result data
        # ✅ Get result data from Supabase
        result_data = get_result_by_id(result_id)

        if not result_data or int(result_data.get('student_id')) != user_id:
            flash('Result not found.', 'error')
            return redirect(url_for('dashboard'))

        result = result_data
        
        # ✅ Get responses for THIS specific result
        try:
            print(f"📊 Loading responses for result_id: {result_id}")
            user_responses = get_responses_by_result(result_id)
            
            if not user_responses:
                flash('No responses found.', 'error')
                return redirect(url_for('dashboard'))
            
            user_responses.sort(key=lambda x: int(x.get('question_id', 0)))
            print(f"✅ Loaded {len(user_responses)} responses")
            
        except Exception as e:
            print(f"Error loading responses: {e}")
            flash('No responses found.', 'error')
            return redirect(url_for('dashboard'))
        
        # Get questions
        # ✅ Get questions from Supabase
        try:
            questions = get_questions_by_exam(exam_id)
            questions_dict = {int(q.get('id')): q for q in questions}
        except Exception as e:
            print(f"Error loading questions: {e}")
            questions_dict = {}
        
        # Create PDF
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=50, leftMargin=50, topMargin=50, bottomMargin=50)
        
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle('CustomTitle', parent=styles['Title'], fontSize=18, textColor=colors.HexColor('#2c3e50'), spaceAfter=20, alignment=TA_CENTER)
        heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'], fontSize=14, textColor=colors.HexColor('#2c3e50'), spaceAfter=10)
        
        story = []
        
        # Title
        story.append(Paragraph("Exam Response Analysis", title_style))
        
        # Header info
        header_data = [
            ['Exam:', str(exam.get('name', 'Unknown'))],
            ['Student:', str(full_name)],
            ['Score:', f"{result.get('score', 0)}/{result.get('max_score', 0)} ({result.get('percentage', 0):.1f}%)"],
            ['Grade:', str(result.get('grade', 'N/A'))]
        ]
        
        header_table = Table(header_data, colWidths=[1.5*inch, 4*inch])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('PADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(header_table)
        story.append(Spacer(1, 20))
        
        # Questions and responses
        for response in user_responses:
            question_id = int(response.get('question_id', 0))
            question = questions_dict.get(question_id, {})
            
            if not question:
                continue
                
            story.append(Paragraph(f"Question {question_id}", heading_style))
            
            question_text = str(question.get('question_text', ''))
            story.append(Paragraph(f"<b>Question:</b> {question_text}", styles['Normal']))
            story.append(Spacer(1, 10))
            
            question_type = question.get('question_type', '')
            if question_type in ['MCQ', 'MSQ']:
                story.append(Paragraph("<b>Options:</b>", styles['Normal']))
                
                options = [
                    ('A', question.get('option_a', '')),
                    ('B', question.get('option_b', '')),
                    ('C', question.get('option_c', '')),
                    ('D', question.get('option_d', ''))
                ]
                
                for label, option_text in options:
                    if option_text and str(option_text).strip() and str(option_text) not in ['nan', 'None', '']:
                        story.append(Paragraph(f"<b>{label}.</b> {option_text}", styles['Normal']))
                
                story.append(Spacer(1, 10))
            
            given_answer = str(response.get('given_answer', 'Not Answered'))
            if given_answer in ['nan', 'None', '']:
                given_answer = 'Not Answered'
                
            correct_answer = str(response.get('correct_answer', 'N/A'))
            if correct_answer in ['nan', 'None', '']:
                correct_answer = 'N/A'
            
            marks = response.get('marks_obtained', 0)
            is_correct = str(response.get('is_correct', 'false')).lower() == 'true'
            
            answer_data = [
                ['Your Answer:', given_answer],
                ['Correct Answer:', correct_answer],
                ['Marks Obtained:', str(marks)],
                ['Status:', 'Correct' if is_correct else 'Incorrect' if given_answer != 'Not Answered' else 'Not Attempted']
            ]
            
            answer_table = Table(answer_data, colWidths=[1.5*inch, 4*inch])
            answer_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightblue),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('PADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(answer_table)
            story.append(Spacer(1, 20))
        
        # Summary
        story.append(Paragraph("Performance Summary", heading_style))
        
        summary_data = [
            ['Total Questions:', str(result.get('total_questions', 0))],
            ['Correct Answers:', str(result.get('correct_answers', 0))],
            ['Incorrect Answers:', str(result.get('incorrect_answers', 0))],
            ['Unanswered:', str(result.get('unanswered_questions', 0))],
            ['Final Score:', f"{result.get('score', 0)}/{result.get('max_score', 0)}"],
            ['Percentage:', f"{result.get('percentage', 0):.1f}%"]
        ]
        
        summary_table = Table(summary_data, colWidths=[2*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.lightgreen),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('PADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(summary_table)
        
        doc.build(story)
        
        pdf_bytes = buffer.getvalue()
        buffer.close()
        
        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment; filename=exam_{exam_id}_response_{username}.pdf'}
        )
        
    except Exception as e:
        print(f"PDF generation error: {e}")
        import traceback
        traceback.print_exc()
        flash('Error generating PDF.', 'error')
        return redirect(url_for('response', exam_id=exam_id))




@app.route('/response-txt/<int:exam_id>')
@require_user_role
def response_txt(exam_id):
    """Text file export as fallback"""
    try:
        user_id = session.get('user_id')
        username = session.get('username', 'Student')
        
        # Create simple text content
        content = f"""Exam Response Summary
Exam ID: {exam_id}
Student: {username}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

For detailed analysis including questions and answers,
please view the online response page in your browser.

This is a basic completion record for your exam attempt.
"""
        
        return Response(
            content,
            mimetype='text/plain',
            headers={
                'Content-Disposition': f'attachment; filename="exam_{exam_id}_summary.txt"'
            }
        )
        
    except Exception as e:
        print(f"Text export error: {e}")
        flash('Export failed. Please contact support.', 'error')
        return redirect(url_for('response', exam_id=exam_id))


@app.route('/logout')
def logout():
    try:
        user_id = session.get('user_id')
        token = session.get('token')
        
        if user_id and token:
            invalidate_session(user_id, token)
        
        session.clear()
        flash('Logged out successfully!', 'success')
        
        # ✅ Use render_template with redirect JavaScript (prevents back button)
        return render_template('logout_redirect.html')
    
    except Exception as e:
        print(f"Logout error: {e}")
        session.clear()
        return render_template('logout_redirect.html')



# -------------------------
# CRITICAL: Add service check endpoint for debugging
# -------------------------
@app.route('/debug/service-status')
def debug_service_status():
    """Debug endpoint to check service status"""
    global drive_service
    
    status = {
        'drive_service_initialized': drive_service is not None,
        'environment_variables': {},
        'file_ids': DRIVE_FILE_IDS.copy(),
        'folder_ids': DRIVE_FOLDER_IDS.copy()
    }
    
    # Check environment variables (don't expose full values)
    for var in ['SECRET_KEY', 'GOOGLE_SERVICE_ACCOUNT_JSON', 'USERS_FILE_ID']:
        value = os.environ.get(var)
        if value:
            if var == 'GOOGLE_SERVICE_ACCOUNT_JSON':
                status['environment_variables'][var] = f"Present ({len(value)} chars)"
            else:
                status['environment_variables'][var] = "Present"
        else:
            status['environment_variables'][var] = "MISSING"
    
    # Test drive service if available
    if drive_service:
        try:
            about = drive_service.about().get(fields="user").execute()
            status['drive_test'] = f"Connected as: {about.get('user', {}).get('emailAddress', 'Unknown')}"
        except Exception as e:
            status['drive_test'] = f"Error: {str(e)}"
    else:
        status['drive_test'] = "Service not initialized"
    
    return jsonify(status)






# -------------------------
# Error Handlers
# -------------------------
@app.errorhandler(404)
def not_found_error(error):
    try:
        return render_template('error.html', error_code=404, error_message="Page not found"), 404
    except:
        return "404 - Page not found", 404


@app.errorhandler(500)
def internal_error(error):
    try:
        return render_template('error.html', error_code=500, error_message="Internal server error"), 500
    except:
        return "500 - Internal server error", 500




@app.errorhandler(Exception)
def handle_global_error(e):
    """Enhanced global error handler with debugging"""
    print(f"GLOBAL ERROR HANDLER caught: {e}")
    print(f"Request path: {request.path}")
    print(f"Request method: {request.method}")
    print(f"Form data keys: {list(request.form.keys()) if request.form else 'No form data'}")
    
    import traceback
    traceback.print_exc()
    
    # Log the error details
    error_info = {
        'error': str(e),
        'type': type(e).__name__,
        'route': request.endpoint,
        'method': request.method,
        'url': request.url,
        'user_id': session.get('user_id', 'anonymous'),
        'timestamp': datetime.now().isoformat()
    }
    
    try:
        # Log to file if possible
        with open('error_log.txt', 'a') as f:
            f.write(f"{datetime.now()}: {error_info}\n")
    except:
        pass
    
    # Don't flash errors for AJAX requests
    if request.is_json or '/api/' in request.path:
        return {"error": "Server error occurred"}, 500
    
    flash("A system error occurred. Please try again or contact support.", "error")
    
    # Redirect based on context
    if '/admin/' in request.path:
        return redirect(url_for('admin.admin_login'))
    else:
        return redirect(url_for('login'))
















@app.route('/request-admin-access')
def request_admin_access_page():
    """Request admin access page for users"""
    return render_template('request_admin_access.html')

@app.route('/api/validate-user-for-request', methods=['POST'])
def api_validate_user_for_request():
    """Validate user for access request - PURE SUPABASE"""
    try:
        data = request.get_json()
        if not data or not data.get('username') or not data.get('email'):
            return jsonify({'success': False, 'message': 'Username and email are required'}), 400

        username = data['username'].strip()
        email = data['email'].strip().lower()

        print(f"🔍 Validating user: {username}, {email}")

        # ✅ GET USER FROM SUPABASE (NO CSV!)
        from supabase_db import supabase
        
        try:
            user_response = supabase.table('users').select('*')\
                .eq('username', username)\
                .eq('email', email)\
                .execute()
            
            if not user_response.data:
                print(f"❌ User not found in Supabase")
                return jsonify({
                    'success': False, 
                    'message': 'User does not exist with provided username and email combination'
                }), 404
            
            user = user_response.data[0]
            print(f"✅ User found: {user.get('username')}")
            
        except Exception as e:
            print(f"❌ Supabase user query error: {e}")
            return jsonify({'success': False, 'message': 'Database error'}), 500

        current_access = str(user.get('role', 'user')).strip().lower()
        
        # ✅ GET REQUESTS FROM SUPABASE (NO CSV!)
        try:
            requests_response = supabase.table('requests_raised').select('*')\
                .eq('username', username)\
                .eq('email', email)\
                .order('request_date', desc=True)\
                .execute()
            
            user_requests_data = requests_response.data if requests_response.data else []
            print(f"✅ Found {len(user_requests_data)} existing requests")
            
        except Exception as e:
            print(f"⚠️ Error loading requests: {e}")
            user_requests_data = []

        # Format requests
        user_requests = []
        for req in user_requests_data:
            user_requests.append({
                'request_id': int(req.get('request_id', 0)),
                'requested_access': req.get('requested_access', ''),
                'request_date': str(req.get('request_date', '')),
                'status': req.get('request_status', ''),
                'reason': req.get('reason') or ''
            })

        # Determine available requests
        available_requests = []
        if current_access == 'user':
            available_requests = ['admin', 'user,admin']
        elif current_access == 'admin':
            available_requests = ['user', 'user,admin']
        elif current_access in ['user,admin', 'admin,user']:
            available_requests = []
        else:
            available_requests = ['admin', 'user,admin']

        has_pending = any(str(req.get('status', '')).lower() == 'pending' for req in user_requests)

        response_data = {
            'success': True,
            'user': {
                'username': str(user['username']),
                'email': str(user['email']),
                'current_access': current_access,
                'full_name': str(user.get('full_name', user['username']))
            },
            'requests': user_requests,
            'available_requests': available_requests,
            'has_pending_request': has_pending,
            'can_request': len(available_requests) > 0 and not has_pending
        }
        
        print(f"✅ Validation successful. Can request: {response_data['can_request']}")
        return jsonify(response_data)

    except Exception as e:
        print(f"❌ Validation error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'System error occurred'}), 500




@app.route('/api/submit-access-request', methods=['POST'])
def api_submit_access_request():
    """Submit access request - PURE SUPABASE"""
    try:
        data = request.get_json()
        required_fields = ['username', 'email', 'current_access', 'requested_access']

        for field in required_fields:
            if not data or not data.get(field):
                return jsonify({
                    'success': False, 
                    'message': f'{field.replace("_", " ").title()} is required'
                }), 400

        username = data['username'].strip()
        email = data['email'].strip().lower()
        current_access = data['current_access'].strip().lower()
        requested_access = data['requested_access'].strip().lower()

        print(f"📝 Submitting request: {username} → {requested_access}")

        # ✅ VERIFY USER EXISTS IN SUPABASE (NO CSV!)
        from supabase_db import supabase
        
        try:
            user_response = supabase.table('users').select('*')\
                .eq('username', username)\
                .eq('email', email)\
                .execute()
            
            if not user_response.data:
                return jsonify({'success': False, 'message': 'User validation failed'}), 400
            
            print(f"✅ User verified: {username}")
            
        except Exception as e:
            print(f"❌ User verification error: {e}")
            return jsonify({'success': False, 'message': 'Database error'}), 500

        # ✅ CHECK FOR EXISTING PENDING REQUEST
        try:
            pending_response = supabase.table('requests_raised').select('*')\
                .eq('username', username)\
                .eq('email', email)\
                .eq('request_status', 'pending')\
                .execute()
            
            if pending_response.data:
                print(f"⚠️ Pending request already exists")
                return jsonify({
                    'success': False, 
                    'message': 'You already have a pending request. Please wait for admin approval.'
                }), 400
        
        except Exception as e:
            print(f"⚠️ Error checking pending: {e}")

        # ✅ CREATE NEW REQUEST (AUTO INCREMENT request_id)
        
        user_reason = data.get('user_reason', '').strip()
        if not user_reason:
            return jsonify({
                'success': False,
                'message': 'Please provide a reason for your request'
            }), 400

        # âœ… CREATE NEW REQUEST (AUTO INCREMENT request_id)
        new_request = {
            'username': username,
            'email': email,
            'current_access': current_access,
            'requested_access': requested_access,
            'request_date': datetime.now().isoformat(),
            'request_status': 'pending',
            'reason': f"[USER REQUEST] {user_reason}",  # Prefix with [USER REQUEST]
            'processed_by': None,
            'processed_date': None
        }

        # ✅ INSERT INTO SUPABASE
        try:
            insert_response = supabase.table('requests_raised').insert(new_request).execute()
            
            if not insert_response.data:
                raise Exception("No data returned from insert")
            
            created_request = insert_response.data[0]
            request_id = int(created_request.get('request_id', 0))
            
            print(f"✅ Request {request_id} created successfully")
            
        except Exception as e:
            print(f"❌ Insert error: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({
                'success': False, 
                'message': 'Failed to save request. Please try again.'
            }), 500

        # ✅ GET UPDATED REQUESTS
        requests_response = supabase.table('requests_raised').select('*')\
            .eq('username', username)\
            .eq('email', email)\
            .order('request_date', desc=True)\
            .execute()
        
        user_requests = []
        for req in (requests_response.data or []):
            user_requests.append({
                'request_id': int(req.get('request_id', 0)),
                'requested_access': req.get('requested_access', ''),
                'request_date': str(req.get('request_date', '')),
                'status': req.get('request_status', ''),
                'reason': req.get('reason') or ''
            })

        # Determine available requests
        available_requests = []
        if current_access == 'user':
            available_requests = ['admin', 'user,admin']
        elif current_access == 'admin':
            available_requests = ['user', 'user,admin']

        has_pending = True  # Just submitted

        return jsonify({
            'success': True,
            'message': 'Access request submitted successfully. Please wait for admin approval.',
            'request_id': request_id,
            'user': {
                'username': username,
                'email': email,
                'current_access': current_access,
                'full_name': username
            },
            'requests': user_requests,
            'available_requests': available_requests,
            'has_pending_request': has_pending,
            'can_request': False  # Can't request again until pending is processed
        })

    except Exception as e:
        print(f"❌ Submit error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'System error occurred'}), 500


# Helper function to initialize requests_raised.csv if it doesn't exist
def ensure_requests_raised_csv_safe():
    """Safe version that doesn't use Flask session functions"""
    try:
        # Only check if file exists, don't try to load it
        print("Checking requests_raised.csv file...")
        return True  # Just return success for now
    except Exception as e:
        print(f"Error checking requests_raised.csv: {e}")
        return False

def init_requests_raised_if_needed():
    """Initialize requests_raised.csv when actually needed (within request context)"""
    try:
        requests_df = load_csv_with_cache('requests_raised.csv')
        if requests_df is None or requests_df.empty:
            headers_df = pd.DataFrame(columns=[
                'request_id', 'username', 'email', 'current_access',
                'requested_access', 'request_date', 'request_status', 'reason'
            ])
            success = safe_csv_save_with_retry(headers_df, 'requests_raised')
            if success:
                print("✅ Created requests_raised.csv with headers")
            return success
        return True
    except Exception as e:
        print(f"Error initializing requests_raised.csv: {e}")
        return False


def cleanup_app_cache():
    """Periodic cache cleanup"""
    try:
        current_time = time.time()
        cache_data = app_cache.get('data', {})
        cache_timestamps = app_cache.get('timestamps', {})
        
        # Remove items older than 10 minutes
        for key in list(cache_data.keys()):
            if current_time - cache_timestamps.get(key, 0) > 600:
                cache_data.pop(key, None)
                cache_timestamps.pop(key, None)
        
        # Limit total cache items
        if len(cache_data) > 50:
            # Keep only the 30 most recent items
            sorted_items = sorted(cache_timestamps.items(), key=lambda x: x[1], reverse=True)
            keep_keys = [key for key, _ in sorted_items[:30]]
            
            app_cache['data'] = {k: v for k, v in cache_data.items() if k in keep_keys}
            app_cache['timestamps'] = {k: v for k, v in cache_timestamps.items() if k in keep_keys}
    
    except Exception as e:
        print(f"Cache cleanup error: {e}")

# Run cleanup every 5 minutes
import threading
def periodic_cleanup():
    cleanup_app_cache()
    threading.Timer(300, periodic_cleanup).start()

periodic_cleanup()

@app.route('/_ping', methods=['POST'])
def ping():
    """Keep session alive"""
    if 'user_id' in session:
        return '', 204  # No content, session is alive
    return jsonify({'reason': 'no_session'}), 401


# =============================================
# REMAINING PASSWORD ROUTES - ADD TO main.py
# =============================================

@app.route('/api/request-password-reset', methods=['POST'])
def request_password_reset():
    """API endpoint to request password reset via email - SUPABASE VERSION"""
    try:
        data = request.get_json()
        if not data or not data.get('email'):
            return jsonify({
                'success': False,
                'message': 'Email address is required'
            }), 400

        email = data['email'].strip().lower()
        client_ip = get_client_ip()

        if not email:
            return jsonify({
                'success': False,
                'message': 'Please enter a valid email address'
            }), 400

        # Always show success message to prevent email enumeration
        success_message = "If an account exists with this email, a password reset link has been sent."

        # ✅ USE SUPABASE INSTEAD OF CSV
        from supabase_db import get_user_by_email
        
        user = get_user_by_email(email)
        
        if user:
            try:
                full_name = user.get('full_name', 'User')
                username = user.get('username', email.split('@')[0])
                
                # Generate reset token
                reset_token = create_password_token(email, 'reset')
                
                # ✅ SEND RESET EMAIL WITH USERNAME
                from email_utils import send_password_reset_email
                email_sent, email_message = send_password_reset_email(email, full_name, username, reset_token)
                
                if email_sent:
                    print(f"✅ Reset email sent to {email} with username: {username}")
                else:
                    print(f"❌ Failed to send reset email to {email}: {email_message}")
                
            except Exception as e:
                print(f"❌ Error processing reset request for {email}: {e}")
                import traceback
                traceback.print_exc()

        # Always return success to prevent email enumeration
        return jsonify({
            'success': True,
            'message': success_message
        })

    except Exception as e:
        print(f"❌ Error in password reset request: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'message': 'System error occurred. Please try again.'
        }), 500

# REPLACE THE PASSWORD RESET ROUTE IN main.py WITH THIS:

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password_page():
    """Password reset page route - SUPABASE VERSION"""
    if request.method == 'POST':
        try:
            email = request.form.get('email', '').strip().lower()
            
            if not email:
                flash('Please enter your email address.', 'error')
                return redirect(url_for('reset_password_page'))

            client_ip = get_client_ip()
            
            # Always show success message to prevent email enumeration
            success_message = "If an account exists with this email, a password reset link has been sent. Please check your inbox and spam folder."

            # ✅ USE SUPABASE INSTEAD OF CSV
            from supabase_db import get_user_by_email
            
            user = get_user_by_email(email)
            
            if user:
                try:
                    full_name = user.get('full_name', 'User')
                    username = user.get('username', email.split('@')[0])
                    
                    # Generate reset token
                    reset_token = create_password_token(email, 'reset')
                    
                    # ✅ SEND RESET EMAIL WITH USERNAME
                    from email_utils import send_password_reset_email
                    email_sent, email_message = send_password_reset_email(email, full_name, username, reset_token)
                    
                    if email_sent:
                        print(f"✅ Reset email sent to {email} with username: {username}")
                    else:
                        print(f"❌ Failed to send reset email to {email}: {email_message}")
                    
                except Exception as e:
                    print(f"❌ Error processing reset request for {email}: {e}")
                    import traceback
                    traceback.print_exc()

            # Always return success message (security - don't leak if email exists)
            flash(success_message, 'success')
            return redirect(url_for('reset_password_page'))
            
        except Exception as e:
            print(f"❌ Error in password reset: {e}")
            import traceback
            traceback.print_exc()
            flash('System error occurred. Please try again.', 'error')
            return redirect(url_for('reset_password_page'))
    
    # GET request - show the form
    return render_template('password_reset.html')

# ADD migration route (run once to convert existing passwords)
@app.route('/admin/migrate-passwords')
@require_admin_role
def admin_migrate_passwords():
    """One-time migration route to convert plaintext passwords to bcrypt."""
    try:
        success, message = migrate_plaintext_passwords()
        
        if success:
            flash(f'Password migration completed: {message}', 'success')
        else:
            flash(f'Password migration failed: {message}', 'error')
        
        return redirect(url_for('admin.dashboard'))
        
    except Exception as e:
        print(f"Error in password migration: {e}")
        flash(f'Migration error: {str(e)}', 'error')
        return redirect(url_for('admin.dashboard'))

# UPDATE existing API route for secure password change
@app.route('/api/reset-password', methods=['POST'])
def api_reset_password():
    """REPLACE existing api_reset_password with secure version."""
    try:
        data = request.get_json()
        
        # This is now handled by the token-based system
        # Redirect users to use the proper reset flow
        return jsonify({
            'success': False,
            'message': 'Please use the reset link sent to your email to change your password.',
            'redirect': url_for('reset_password_page')
        }), 400
        
    except Exception as e:
        print(f"Error in API reset password: {e}")
        return jsonify({
            'success': False,
            'message': 'System error occurred'
        }), 500


# Background cleanup and startup tasks
import threading

def background_cleanup():
    while True:
        try:
            time.sleep(300)
        except Exception as e:
            print(f"Background cleanup error: {e}")
            time.sleep(60)

try:
    cleanup_thread = threading.Thread(target=background_cleanup, daemon=True)
    cleanup_thread.start()
    print("Background cleanup started")
except Exception as e:
    print(f"Background cleanup startup error: {e}")



@app.route('/debug/check-ai-env')
def debug_check_ai_env():
    """Debug route to verify environment variables"""
    import os
    return {
        'AI_CHAT_HISTORY_FILE_ID_env': os.environ.get('AI_CHAT_HISTORY_FILE_ID', 'NOT SET'),
        'AI_USAGE_TRACKING_FILE_ID_env': os.environ.get('AI_USAGE_TRACKING_FILE_ID', 'NOT SET'),
        'DRIVE_FILE_IDS_ai_chat_history': DRIVE_FILE_IDS.get('ai_chat_history', 'NOT IN DICT'),
        'DRIVE_FILE_IDS_ai_usage_tracking': DRIVE_FILE_IDS.get('ai_usage_tracking', 'NOT IN DICT'),
        'all_drive_file_ids_keys': list(DRIVE_FILE_IDS.keys())
    }

@app.context_processor
def inject_year():
    return dict(CURRENT_YEAR=datetime.now().year)

# -------------------------
# Run App - CRITICAL INITIALIZATION
# -------------------------
if __name__ == '__main__':
    print("🚀 Starting FIXED Exam Portal...")
    
    # CRITICAL: Force initialization during startup
    print("🔧 Forcing Google Drive service initialization...")
    if init_drive_service():
        print("✅ Google Drive integration: ACTIVE")
        
        # Check and fix AI CSV structure
        print("🔧 Checking AI CSV structure...")
        ensure_ai_csv_structure()
        
    else:
        print("❌ Google Drive integration: INACTIVE")
        print("⚠️ App will run in limited mode")

    app.run(debug=True if not IS_PRODUCTION else False)
else:
    # CRITICAL: This runs when deployed with Gunicorn
    print("🌐 Gunicorn detected - initializing services for production...")
    
    # Force immediate initialization
    if init_drive_service():
        print("✅ Production Google Drive integration: ACTIVE")
        
        # Check and fix AI CSV structure
        print("🔧 Checking AI CSV structure...")
        ensure_ai_csv_structure()
        
    else:
        print("❌ Production Google Drive integration: FAILED")
        print("📋 Check environment variables and credentials")
