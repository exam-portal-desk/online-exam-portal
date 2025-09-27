from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import pandas as pd
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
import threading
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
from zoneinfo import ZoneInfo
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



# Register admin blueprint
app.register_blueprint(admin_bp, url_prefix="/admin")

# Configuration
USERS_CSV = 'users.csv'
EXAMS_CSV = 'exams.csv'
QUESTIONS_CSV = 'questions.csv'
RESULTS_CSV = 'results.csv'
RESPONSES_CSV = 'responses.csv'

# CRITICAL: Debug environment variables
print("🔍 Checking environment variables...")
required_env_vars = [
    'SECRET_KEY', 'GOOGLE_SERVICE_ACCOUNT_JSON',
    'USERS_FILE_ID', 'EXAMS_FILE_ID', 'QUESTIONS_FILE_ID', 'RESULTS_FILE_ID', 'RESPONSES_FILE_ID'
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

# Google Drive File IDs
USERS_FILE_ID = os.environ.get('USERS_FILE_ID')
EXAMS_FILE_ID = os.environ.get('EXAMS_FILE_ID')
QUESTIONS_FILE_ID = os.environ.get('QUESTIONS_FILE_ID')
RESULTS_FILE_ID = os.environ.get('RESULTS_FILE_ID')
RESPONSES_FILE_ID = os.environ.get('RESPONSES_FILE_ID')
EXAM_ATTEMPTS_FILE_ID = os.environ.get('EXAM_ATTEMPTS_FILE_ID')
REQUESTS_RAISED_FILE_ID = os.environ.get("REQUESTS_RAISED_FILE_ID")
LOGIN_ATTEMPTS_FILE_ID = os.environ.get('LOGIN_ATTEMPTS_FILE_ID')
PW_TOKENS_FILE_ID = os.environ.get('PW_TOKENS_FILE_ID')

DRIVE_FILE_IDS = {
    'users': USERS_FILE_ID,
    'exams': EXAMS_FILE_ID,
    'questions': QUESTIONS_FILE_ID,
    'results': RESULTS_FILE_ID,
    'responses': RESPONSES_FILE_ID,
    'exam_attempts': EXAM_ATTEMPTS_FILE_ID,
    'requests_raised': REQUESTS_RAISED_FILE_ID,
    'login_attempts': LOGIN_ATTEMPTS_FILE_ID,
    'pw_tokens': PW_TOKENS_FILE_ID  
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
    """Enhanced cache clearing for immediate data refresh"""
    global app_cache
    
    try:
        # Clear global app cache
        cache_keys_to_clear = [k for k in app_cache.get('data', {}).keys() if 'users' in k.lower()]
        for key in cache_keys_to_clear:
            app_cache['data'].pop(key, None)
            app_cache['timestamps'].pop(key, None)
        
        # Force refresh flag
        app_cache['force_refresh'] = True
        
        # Clear session cache if available
        try:
            from flask import session
            session_keys_to_clear = [k for k in list(session.keys()) if 'csv_users' in k or 'user_data' in k]
            for k in session_keys_to_clear:
                session.pop(k, None)
        except:
            pass
        
        # Clear Google Drive service cache if available
        try:
            from google_drive_service import clear_csv_cache
            if DRIVE_FILE_IDS.get('users'):
                clear_csv_cache(DRIVE_FILE_IDS['users'])
        except:
            pass
        
        print("Enhanced cache clearing completed")
        
    except Exception as e:
        print(f"Error in enhanced cache clearing: {e}")



# =============================================
# CONCURRENT SAFETY SYSTEM
# =============================================

# Global file locks
file_locks = {}
lock_registry = threading.RLock()

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
        'users.csv': DRIVE_FILE_IDS['users'],
        'exams.csv': DRIVE_FILE_IDS['exams'],
        'questions.csv': DRIVE_FILE_IDS['questions'],
        'results.csv': DRIVE_FILE_IDS['results'],
        'responses.csv': DRIVE_FILE_IDS['responses']
    }

    for filename, file_id in required_files.items():
        if not file_id or file_id.startswith('YOUR_'):
            print(f"⚠️ {filename}: File ID not configured properly")
            continue
            
        try:
            # Try to get file metadata to check if it exists
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


def ensure_required_files():
    """Ensure all required CSV files exist in Google Drive"""
    global drive_service

    if not drive_service:
        return

    required_files = {
        'users.csv': DRIVE_FILE_IDS['users'],
        'exams.csv': DRIVE_FILE_IDS['exams'],
        'questions.csv': DRIVE_FILE_IDS['questions'],
        'results.csv': DRIVE_FILE_IDS['results'],
        'responses.csv': DRIVE_FILE_IDS['responses']
    }

    for filename, file_id in required_files.items():
        try:
            # Try to load the file to check if it exists
            test_df = load_csv_from_drive(drive_service, file_id)
            if test_df is not None:
                print(f"✅ Verified {filename} exists")
            else:
                print(f"⚠️ {filename} may not exist, but ID is configured")
        except Exception as e:
            print(f"❌ Error verifying {filename}: {e}")


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
    """Process image path using subjects.csv - PERFORMANCE OPTIMIZED"""
    global drive_service, app_cache

    image_path = question.get("image_path")

    if (
        image_path is None
        or pd.isna(image_path)
        or str(image_path).strip() in ["", "nan", "NaN", "null", "None"]
    ):
        return False, None

    image_path = str(image_path).strip()
    if not image_path:
        return False, None

    # Cache check first
    cache_key = f"image_{image_path}"
    if cache_key in app_cache["images"]:
        cached_time = app_cache["timestamps"].get(cache_key, 0)
        if time.time() - cached_time < 3600:  # 1 hour
            print(f"⚡ Using cached image URL for {image_path}")
            return True, app_cache["images"][cache_key]

    # PERFORMANCE FIX: Reuse global service
    if drive_service is None:
        print(f"❌ No drive service for image: {image_path}")
        return False, None

    try:
        filename = os.path.basename(image_path)  # e.g. dt-1.png
        subject = os.path.dirname(image_path).lower()  # e.g. math

        # Find subject folder with SSL-safe retry - using GLOBAL service
        folder_id = None
        subjects_file_id = os.environ.get("SUBJECTS_FILE_ID")
        if subjects_file_id:
            for attempt in range(3):
                try:
                    print(f"📂 Loading subjects.csv (attempt {attempt + 1})")
                    # Use global service instead of creating new one
                    subjects_df = load_csv_from_drive(drive_service, subjects_file_id)
                    if not subjects_df.empty:
                        subjects_df["subject_name"] = subjects_df["subject_name"].astype(str).str.strip().str.lower()
                        match = subjects_df[subjects_df["subject_name"] == subject.strip().lower()]
                        if not match.empty:
                            folder_id = str(match.iloc[0]["subject_folder_id"])
                            print(f"📂 Found folder for subject '{subject}': {folder_id}")
                            break
                        else:
                            print(f"⚠️ No match for subject '{subject}' in subjects.csv")
                            break
                    else:
                        print(f"⚠️ Empty subjects.csv on attempt {attempt + 1}")
                except Exception as e:
                    error_msg = str(e).lower()
                    if 'ssl' in error_msg or 'timeout' in error_msg:
                        print(f"🔄 SSL/timeout error on attempt {attempt + 1}, retrying...")
                        time.sleep(1 * (attempt + 1))
                        continue
                    else:
                        print(f"❌ Non-SSL error reading subjects.csv: {e}")
                        break

        # Fallback to IMAGES_FOLDER_ID if subject folder not found
        if not folder_id and os.environ.get("IMAGES_FOLDER_ID"):
            folder_id = os.environ.get("IMAGES_FOLDER_ID")
            print(f"📂 Fallback to IMAGES folder for subject {subject}: {folder_id}")

        if not folder_id:
            print(f"❌ No folder ID found for subject: {subject}")
            return False, None

        # Find file inside resolved folder with SSL-safe retry - using GLOBAL service
        image_file_id = None
        for attempt in range(3):
            try:
                print(f"🔍 Finding image file (attempt {attempt + 1}): {filename}")
                # Use global service instead of creating new one
                image_file_id = find_file_by_name(drive_service, filename, folder_id)
                if image_file_id:
                    break
            except Exception as e:
                error_msg = str(e).lower()
                if 'ssl' in error_msg or 'timeout' in error_msg:
                    print(f"🔄 SSL/timeout error finding file, attempt {attempt + 1}")
                    time.sleep(1 * (attempt + 1))
                    continue
                else:
                    print(f"❌ Non-SSL error finding file: {e}")
                    break

        if image_file_id:
            # Get public URL with retry - using GLOBAL service
            image_url = None
            for attempt in range(3):
                try:
                    print(f"🔗 Getting public URL (attempt {attempt + 1})")
                    # Use global service instead of creating new one
                    image_url = get_public_url(drive_service, image_file_id)
                    if image_url:
                        break
                except Exception as e:
                    error_msg = str(e).lower()
                    if 'ssl' in error_msg or 'timeout' in error_msg:
                        print(f"🔄 SSL/timeout error getting URL, attempt {attempt + 1}")
                        time.sleep(1 * (attempt + 1))
                        continue
                    else:
                        print(f"❌ Non-SSL error getting URL: {e}")
                        break
            
            if image_url:
                app_cache["images"][cache_key] = image_url
                app_cache["timestamps"][cache_key] = time.time()
                print(f"✅ Cached image URL: {image_path} -> {image_url}")
                return True, image_url

        print(f"❌ Image file not found: {filename} in folder {folder_id}")
        return False, None

    except Exception as e:
        print(f"❌ Error processing image {image_path}: {e}")
        return False, None

@debug_logging("preload_exam_data_fixed")
def preload_exam_data_fixed(exam_id):
    """
    FIXED: Exam data preloading with proper error handling and validation
    """
    start_time = time.time()
    print(f"Preloading exam data for exam_id: {exam_id}")

    try:
        # CRITICAL: Load questions first with explicit validation
        questions_df = None
        for attempt in range(3):  # Retry loading questions
            try:
                print(f"Loading questions.csv (attempt {attempt + 1})")
                questions_df = load_csv_with_cache('questions.csv', force_reload=(attempt > 0))
                
                # Validate questions DataFrame
                if questions_df is None:
                    print(f"questions.csv returned None on attempt {attempt + 1}")
                    continue
                elif not hasattr(questions_df, 'empty'):
                    print(f"Invalid questions DataFrame type: {type(questions_df)}")
                    continue
                elif questions_df.empty:
                    print(f"questions.csv is empty on attempt {attempt + 1}")
                    if attempt == 2:  # Last attempt
                        return False, "Questions database is empty"
                    continue
                else:
                    print(f"Successfully loaded {len(questions_df)} questions")
                    break
                    
            except Exception as e:
                print(f"Error loading questions.csv (attempt {attempt + 1}): {e}")
                if attempt == 2:  # Last attempt
                    return False, f"Failed to load questions: {str(e)}"
                time.sleep(0.5)  # Brief delay before retry

        if questions_df is None or questions_df.empty:
            return False, "Questions data is unavailable or empty"

        # Load exams data with validation
        exams_df = None
        try:
            exams_df = load_csv_with_cache('exams.csv')
            if exams_df is None or exams_df.empty:
                return False, "Exams data is unavailable"
        except Exception as e:
            print(f"Error loading exams.csv: {e}")
            return False, f"Failed to load exam metadata: {str(e)}"

        # Filter questions for this exam
        exam_id_str = str(exam_id)
        try:
            # Ensure exam_id column exists
            if 'exam_id' not in questions_df.columns:
                return False, "Questions file missing exam_id column"
                
            exam_questions = questions_df[questions_df['exam_id'].astype(str) == exam_id_str]
            print(f"Found {len(exam_questions)} questions for exam {exam_id}")
        except Exception as e:
            print(f"Error filtering questions: {e}")
            return False, f"Error filtering questions for exam {exam_id}"

        if exam_questions.empty:
            # Debug: Show available exam IDs
            try:
                available_ids = sorted(questions_df['exam_id'].unique().tolist())
                print(f"Available exam_ids in questions.csv: {available_ids}")
            except:
                pass
            return False, f"No questions found for exam ID {exam_id}"

        # Get exam info with validation
        try:
            if 'id' not in exams_df.columns:
                return False, "Exams file missing id column"
                
            exam_info = exams_df[exams_df['id'].astype(str) == exam_id_str]
            if exam_info.empty:
                return False, f"Exam metadata not found for ID {exam_id}"
        except Exception as e:
            print(f"Error getting exam info: {e}")
            return False, f"Error accessing exam metadata: {str(e)}"

        # Process questions with images
        processed_questions = []
        image_urls = {}
        failed_images = []

        for _, question in exam_questions.iterrows():
            try:
                question_dict = question.to_dict()
                
                # Validate required fields
                if 'id' not in question_dict or not question_dict['id']:
                    print(f"Skipping question with missing ID")
                    continue

                # Process image with timeout protection
                try:
                    image_path = question_dict.get('image_path')
                    if image_path and str(image_path).strip() not in ['', 'nan', 'NaN', 'null', 'None']:
                        print(f"Processing image for Q{question_dict.get('id')}: {image_path}")
                        has_image, image_url = process_question_image_fixed_ssl_safe(question_dict)
                        question_dict['has_image'] = bool(has_image)
                        question_dict['image_url'] = image_url

                        if has_image and image_url:
                            image_urls[str(question_dict.get('id', ''))] = image_url
                        else:
                            failed_images.append(str(image_path))
                    else:
                        question_dict['has_image'] = False
                        question_dict['image_url'] = None
                except Exception as e:
                    print(f"Non-critical image error for Q{question_dict.get('id')}: {e}")
                    question_dict['has_image'] = False
                    question_dict['image_url'] = None

                # Parse correct answers
                try:
                    question_dict['parsed_correct_answer'] = parse_correct_answers(
                        question_dict.get('correct_answer'),
                        question_dict.get('question_type', 'MCQ')
                    )
                except Exception as e:
                    print(f"Error parsing correct answer for Q{question_dict.get('id')}: {e}")
                    question_dict['parsed_correct_answer'] = None

                processed_questions.append(question_dict)

            except Exception as e:
                print(f"Error processing question: {e}")
                continue

        if not processed_questions:
            return False, "No questions could be processed successfully"

        # Store in session with validation
        try:
            cache_key = f'exam_data_{exam_id}'
            session_data = {
                'exam_info': exam_info.iloc[0].to_dict(),
                'questions': processed_questions,
                'image_urls': image_urls,
                'failed_images': failed_images,
                'total_questions': len(processed_questions),
                'loaded_at': datetime.now().isoformat(),
                'exam_id': exam_id
            }
            
            # Validate session data before storing
            if not session_data['exam_info']:
                return False, "Exam info validation failed"
            if not session_data['questions']:
                return False, "Questions validation failed"
                
            try:
                # Limit session data size to prevent crashes
                if len(processed_questions) > 50:
                    # Store only essential data for large exams
                    session_data['questions'] = processed_questions[:50]  # Limit to 50 questions
                    print(f"Limited session storage to 50 questions (total: {len(processed_questions)})")
                
                session[cache_key] = session_data
            except Exception as e:
                print(f"Session storage error: {e}")
                # Try storing minimal data
                try:
                    minimal_data = {
                        'exam_info': exam_info.iloc[0].to_dict(),
                        'questions': processed_questions,
                        'total_questions': len(processed_questions),
                        'exam_id': exam_id
                    }
                    session[cache_key] = minimal_data
                except:
                    return False, "Failed to cache exam data"
            session.permanent = True
            
            print(f"Successfully stored exam data in session for exam {exam_id}")

        except Exception as e:
            print(f"Error storing session data: {e}")
            return False, f"Error caching exam data: {str(e)}"

        load_time = time.time() - start_time
        print(f"Successfully preloaded exam data in {load_time:.2f}s: {len(processed_questions)} questions")

        return True, f"Successfully loaded {len(processed_questions)} questions"

    except Exception as e:
        print(f"Critical error in preload_exam_data_fixed: {e}")
        import traceback
        traceback.print_exc()
        return False, f"Critical system error: {str(e)}"


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
    """Get active (in_progress) attempt for a user and exam"""
    try:
        attempts_df = safe_csv_load_with_recovery('exam_attempts.csv')
        
        if attempts_df is None or attempts_df.empty:
            print(f"No attempts data found for user {user_id}, exam {exam_id}")
            return None

        # Ensure proper data types
        attempts_df['student_id'] = attempts_df['student_id'].astype(str)
        attempts_df['exam_id'] = attempts_df['exam_id'].astype(str)
        attempts_df['status'] = attempts_df['status'].astype(str)
        
        # Find active attempts
        mask = (
            (attempts_df['student_id'] == str(user_id)) &
            (attempts_df['exam_id'] == str(exam_id)) &
            (attempts_df['status'].str.lower() == 'in_progress')
        )
        
        active_attempts = attempts_df[mask]
        
        if active_attempts.empty:
            print(f"No active attempt found for user {user_id}, exam {exam_id}")
            return None
        
        # Get the most recent active attempt
        latest_attempt = active_attempts.iloc[-1].to_dict()
        print(f"Found active attempt {latest_attempt.get('id')} for user {user_id}, exam {exam_id}")
        
        return {
            'id': latest_attempt.get('id'),
            'student_id': latest_attempt.get('student_id'),
            'exam_id': latest_attempt.get('exam_id'),
            'attempt_number': latest_attempt.get('attempt_number', 1),
            'status': latest_attempt.get('status'),
            'start_time': latest_attempt.get('start_time'),
            'end_time': latest_attempt.get('end_time')
        }
        
    except Exception as e:
        print(f"Error getting active attempt: {e}")
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

# Update the ensure_required_files function to include the new CSV
def ensure_required_files():
    """Ensure all required CSV files exist in Google Drive"""
    global drive_service

    if not drive_service:
        print("❌ No Google Drive service for file verification")
        return

    required_files = {
        'users.csv': DRIVE_FILE_IDS['users'],
        'exams.csv': DRIVE_FILE_IDS['exams'],
        'questions.csv': DRIVE_FILE_IDS['questions'],
        'results.csv': DRIVE_FILE_IDS['results'],
        'responses.csv': DRIVE_FILE_IDS['responses'],
        'exam_attempts.csv': DRIVE_FILE_IDS.get('exam_attempts'),
        'requests_raised.csv': DRIVE_FILE_IDS.get('requests_raised')  # Add this line
    }

    for filename, file_id in required_files.items():
        if not file_id or file_id.startswith('YOUR_'):
            print(f"⚠️ {filename}: File ID not configured properly")
            continue
            
        try:
            # Try to get file metadata to check if it exists
            meta = drive_service.files().get(fileId=file_id, fields="id,name,size").execute()
            print(f"✅ Verified {filename}: {meta.get('name')} ({meta.get('size', '0')} bytes)")
        except Exception as e:
            print(f"❌ Error verifying {filename} (ID: {file_id}): {e}")

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
    """Create a secure token for password operations."""
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(hours=1)
    
    # Load existing tokens
    tokens_df = load_csv_with_cache('pw_tokens.csv')
    if tokens_df is None or tokens_df.empty:
        tokens_df = pd.DataFrame(columns=['token', 'email', 'expires_at', 'used', 'created_at', 'type'])
    
    # Add new token
    new_token = {
        'token': token,
        'email': email.lower(),
        'expires_at': expires_at.strftime('%Y-%m-%d %H:%M:%S'),
        'used': False,
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'type': token_type
    }
    
    tokens_df = pd.concat([tokens_df, pd.DataFrame([new_token])], ignore_index=True)
    
    if safe_csv_save_with_retry(tokens_df, 'pw_tokens'):
        return token
    else:
        raise Exception("Failed to save token")

def validate_and_use_token(token: str) -> tuple:
    """Validate a token and mark it as used."""
    try:
        tokens_df = load_csv_with_cache('pw_tokens.csv')
        if tokens_df is None or tokens_df.empty:
            return False, "Invalid token", {}
        
        # Find token
        token_row = tokens_df[tokens_df['token'] == token]
        if token_row.empty:
            return False, "Invalid token", {}
        
        token_data = token_row.iloc[0].to_dict()
        
        # Check if already used
        if token_data['used']:
            return False, "Token has already been used", {}
        
        # Check expiration
        expires_at = pd.to_datetime(token_data['expires_at'])
        if datetime.now() > expires_at:
            return False, "Token has expired", {}
        
        # Mark as used
        tokens_df.loc[tokens_df['token'] == token, 'used'] = True
        safe_csv_save_with_retry(tokens_df, 'pw_tokens')
        
        return True, "Token valid", token_data
        
    except Exception as e:
        print(f"Error validating token: {e}")
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


def calculate_student_analytics(results_df, exams_df, user_id):
    """Calculate analytics data for student"""
    try:
        analytics = {}
        
        if results_df.empty:
            return {}
        
        results_df = results_df.copy()
        results_df['completed_at'] = pd.to_datetime(results_df['completed_at'], errors='coerce')
        results_df = results_df.sort_values('completed_at')
        
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
            if exams_df is not None and not exams_df.empty:
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
            if exams_df is not None and not exams_df.empty:
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

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get('admin_id') and session.get('user_id'):
        flash("You are already logged in as Admin. Please logout first to access User portal.", "warning")
        return redirect(url_for("admin.dashboard"))
    
    if request.method == "POST":
        try:
            identifier = request.form["username"].strip().lower()
            password = request.form["password"].strip()
            client_ip = get_client_ip()

            if not identifier or not password:
                flash("Both username/email and password are required!", "error")
                return redirect(url_for("login"))

            is_allowed, limit_message, attempts_remaining = check_login_attempts(identifier, client_ip)
            if not is_allowed:
                flash(limit_message, "error")
                return redirect(url_for("login"))

            users_df = load_csv_with_cache("users.csv")
            
            if users_df is None or users_df.empty:
                flash("User database unavailable!", "error")
                return redirect(url_for("login"))

            users_df = users_df.fillna('')
            users_df[['username', 'email', 'role']] = users_df[['username', 'email', 'role']].astype(str)

            user_row = users_df[
                (users_df["username"].str.lower() == identifier) |
                (users_df["email"].str.lower() == identifier)
            ]

            if user_row.empty:
                record_failed_login(identifier, client_ip)
                attempts_remaining = check_login_attempts(identifier, client_ip)[2]
                flash(f"Invalid credentials! {max(0, attempts_remaining - 1)} attempts remaining.", "error")
                return redirect(url_for("login"))

            user = user_row.iloc[0].to_dict()
            stored_password = str(user.get("password", ""))
            
            if not stored_password:
                flash("Your account has no password set. Contact system administrator.", "error")
                return redirect(url_for("login"))
            
            password_valid = False
            if is_password_hashed(stored_password):
                password_valid = verify_password(password, stored_password)
            else:
                password_valid = (stored_password == password)

            if not password_valid:
                record_failed_login(identifier, client_ip)
                attempts_remaining = check_login_attempts(identifier, client_ip)[2]
                flash(f"Invalid credentials! {max(0, attempts_remaining - 1)} attempts remaining.", "error")
                return redirect(url_for("login"))

            clear_login_attempts(identifier, client_ip)

            role = str(user.get("role", "")).lower()
            if "user" not in role:
                flash("You don't have User portal access. Contact admin if you need access.", "error")
                return redirect(url_for("login"))

            user_id = int(user["id"])
            
            def background_session_setup():
                try:
                    invalidate_session(user_id)
                    token = generate_session_token()
                    save_session_record({
                        "user_id": user_id,
                        "token": token,
                        "device_info": request.headers.get("User-Agent", "unknown"),
                        "is_exam_active": False
                    })
                    return token
                except Exception as e:
                    print(f"[login] Background session setup error: {e}")
                    return generate_session_token()

            token = background_session_setup()

            session.clear()
            session['user_id'] = user_id
            session['token'] = token
            session['username'] = user.get("username")
            session['full_name'] = user.get("full_name", user.get("username"))
            session.permanent = True
            session.modified = True

            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))

        except KeyError as e:
            print(f"[login] Missing form field: {e}")
            flash("Login form error. Please try again.", "error")
            return redirect(url_for("login"))
        except Exception as e:
            print(f"[login] Unexpected error: {e}")
            flash("A system error occurred. Please try again.", "error")
            return redirect(url_for("login"))

    return render_template("login.html")







@app.route('/api/verify-user', methods=['POST'])
def api_verify_user():
    """API endpoint to verify if user exists"""
    try:
        data = request.get_json()
        if not data or not data.get('username'):
            return jsonify({
                'success': False,
                'message': 'Username or email is required'
            }), 400

        username_or_email = data['username'].strip().lower()
        
        # Load users data with force reload to get latest data
        users_df = load_csv_with_cache('users.csv', force_reload=True)
        if users_df.empty:
            return jsonify({
                'success': False,
                'message': 'User database is unavailable'
            }), 500

        # Search for user by username or email
        users_df['username_lower'] = users_df['username'].astype(str).str.strip().str.lower()
        users_df['email_lower'] = users_df['email'].astype(str).str.strip().str.lower()
        
        user_row = users_df[
            (users_df['username_lower'] == username_or_email) |
            (users_df['email_lower'] == username_or_email)
        ]
        
        if user_row.empty:
            return jsonify({
                'success': False,
                'message': 'User does not exist'
            }), 404
        
        user = user_row.iloc[0]
        
        # Return user info (without sensitive data)
        return jsonify({
            'success': True,
            'user': {
                'id': int(user['id']),
                'username': user['username'],
                'email': user['email'],
                'full_name': user['full_name']
            }
        })
        
    except Exception as e:
        print(f"Error verifying user: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'message': 'System error occurred'
        }), 500



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
    """Enhanced user registration with secure password setup via email."""
    if request.method == 'POST':
        try:
            # Get form data
            email = request.form['email'].strip().lower()
            first_name = request.form.get('first_name', '').strip()
            last_name = request.form.get('last_name', '').strip()

            # Validate inputs
            if not email:
                flash('Please enter your email address.', 'error')
                return redirect(url_for('create_account'))  # Redirect instead of render

            if not first_name:
                flash('Please enter your first name.', 'error')
                return redirect(url_for('create_account'))  # Redirect instead of render

            if not last_name:
                flash('Please enter your last name.', 'error')
                return redirect(url_for('create_account'))  # Redirect instead of render

            # Create full name from first and last name
            full_name = f"{first_name} {last_name}".strip()

            is_valid, error_message = verify_email_exists(email)
            if not is_valid:
                flash(f'Invalid email: {error_message}', 'error')
                return redirect(url_for('create_account'))  # Redirect instead of render

            # Use safe registration with file locking
            with get_file_lock('users'):
                users_df = safe_csv_load_with_recovery('users.csv')

                # Check if email exists
                if not users_df.empty and email.lower() in users_df['email'].str.lower().values:
                    # Email already exists - don't reveal this, just say setup link sent
                    flash('If this email is not already registered, a setup link has been sent. Please check your inbox and spam folder.', 'success')
                    return redirect(url_for('registration_success_generic'))  # Already redirecting

                # Get existing usernames for uniqueness check
                existing_usernames = set()
                if not users_df.empty and 'username' in users_df.columns:
                    existing_usernames = set(users_df['username'].astype(str).str.lower())

                # Generate next ID
                next_id = 1
                if not users_df.empty and 'id' in users_df.columns:
                    next_id = int(users_df['id'].fillna(0).astype(int).max()) + 1

                # Generate unique username using firstname.lastname format
                username = generate_username(full_name, existing_usernames)

                # Create new user data
                new_user = {
                    'id': next_id,
                    'username': username,
                    'email': email,
                    'full_name': full_name,  # Keep storing full_name in CSV as before
                    'password': '',  # Empty password - will be set via email link
                    'role': 'user',
                    'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'last_login': ''  # Add last_login field for consistency
                }

                # Add user to dataframe
                if users_df.empty:
                    users_df = pd.DataFrame([new_user])
                else:
                    users_df = pd.concat([users_df, pd.DataFrame([new_user])], ignore_index=True)

                # Save to CSV
                if safe_csv_save_with_retry(users_df, 'users'):
                    try:
                        # Generate setup token
                        setup_token = create_password_token(email, 'setup')

                        # Send setup email (now includes username)
                        email_sent, email_message = send_password_setup_email(email, full_name, username, setup_token)

                        if email_sent:
                            flash('Account created successfully! Please check your email for setup instructions.', 'success')
                        else:
                            print(f"Failed to send setup email to {email}: {email_message}")
                            flash('Account created, but email sending failed. Please contact admin.', 'warning')

                        return redirect(url_for('registration_success_generic'))  # Already redirecting

                    except Exception as e:
                        print(f"Error sending setup email: {e}")
                        flash('Account created, but email sending failed. Please contact admin.', 'warning')
                        return redirect(url_for('registration_success_generic'))  # Already redirecting
                else:
                    flash('Registration failed. Please try again.', 'error')
                    return redirect(url_for('create_account'))  # Redirect instead of render

        except Exception as e:
            print(f"Registration error: {e}")
            flash('System error occurred. Please try again.', 'error')
            return redirect(url_for('create_account'))  # Redirect instead of render
    
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
    """Password setup route for new users."""
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

            # Update user password
            users_df = load_csv_with_cache('users.csv')
            if users_df is None or users_df.empty:
                flash('User database error.', 'error')
                return redirect(url_for('login'))

            email = token_data['email']
            user_mask = users_df['email'].str.lower() == email.lower()
            if not user_mask.any():
                flash('User not found.', 'error')
                return redirect(url_for('login'))

            # Hash new password and update
            hashed_password = hash_password(new_password)
            users_df.loc[user_mask, 'password'] = hashed_password
            users_df.loc[user_mask, 'updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            if safe_csv_save_with_retry(users_df, 'users'):
                user = users_df[user_mask].iloc[0]
                flash(f'Password set successfully! You can now login with username: {user["username"]}', 'success')
                return redirect(url_for('login'))
            else:
                flash('Failed to set password. Please try again.', 'error')
                return render_template('password_setup_form.html', token=token)

        except Exception as e:
            print(f"Error setting up password: {e}")
            flash('An error occurred. Please try again.', 'error')
            return render_template('password_setup_form.html', token=token)

    # GET request - show form
    # Validate token first (but don't mark as used)
    try:
        tokens_df = load_csv_with_cache('pw_tokens.csv')
        if tokens_df is None or tokens_df.empty:
            flash('Invalid setup link.', 'error')
            return redirect(url_for('login'))
        
        token_row = tokens_df[tokens_df['token'] == token]
        if token_row.empty:
            flash('Invalid setup link.', 'error')
            return redirect(url_for('login'))
        
        token_data = token_row.iloc[0].to_dict()
        
        if token_data['used']:
            flash('This setup link has already been used.', 'error')
            return redirect(url_for('login'))
        
        expires_at = pd.to_datetime(token_data['expires_at'])
        if datetime.now() > expires_at:
            flash('This setup link has expired.', 'error')
            return redirect(url_for('login'))
        
        if token_data.get('type') != 'setup':
            flash('Invalid setup link type.', 'error')
            return redirect(url_for('login'))
    
    except Exception as e:
        print(f"Error validating setup token: {e}")
        flash('Error validating setup link.', 'error')
        return redirect(url_for('login'))
    
    return render_template('password_setup_form.html', token=token, email=token_data.get('email', ''))



@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password_with_token(token):
    """Password reset route for existing users."""
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

            # Update user password
            users_df = load_csv_with_cache('users.csv')
            if users_df is None or users_df.empty:
                flash('User database error.', 'error')
                return redirect(url_for('login'))

            email = token_data['email']
            user_mask = users_df['email'].str.lower() == email.lower()
            if not user_mask.any():
                flash('User not found.', 'error')
                return redirect(url_for('login'))

            # Hash new password and update
            hashed_password = hash_password(new_password)
            users_df.loc[user_mask, 'password'] = hashed_password
            users_df.loc[user_mask, 'updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            if safe_csv_save_with_retry(users_df, 'users'):
                flash('Password updated successfully! You can now login with your new password.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Failed to update password. Please try again.', 'error')
                return render_template('password_reset_form.html', token=token)

        except Exception as e:
            print(f"Error resetting password: {e}")
            flash('An error occurred. Please try again.', 'error')
            return render_template('password_reset_form.html', token=token)

    # GET request - show form
    # Validate token first (but don't mark as used)
    try:
        tokens_df = load_csv_with_cache('pw_tokens.csv')
        if tokens_df is None or tokens_df.empty:
            flash('Invalid reset link.', 'error')
            return redirect(url_for('login'))
        
        token_row = tokens_df[tokens_df['token'] == token]
        if token_row.empty:
            flash('Invalid reset link.', 'error')
            return redirect(url_for('login'))
        
        token_data = token_row.iloc[0].to_dict()
        
        if token_data['used']:
            flash('This reset link has already been used.', 'error')
            return redirect(url_for('login'))
        
        expires_at = pd.to_datetime(token_data['expires_at'])
        if datetime.now() > expires_at:
            flash('This reset link has expired.', 'error')
            return redirect(url_for('login'))
        
        if token_data.get('type') != 'reset':
            flash('Invalid reset link type.', 'error')
            return redirect(url_for('login'))
    
    except Exception as e:
        print(f"Error validating reset token: {e}")
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
    """User dashboard route"""
    try:
        user_id = session.get('user_id')
        print(f"[DASHBOARD] User ID: {user_id}")
        
        # Your existing dashboard code here
        exams_df = load_csv_with_cache('exams.csv')
        results_df = load_csv_with_cache('results.csv')

        upcoming_exams, ongoing_exams, completed_exams = [], [], []

        if not exams_df.empty:
            if 'status' not in exams_df.columns:
                exams_df['status'] = 'upcoming'

            upcoming_exams = exams_df[exams_df['status'] == 'upcoming'].to_dict('records')
            ongoing_exams = exams_df[exams_df['status'] == 'ongoing'].to_dict('records')
            completed_exams = exams_df[exams_df['status'] == 'completed'].to_dict('records')

            # Process results for completed exams
            if not results_df.empty:
                for exam in completed_exams:
                    exam_id = int(exam.get('id', 0))
                    r = results_df[
                        (results_df['student_id'].astype(str) == str(session['user_id'])) &
                        (results_df['exam_id'].astype(str) == str(exam_id))
                        ]
                    if not r.empty:
                        score = r.iloc[0].get('score', 0)
                        max_score = r.iloc[0].get('max_score', 0)
                        grade = r.iloc[0].get('grade', 'N/A')
                        exam['result'] = f"{score}/{max_score} ({grade})" if pd.notna(score) and pd.notna(
                            max_score) else 'Recorded'
                    else:
                        exam['result'] = 'Pending'
            else:
                for exam in completed_exams:
                    exam['result'] = 'Pending'

        return render_template('dashboard.html',
                               upcoming_exams=upcoming_exams,
                               ongoing_exams=ongoing_exams,
                               completed_exams=completed_exams)
        
    except Exception as e:
        print(f"[DASHBOARD] Error: {e}")
        flash("Error loading dashboard. Please try again.", "error")
        return redirect(url_for('login'))

@app.route('/analytics')
@require_user_role
def student_analytics():
    """Student performance analytics dashboard"""
    try:
        user_id = session.get('user_id')
        username = session.get('username', 'Student')
        
        results_df = load_csv_with_cache('results.csv')
        exams_df = load_csv_with_cache('exams.csv')
        
        if results_df is None or results_df.empty:
            flash("No results data available yet.", "info")
            return render_template('student_analytics.html', 
                                 analytics_data={}, 
                                 has_data=False)
        
        student_results = results_df[results_df['student_id'].astype(str) == str(user_id)]
        
        if student_results.empty:
            flash("No exam results found for your account.", "info")
            return render_template('student_analytics.html', 
                                 analytics_data={}, 
                                 has_data=False)
        
        analytics_data = calculate_student_analytics(student_results, exams_df, user_id)
        
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
        # Use cache-loading helper (consistent behaviour across app)
        results_df = load_csv_with_cache('results.csv')
        exams_df = load_csv_with_cache('exams.csv')

        # Defensive: if either DataFrame is None or empty, render page with empty results list
        if results_df is None or (hasattr(results_df, "empty") and results_df.empty):
            # render an empty results page with informative flash
            flash("No results found for your account yet.", "info")
            return render_template("results_history.html", results=[])

        if exams_df is None or (hasattr(exams_df, "empty") and exams_df.empty):
            # We can still show results but won't have exam names; show message and render empty
            flash("Exam metadata missing. Contact admin.", "warning")
            return render_template("results_history.html", results=[])

        student_id = str(session["user_id"])

        # safe column checks
        if "student_id" not in results_df.columns or "exam_id" not in results_df.columns:
            flash("Results file is missing required columns. Contact admin.", "error")
            return render_template("results_history.html", results=[])

        # filter results for this user
        student_results = results_df[results_df["student_id"].astype(str) == student_id]
        if student_results.empty:
            flash("No results found for your account yet.", "info")
            return render_template("results_history.html", results=[])

        # merge with exams to get exam names (safe merge - fill missing names)
        merged = student_results.merge(
            exams_df.rename(columns={"id": "exam_id", "name": "exam_name"}),
            left_on="exam_id", right_on="exam_id", how="left", suffixes=("_result", "_exam")
        )

        results = []
        for _, row in merged.iterrows():
            # safe extraction using .get / fallback defaults
            completed_at = row.get("completed_at") or row.get("completed_at_result") or ""
            exam_name = row.get("exam_name") or row.get("name") or f"Exam {row.get('exam_id')}"
            # other numeric fields may be missing; coerce to sensible defaults
            score = row.get("score") if row.get("score") is not None else 0
            max_score = row.get("max_score") if row.get("max_score") is not None else row.get("total_questions", 0)
            percentage = float(row.get("percentage") or 0.0)
            results.append({
                "id": int(row.get("id_result") or row.get("id") or 0),
                "exam_id": int(row.get("exam_id") or 0),
                "exam_name": exam_name,
                "subject": row.get("name") or exam_name,
                "completed_at": completed_at,
                "score": score,
                "max_score": max_score,
                "percentage": round(percentage, 2),
                "grade": row.get("grade") or "N/A",
                "time_taken_minutes": row.get("time_taken_minutes") or 0,
                "correct_answers": int(row.get("correct_answers") or 0),
                "incorrect_answers": int(row.get("incorrect_answers") or 0),
                "unanswered_questions": int(row.get("unanswered_questions") or 0),
            })

        # Sort by completed_at (safe parsing)
        def _parse_date_safe(s):
            try:
                return datetime.strptime(str(s), "%Y-%m-%d %H:%M:%S")
            except Exception:
                return datetime.min

        results.sort(key=lambda r: _parse_date_safe(r.get("completed_at", "")), reverse=True)

        return render_template("results_history.html", results=results)

    except Exception as e:
        print("Error in results_history:", str(e))
        import traceback
        traceback.print_exc()
        flash("Could not load results history.", "danger")
        return render_template("results_history.html", results=[])




@app.route('/exam-instructions/<int:exam_id>')
@require_user_role
def exam_instructions(exam_id):
    exams_df = load_csv_with_cache('exams.csv')
    if exams_df.empty:
        flash('No exams available.', 'error')
        return redirect(url_for('dashboard'))

    exam = exams_df[exams_df['id'].astype(str) == str(exam_id)]
    if exam.empty:
        flash('Exam not found!', 'error')
        return redirect(url_for('dashboard'))

    exam_data = exam.iloc[0].to_dict()

    # defaults
    if 'positive_marks' not in exam_data or pd.isna(exam_data.get('positive_marks')):
        exam_data['positive_marks'] = 1
    if 'negative_marks' not in exam_data or pd.isna(exam_data.get('negative_marks')):
        exam_data['negative_marks'] = 0

    user_id = session.get('user_id')
    active_attempt = get_active_attempt(user_id, exam_id)

    # compute attempts left using exam_attempts.csv (safe load)
    attempts_df = load_csv_with_cache('exam_attempts.csv')
    if attempts_df is None or attempts_df.empty:
        attempts_df = pd.DataFrame(columns=['id','student_id','exam_id','attempt_number','status','start_time','end_time'])

    # normalize
    attempts_df = attempts_df.fillna('')
    user_exam_mask = (attempts_df['student_id'].astype(str) == str(user_id)) & (attempts_df['exam_id'].astype(str) == str(exam_id))
    completed_count = 0
    if not attempts_df.empty and user_exam_mask.any():
        completed_count = int(attempts_df.loc[user_exam_mask & (attempts_df['status'].astype(str).str.lower()=='completed')].shape[0])

    try:
        max_attempts = int(exam_data.get('max_attempts') or 0)
    except Exception:
        max_attempts = 0  # 0 = unlimited

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
        # max_attempts = 0 means unlimited
        attempts_left = None  # Will show as unlimited
        can_start = True

    # Override can_start if there's already an active attempt
    if active_attempt:
        can_start = False  # Should show resume instead

    return render_template(
        'exam_instructions.html',
        exam=exam_data,
        active_attempt=active_attempt,
        attempts_left=attempts_left,
        max_attempts=max_attempts,
        attempts_exhausted=attempts_exhausted,
        can_start=can_start  # Add this new variable
    )



@app.route('/start-exam/<int:exam_id>', methods=['POST'])
@require_user_role
def start_exam(exam_id):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"success": False, "message": "Authentication error."})

    try:
        exams_df = load_csv_with_cache('exams.csv')
        if exams_df.empty:
            return jsonify({"success": False, "message": "No exams available."})

        exam = exams_df[exams_df['id'].astype(str) == str(exam_id)]
        if exam.empty:
            return jsonify({"success": False, "message": "Exam not found."})

        exam_data = exam.iloc[0].to_dict()

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

        attempts_df = load_csv_with_cache('exam_attempts.csv')
        if attempts_df is None or attempts_df.empty:
            attempts_df = pd.DataFrame(columns=['id','student_id','exam_id','attempt_number','status','start_time','end_time'])

        try:
            max_attempts = int(exam_data.get('max_attempts', 0))
        except:
            max_attempts = 0

        if max_attempts > 0:
            user_exam_attempts = attempts_df[
                (attempts_df['student_id'].astype(str) == str(user_id)) &
                (attempts_df['exam_id'].astype(str) == str(exam_id)) &
                (attempts_df['status'].astype(str).str.lower() == 'completed')
            ]
            if len(user_exam_attempts) >= max_attempts:
                return jsonify({
                    "success": False,
                    "message": f"Maximum attempts ({max_attempts}) reached for this exam."
                })

        try:
            user_exam_mask = (attempts_df['student_id'].astype(str) == str(user_id)) & (attempts_df['exam_id'].astype(str) == str(exam_id))
            if user_exam_mask.any():
                attempt_number = int(attempts_df.loc[user_exam_mask, 'attempt_number'].max()) + 1
            else:
                attempt_number = 1

            next_id = 1 if attempts_df.empty else int(attempts_df['id'].max()) + 1
            start_iso = pd.Timestamp.now(tz="UTC").strftime("%Y-%m-%d %H:%M:%S")

            new_attempt = pd.DataFrame([{
                'id': next_id,
                'student_id': str(user_id),
                'exam_id': str(exam_id),
                'attempt_number': attempt_number,
                'status': 'in_progress',
                'start_time': start_iso,
                'end_time': None
            }])

            attempts_df = pd.concat([attempts_df, new_attempt], ignore_index=True)
            
            with get_file_lock('exam_attempts'):
                persist_attempts_df(attempts_df)

            session_data = {
                'latest_attempt_id': int(next_id),
                'exam_start_time': start_iso,
                'exam_answers': {},
                'marked_for_review': [],
                'timer_reset_flag': True,
                'attempt_number': attempt_number
            }
            
            for key, value in session_data.items():
                session[key] = value
            session.permanent = True
            session.modified = True

            try:
                set_exam_active(user_id, session.get('token'), exam_id=exam_id, result_id=next_id, is_active=True)
            except Exception as e:
                print(f"Error setting exam active: {e}")

            print(f"Successfully created new attempt {next_id} (#{attempt_number}) for user {user_id}, exam {exam_id}")
            
            return jsonify({
                "success": True, 
                "redirect_url": url_for('exam_page', exam_id=exam_id), 
                "resumed": False,
                "message": "Exam started successfully",
                "attempt_id": next_id,
                "attempt_number": attempt_number,
                "fresh_start": True
            })

        except Exception as e:
            print(f"Error creating new attempt: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({
                "success": False, 
                "message": f"Error creating exam attempt: {str(e)}",
                "error_type": "attempt_creation_failed"
            }), 500

    except Exception as e:
        print(f"Critical error in start_exam: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False, 
            "message": "System error occurred. Please try again or contact support."
        }), 500


@app.route('/api/exam-attempts-status/<int:exam_id>')
@require_user_role
def api_exam_attempts_status(exam_id):
    """
    CRASH-SAFE API endpoint for exam attempts status
    """
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'not_authenticated'}), 401

    try:
        # SAFE: Load exam info
        try:
            exams_df = load_csv_with_cache('exams.csv')
            if exams_df is None or exams_df.empty:
                return jsonify({'error': 'exam_data_unavailable'}), 500
            
            exam_row = exams_df[exams_df['id'].astype(str) == str(exam_id)]
            if exam_row.empty:
                return jsonify({'error': 'exam_not_found'}), 404
            
            exam_info = exam_row.iloc[0].to_dict()
            max_attempts = int(exam_info.get('max_attempts', 0) or 0)
            
        except Exception as e:
            print(f"Error loading exam info: {e}")
            return jsonify({'error': 'exam_info_error', 'message': str(e)}), 500

        # SAFE: Load attempts with reduced retries
        completed_attempts = 0
        active_exists = False
        
        try:
            attempts_df = safe_csv_load_with_recovery('exam_attempts.csv', max_retries=1)
            
            if attempts_df is not None and hasattr(attempts_df, 'empty'):
                if attempts_df.empty and len(attempts_df.columns) > 0:
                    # Header-only file
                    print("Header-only exam_attempts file - no attempts yet")
                    completed_attempts = 0
                    active_exists = False
                elif not attempts_df.empty:
                    # Has data rows
                    try:
                        attempts_df = attempts_df.fillna('')
                        attempts_df['student_id'] = attempts_df['student_id'].astype(str)
                        attempts_df['exam_id'] = attempts_df['exam_id'].astype(str)
                        attempts_df['status'] = attempts_df['status'].astype(str)

                        completed_mask = (
                            (attempts_df['student_id'] == str(user_id)) &
                            (attempts_df['exam_id'] == str(exam_id)) &
                            (attempts_df['status'].str.lower() == 'completed')
                        )
                        completed_attempts = int(completed_mask.sum())

                        inprog_mask = (
                            (attempts_df['student_id'] == str(user_id)) &
                            (attempts_df['exam_id'] == str(exam_id)) &
                            (attempts_df['status'].str.lower() == 'in_progress')
                        )
                        active_exists = bool(inprog_mask.any())
                        
                    except Exception as e:
                        print(f"Error processing attempts data: {e}")
                        completed_attempts = 0
                        active_exists = False
                else:
                    # Completely empty
                    completed_attempts = 0
                    active_exists = False
            else:
                completed_attempts = 0
                active_exists = False
                
        except Exception as e:
            print(f"Error loading attempts: {e}")
            completed_attempts = 0
            active_exists = False

        # SAFE: Calculate attempts left
        attempts_left = None
        if max_attempts <= 0:
            attempts_left = -1  # unlimited
        else:
            attempts_left = max(0, max_attempts - completed_attempts)

        return jsonify({
            'attempts_left': attempts_left,
            'max_attempts': max_attempts,
            'completed_attempts': completed_attempts,
            'active_attempt_exists': bool(active_exists)
        })

    except Exception as e:
        print(f"Critical error in api_exam_attempts_status: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'error': 'server_error', 
            'message': 'System error occurred'
        }), 500




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
    """API endpoint to preload exam data - ENHANCED with better error handling"""
    try:
        # Check if already cached and valid
        cached_data = get_cached_exam_data(exam_id)
        if cached_data and cached_data.get('exam_id') == exam_id:
            return jsonify({
                'success': True,
                'message': f"Using cached data with {cached_data['total_questions']} questions",
                'exam_id': exam_id,
                'cached': True,
                'question_count': cached_data['total_questions']
            })

        # Attempt preload with detailed error reporting
        success, message = preload_exam_data_fixed(exam_id)
        
        status_code = 200 if success else 400
        response_data = {
            'success': success,
            'message': message,
            'exam_id': exam_id,
            'cached': False
        }
        
        # Add diagnostic info for failures
        if not success:
            # Check if questions file exists
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
        print(f"Error in preload route: {e}")
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
        print(f"Loading SPA exam page for exam_id: {exam_id}, user_id: {user_id}")

        # Check for active attempt
        active_attempt = get_active_attempt(user_id, exam_id)
        if active_attempt:
            print(f"Found active attempt: {active_attempt}")
            session['latest_attempt_id'] = int(active_attempt.get('id', 0))
            session['exam_start_time'] = active_attempt.get('start_time')
            if 'exam_answers' not in session:
                session['exam_answers'] = {}
            if 'marked_for_review' not in session:
                session['marked_for_review'] = []
            session.modified = True

        # Get cached exam data
        cached_data = get_cached_exam_data(exam_id)
        if not cached_data:
            print(f"No cached data found, preloading for exam {exam_id}")
            success, message = preload_exam_data_fixed(exam_id)
            if not success:
                flash(f"Unable to load exam data: {message}", "error")
                return redirect(url_for('dashboard'))
            cached_data = get_cached_exam_data(exam_id)

        if not cached_data:
            flash("Unable to load exam data. Please restart the exam.", "error")
            return redirect(url_for('dashboard'))

        exam_data = cached_data.get('exam_info', {})
        questions = cached_data.get('questions', [])

        if not questions:
            flash("No questions found for this exam.", "error") 
            return redirect(url_for('dashboard'))

        # Initialize session data if needed
        if 'exam_answers' not in session:
            session['exam_answers'] = {}
        if 'marked_for_review' not in session:
            session['marked_for_review'] = []

        # Calculate remaining time
        remaining_seconds = 3600
        is_fresh_start = False
        
        session_attempt_id = session.get('latest_attempt_id')
        session_start_time = session.get('exam_start_time')
        
        if active_attempt and session_start_time:
            try:
                start_dt = pd.to_datetime(session_start_time)
                if start_dt.tzinfo is None:
                    start_dt = start_dt.tz_localize("UTC")
                now = pd.Timestamp.now(tz="UTC")
                
                duration_secs = int(float(exam_data.get('duration', 60)) * 60)
                elapsed = (now - start_dt).total_seconds()
                remaining_seconds = max(0, duration_secs - int(elapsed))
                print(f"Resume: calculated remaining time: {remaining_seconds}s")
                
                if remaining_seconds <= 0:
                    print("Exam time expired - auto submitting")
                    try:
                        update_exam_attempt_status(user_id, exam_id, 'completed')
                        session.pop('latest_attempt_id', None)
                        session.pop('exam_start_time', None)
                        flash("Your exam time has expired.", "warning")
                        return redirect(url_for('exam_instructions', exam_id=exam_id))
                    except Exception as e:
                        print(f"Error auto-submitting expired exam: {e}")
                        
            except Exception as e:
                print(f"Error calculating remaining time: {e}")
                duration_secs = int(float(exam_data.get('duration', 60)) * 60)
                remaining_seconds = duration_secs
        else:
            duration_secs = int(float(exam_data.get('duration', 60)) * 60)
            remaining_seconds = duration_secs
            is_fresh_start = True

        # Start from first question for SPA
        current_index = 0
        selected_answer = session.get('exam_answers', {}).get(str(questions[0].get('id'))) if questions else None

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

        print(f"Successfully loaded SPA exam page: {len(questions)} questions, remaining: {remaining_seconds}s")

        return render_template(
            'exam_page.html',
            exam=exam_data,
            question=questions[0] if questions else {},
            current_index=current_index,
            selected_answer=selected_answer,
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
        print(f"ERROR in exam_page: {e}")
        import traceback
        traceback.print_exc()
        flash("Error loading exam page.", "error")
        return redirect(url_for('dashboard'))        









@app.route('/submit-exam/<int:exam_id>', methods=['GET', 'POST'])
@require_user_role
def submit_exam(exam_id):
    if request.method == 'GET':
        return redirect(url_for('exam_page', exam_id=exam_id))
    
    user_id = session.get('user_id')
    token = session.get('token')
    
    if not user_id:
        flash("Authentication error. Please login again.", "error")
        return redirect(url_for('login'))

    try:
        cached_data = None
        try:
            cached_data = get_cached_exam_data(exam_id)
            if not cached_data:
                success, message = preload_exam_data_fixed(exam_id)
                if success:
                    cached_data = get_cached_exam_data(exam_id)
        except Exception as e:
            print(f"Error getting cached exam data: {e}")
            
        if not cached_data:
            flash("Exam session expired. Please contact administrator.", "error")
            return redirect(url_for('dashboard'))
            
        try:
            exam_data = cached_data['exam_info']
            questions = cached_data['questions']
        except (KeyError, TypeError) as e:
            print(f"Error extracting exam data: {e}")
            flash("Invalid exam data. Please contact support.", "error")
            return redirect(url_for('dashboard'))

        if not questions:
            flash("No questions found for this exam.", "error")
            return redirect(url_for('dashboard'))

        answers = session.get('exam_answers', {})
        
        total_questions = len(questions)
        correct_answers = 0
        incorrect_answers = 0
        unanswered_questions = 0
        total_score = 0.0
        max_possible_score = 0.0

        for question in questions:
            question_id = str(question.get('id', ''))
            correct_answer = str(question.get('correct_answer', '')).strip()
            user_answer = answers.get(question_id)
            question_type = question.get('question_type', 'MCQ')
            
            try:
                question_positive_marks = float(question.get('positive_marks', 1) or 1)
            except (ValueError, TypeError):
                question_positive_marks = 1.0
                
            try:
                question_negative_marks = float(question.get('negative_marks', 0) or 0)
            except (ValueError, TypeError):
                question_negative_marks = 0.0
            
            max_possible_score += question_positive_marks
            
            if not user_answer:
                unanswered_questions += 1
            else:
                is_correct = False
                
                if question_type == 'MCQ':
                    is_correct = user_answer.strip().upper() == correct_answer.upper()
                elif question_type == 'MSQ':
                    if isinstance(user_answer, list):
                        user_set = set(ans.strip().upper() for ans in user_answer)
                    else:
                        user_set = set(user_answer.strip().upper().split(','))
                    correct_set = set(correct_answer.upper().split(','))
                    is_correct = user_set == correct_set
                elif question_type == 'NUMERIC':
                    try:
                        user_val = float(user_answer)
                        correct_val = float(correct_answer)
                        tolerance = float(question.get('tolerance', 0.1) or 0.1)
                        is_correct = abs(user_val - correct_val) <= tolerance
                    except (ValueError, TypeError):
                        is_correct = False
                
                if is_correct:
                    correct_answers += 1
                    total_score += question_positive_marks
                else:
                    incorrect_answers += 1
                    total_score -= question_negative_marks

        total_score = max(0, total_score)
        
        start_time_str = session.get('exam_start_time')
        time_taken_minutes = 0
        
        if start_time_str:
            try:
                start_ts = pd.to_datetime(start_time_str)
                now_ts = pd.Timestamp.now(tz="UTC")
                if start_ts.tz is None or start_ts.tzinfo is None:
                    start_ts = start_ts.tz_localize("UTC")
                time_taken_seconds = max(0, (now_ts - start_ts).total_seconds())
                time_taken_minutes = round(time_taken_seconds / 60, 2)
            except Exception as e:
                print(f"Error calculating time taken: {e}")
                time_taken_minutes = 0

        percentage = round((total_score / max_possible_score) * 100, 2) if max_possible_score > 0 else 0.0
        
        def calculate_grade(p):
            if p >= 90: return "A+"
            elif p >= 85: return "A"
            elif p >= 80: return "A-"
            elif p >= 75: return "B+"
            elif p >= 70: return "B"
            elif p >= 65: return "B-"
            elif p >= 60: return "C+"
            elif p >= 55: return "C"
            elif p >= 50: return "C-"
            elif p >= 40: return "D"
            else: return "F"
        
        grade = calculate_grade(percentage)
        completed_at = datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S")
        
        results_df = safe_csv_load_with_recovery('results.csv')
        if results_df is None:
            results_df = pd.DataFrame()

        responses_df = safe_csv_load_with_recovery('responses.csv')
        if responses_df is None:
            responses_df = pd.DataFrame()

        new_result_id = 1 if results_df.empty else int(results_df['id'].max()) + 1
        
        new_result = {
            "id": new_result_id,
            "student_id": user_id,
            "exam_id": exam_id,
            "score": int(total_score),
            "total_questions": float(total_questions),
            "correct_answers": correct_answers,
            "incorrect_answers": incorrect_answers,
            "unanswered_questions": unanswered_questions,
            "max_score": int(max_possible_score),
            "percentage": float(percentage),
            "grade": str(grade),
            "time_taken_minutes": float(time_taken_minutes),
            "completed_at": completed_at
        }

        new_result_df = pd.DataFrame([new_result])
        results_df = pd.concat([results_df, new_result_df], ignore_index=True)

        for question in questions:
            question_id = str(question.get('id', ''))
            user_answer = answers.get(question_id, '')
            correct_answer = str(question.get('correct_answer', ''))
            question_type = question.get('question_type', 'MCQ')
            
            try:
                q_positive = float(question.get('positive_marks', 1) or 1)
            except (ValueError, TypeError):
                q_positive = 1.0
                
            try:
                q_negative = float(question.get('negative_marks', 0) or 0)
            except (ValueError, TypeError):
                q_negative = 0.0
            
            is_correct = False
            if user_answer:
                if question_type == 'MCQ':
                    is_correct = user_answer.strip().upper() == correct_answer.upper()
                elif question_type == 'MSQ':
                    if isinstance(user_answer, list):
                        user_set = set(ans.strip().upper() for ans in user_answer)
                    else:
                        user_set = set(user_answer.strip().upper().split(','))
                    correct_set = set(correct_answer.upper().split(','))
                    is_correct = user_set == correct_set
                elif question_type == 'NUMERIC':
                    try:
                        user_val = float(user_answer)
                        correct_val = float(correct_answer)
                        tolerance = float(question.get('tolerance', 0.1) or 0.1)
                        is_correct = abs(user_val - correct_val) <= tolerance
                    except (ValueError, TypeError):
                        is_correct = False
            
            response_id = 1 if responses_df.empty else int(responses_df['id'].max()) + 1
            
            response_record = {
                "id": response_id,
                "result_id": new_result_id,
                "exam_id": exam_id,
                "question_id": int(question_id),
                "given_answer": str(user_answer) if user_answer else '',
                "correct_answer": str(correct_answer),
                "is_correct": str(is_correct).lower(),
                "marks_obtained": float(q_positive if is_correct else (-q_negative if user_answer else 0)),
                "question_type": str(question_type),
                "is_attempted": str(bool(user_answer)).lower()
            }
            
            responses_df = pd.concat([responses_df, pd.DataFrame([response_record])], ignore_index=True)

        try:
            persist_results_df(results_df)
            persist_responses_df(responses_df)
            print(f"Successfully saved results and responses for user {user_id}, exam {exam_id}")
        except Exception as e:
            print(f"Error in atomic save: {e}")
            flash("Critical error saving results. Please contact support immediately.", "error")
            return redirect(url_for('exam_page', exam_id=exam_id))

        try:
            session['latest_result_id'] = int(new_result_id)
        except Exception as e:
            print(f"Error setting latest_result_id in session: {e}")

        try:
            attempt_id_for_update = session.get('latest_attempt_id')
            if attempt_id_for_update:
                try:
                    ok, info = update_exam_attempt_by_id(attempt_id_for_update, 'completed')
                    if not ok:
                        update_exam_attempt_status(user_id, exam_id, 'completed')
                except Exception as e:
                    print(f"Error updating attempt status: {e}")
                    update_exam_attempt_status(user_id, exam_id, 'completed')
            else:
                update_exam_attempt_status(user_id, exam_id, 'completed')
        except Exception as e:
            print(f"CRITICAL: Failed to update attempt status: {e}")

        try:
            set_exam_active(user_id, token, is_active=False)
        except Exception as e:
            print(f"Error updating session active flag: {e}")

        try:
            session_keys_to_clear = [
                'exam_answers', 'marked_for_review', 'exam_start_time', 
                'exam_remaining_time', 'latest_attempt_id'
            ]
            for key in session_keys_to_clear:
                session.pop(key, None)
                
            keys_to_remove = []
            for key in list(session.keys()):
                if key.startswith('exam_data_') or key.startswith(f'exam_{exam_id}'):
                    keys_to_remove.append(key)
            for key in keys_to_remove:
                session.pop(key, None)
            session.modified = True
        except Exception as e:
            print(f"Error clearing session: {e}")

        flash('Exam submitted successfully!', 'success')
        return redirect(url_for('result', exam_id=exam_id, result_id=new_result_id))
        
    except Exception as e:
        print(f"Critical error in submit_exam: {e}")
        import traceback
        traceback.print_exc()
        flash('Critical error during submission. Please contact support.', 'error')
        try:
            return redirect(url_for('dashboard'))
        except:
            return render_template('error.html', error_code=500, error_message="Critical system error"), 500



@app.route('/api/emergency-sync-exam/<int:exam_id>', methods=['POST'])
@require_user_role
def emergency_sync_exam(exam_id):
    try:
        user_id = session.get('user_id')
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        # Update session with latest data
        session['exam_answers'] = data.get('answers', {})
        session['marked_for_review'] = data.get('markedForReview', [])
        
        # Update remaining time if provided
        if 'timeRemaining' in data:
            # Get exam duration from cached data
            cached_data = get_cached_exam_data(exam_id)
            if cached_data and 'exam_info' in cached_data:
                exam_duration_minutes = int(float(cached_data['exam_info'].get('duration', 60)))
                elapsed_time = (exam_duration_minutes * 60) - data['timeRemaining']
                new_start_time = pd.Timestamp.now(tz="UTC") - pd.Timedelta(seconds=elapsed_time)
                session['exam_start_time'] = new_start_time.isoformat()
        
        # Ensure attempt remains active
        active_attempt = get_active_attempt(user_id, exam_id)
        if active_attempt and active_attempt['status'] != 'completed':
            # Keep attempt alive
            print(f"Emergency sync for user {user_id}, exam {exam_id} - keeping attempt active")
        
        # Mark session as modified to ensure persistence
        session.modified = True
        
        return jsonify({'success': True, 'message': 'Emergency sync completed'})
        
    except Exception as e:
        print(f"Emergency sync error: {e}")
        return jsonify({'error': 'Emergency sync failed'}), 500



@app.route('/result/<int:exam_id>', defaults={'result_id': None})
@app.route('/result/<int:exam_id>/<int:result_id>')
@require_user_role
def result(exam_id, result_id):
    try:
        results_df = safe_csv_load_with_recovery('results.csv')
        exams_df = load_csv_with_cache('exams.csv')
        if results_df is None or exams_df is None:
            flash('Result not found!', 'error')
            return redirect(url_for('dashboard'))
        user_id = int(session['user_id'])
        if result_id:
            r = results_df[
                (results_df['id'].astype('Int64') == int(result_id)) &
                (results_df['student_id'].astype('Int64') == user_id) &
                (results_df['exam_id'].astype('Int64') == int(exam_id))
            ]
        else:
            latest_result_id = session.get('latest_result_id')
            if latest_result_id:
                r = results_df[
                    (results_df['id'].astype('Int64') == int(latest_result_id)) &
                    (results_df['student_id'].astype('Int64') == user_id) &
                    (results_df['exam_id'].astype('Int64') == int(exam_id))
                ]
            else:
                r = results_df[
                    (results_df['student_id'].astype('Int64') == user_id) &
                    (results_df['exam_id'].astype('Int64') == int(exam_id))
                ].sort_values('id', ascending=False).head(1)
        if r is None or r.empty:
            flash('Result not found!', 'error')
            return redirect(url_for('dashboard'))
        r = r.reset_index(drop=True)
        result_data = r.iloc[0].to_dict()
        exam = exams_df[exams_df['id'].astype(str) == str(exam_id)]
        if exam is None or exam.empty:
            flash("Exam details not found.", "error")
            return redirect(url_for('dashboard'))
        exam_data = exam.iloc[0].to_dict()
        return render_template('result.html', result=result_data, exam=exam_data, from_history=(request.args.get("from_history", "0") == "1"))
    except Exception as e:
        print("Error loading result:", e)
        flash("Error loading result page.", "error")
        return redirect(url_for('dashboard'))



@app.route('/response/<int:exam_id>', defaults={'result_id': None})
@app.route('/response/<int:exam_id>/<int:result_id>')
@require_user_role
def response_page(exam_id, result_id):
    """Response analysis page using existing CSV columns only"""
    from_history = request.args.get("from_history", "0") == "1"
    try:
        results_df = load_csv_with_cache('results.csv')
        responses_df = load_csv_with_cache('responses.csv')
        exams_df = load_csv_with_cache('exams.csv')

        # Defensive checks
        if results_df is None or (hasattr(results_df, "empty") and results_df.empty):
            flash('No results available.', 'info')
            return redirect(url_for('dashboard'))
        if responses_df is None or (hasattr(responses_df, "empty") and responses_df.empty):
            flash('No responses available.', 'info')
            return redirect(url_for('dashboard'))
        if exams_df is None or (hasattr(exams_df, "empty") and exams_df.empty):
            flash('Exam metadata missing. Contact admin.', 'warning')
            return redirect(url_for('dashboard'))

        user_id = int(session['user_id'])

        # If specific attempt (from history)
        if result_id:
            user_results = results_df[
                (results_df['id'].astype('Int64') == int(result_id)) &
                (results_df['student_id'].astype('Int64') == user_id) &
                (results_df['exam_id'].astype('Int64') == int(exam_id))
            ]
        else:
            # Otherwise latest attempt
            user_results = results_df[
                (results_df['student_id'].astype('Int64') == user_id) &
                (results_df['exam_id'].astype('Int64') == int(exam_id))
            ].sort_values('id', ascending=False).head(1)

        if user_results.empty:
            flash('Response not found!', 'error')
            return redirect(url_for('dashboard'))

        result_record = user_results.iloc[0]
        result_id = int(result_record['id'])
        result_data = result_record.to_dict()

        # Get exam data
        exam_record = exams_df[exams_df['id'].astype('Int64') == int(exam_id)]
        if exam_record.empty:
            flash('Exam not found!', 'error')
            return redirect(url_for('dashboard'))
        exam_data = exam_record.iloc[0].to_dict()

        # Get responses for this result - using EXISTING columns
        user_responses = responses_df[
            responses_df['result_id'].astype('Int64') == result_id
        ].sort_values('question_id')

        if user_responses.empty:
            flash('No detailed responses saved for this result.', 'info')
            return redirect(url_for('dashboard'))

        # Get questions data
        questions_df = load_csv_with_cache('questions.csv')
        questions_dict = {}
        if questions_df is not None and not questions_df.empty:
            for _, q in questions_df.iterrows():
                questions_dict[int(q['id'])] = q.to_dict()

        # Build response data using EXISTING columns only
        question_responses = []
        for _, response in user_responses.iterrows():
            qid = int(response['question_id'])
            qdata = questions_dict.get(qid, {})

            if not qdata:
                continue

            # Sanitize question + options
            qdata['question_text'] = sanitize_for_display(qdata.get('question_text', ''))
            qdata['option_a'] = sanitize_for_display(qdata.get('option_a', ''))
            qdata['option_b'] = sanitize_for_display(qdata.get('option_b', ''))
            qdata['option_c'] = sanitize_for_display(qdata.get('option_c', ''))
            qdata['option_d'] = sanitize_for_display(qdata.get('option_d', ''))

            # Use existing CSV column names: given_answer, correct_answer, question_type, is_correct, marks_obtained, is_attempted
            given_answer_str = str(response.get('given_answer') or '')
            correct_answer_str = str(response.get('correct_answer') or '')
            qtype = str(response.get('question_type') or 'MCQ')
            
            print(f"Question {qid}: question_type = {qtype}, given_answer = {given_answer_str}")

            # Parse answers
            try:
                if qtype == 'MSQ' and given_answer_str.strip():
                    if given_answer_str.startswith('[') and given_answer_str.endswith(']'):
                        given_answer = json.loads(given_answer_str)
                    else:
                        given_answer = [ans.strip() for ans in given_answer_str.split(',') if ans.strip()]
                else:
                    given_answer = given_answer_str if given_answer_str not in ['None', '', None] else None
            except Exception:
                given_answer = given_answer_str if given_answer_str not in ['None', '', None] else None

            try:
                if qtype == 'MSQ' and correct_answer_str.strip():
                    if correct_answer_str.startswith('[') and correct_answer_str.endswith(']'):
                        correct_answer = json.loads(correct_answer_str)
                    else:
                        correct_answer = [ans.strip() for ans in correct_answer_str.split(',') if ans.strip()]
                else:
                    correct_answer = correct_answer_str if correct_answer_str not in ['None', '', None] else None
            except Exception:
                correct_answer = correct_answer_str if correct_answer_str not in ['None', '', None] else None

            # Get values from existing columns
            is_attempted = str(response.get('is_attempted', 'true')).lower() == 'true'
            is_correct = str(response.get('is_correct', 'false')).lower() == 'true'
            marks_obtained = float(response.get('marks_obtained', 0) or 0)

            response_data = {
                'question': qdata,
                'given_answer': given_answer,
                'correct_answer': correct_answer,
                'is_correct': is_correct,
                'is_attempted': is_attempted,
                'marks_obtained': marks_obtained,
                'question_type': qtype
            }
            question_responses.append(response_data)

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
        flash('Error loading response analysis.', 'error')
        return redirect(url_for('dashboard'))


@app.route('/response-pdf/<int:exam_id>')
@require_user_role
def response_pdf(exam_id):
    """Complete PDF using ReportLab - handles all Unicode"""
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
        
        # Get all your data (same as before)
        exams_df = load_csv_with_cache('exams.csv')
        exam_info = exams_df[exams_df['id'] == exam_id]
        if exam_info.empty:
            flash('Exam not found.', 'error')
            return redirect(url_for('dashboard'))
        
        exam = exam_info.iloc[0]
        
        results_df = load_csv_with_cache('results.csv')
        user_result = results_df[
            (results_df['student_id'] == user_id) & 
            (results_df['exam_id'] == exam_id)
        ].tail(1)
        
        if user_result.empty:
            flash('No results found.', 'error')
            return redirect(url_for('dashboard'))
        
        result = user_result.iloc[0]
        result_id = result['id']
        
        responses_df = load_csv_with_cache('responses.csv')
        user_responses = responses_df[
            responses_df['result_id'] == result_id
        ].sort_values('question_id')
        
        questions_df = load_csv_with_cache('questions.csv')
        
        # Create PDF
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=50, leftMargin=50, topMargin=50, bottomMargin=50)
        
        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle('CustomTitle', parent=styles['Title'], fontSize=18, textColor=colors.HexColor('#2c3e50'), spaceAfter=20, alignment=TA_CENTER)
        heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'], fontSize=14, textColor=colors.HexColor('#2c3e50'), spaceAfter=10)
        
        story = []
        
        # Title
        story.append(Paragraph("Exam Response Analysis", title_style))
        
        # Header info
        header_data = [
            ['Exam:', str(exam['name'])],
            ['Student:', str(full_name)],
            ['Score:', f"{result['score']}/{result['max_score']} ({result['percentage']:.1f}%)"],
            ['Grade:', str(result['grade'])]
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
        for idx, response in user_responses.iterrows():
            question_id = response['question_id']
            question_row = questions_df[questions_df['id'] == question_id]
            
            if question_row.empty:
                continue
                
            question = question_row.iloc[0]
            
            # Question header
            story.append(Paragraph(f"Question {question_id}", heading_style))
            
            # Question text - ReportLab handles Unicode automatically
            question_text = str(question.get('question_text', ''))
            story.append(Paragraph(f"<b>Question:</b> {question_text}", styles['Normal']))
            story.append(Spacer(1, 10))
            
            # Options for MCQ/MSQ
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
                    if option_text and str(option_text).strip() and str(option_text) != 'nan':
                        story.append(Paragraph(f"<b>{label}.</b> {option_text}", styles['Normal']))
                
                story.append(Spacer(1, 10))
            
            # Answers
            given_answer = str(response.get('given_answer', 'Not Answered'))
            if given_answer in ['nan', 'None', '']:
                given_answer = 'Not Answered'
                
            correct_answer = str(response.get('correct_answer', 'N/A'))
            if correct_answer in ['nan', 'None', '']:
                correct_answer = 'N/A'
            
            marks = response.get('marks_obtained', 0)
            is_correct = response.get('is_correct', False)
            
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
            ['Total Questions:', str(result['total_questions'])],
            ['Correct Answers:', str(result['correct_answers'])],
            ['Incorrect Answers:', str(result['incorrect_answers'])],
            ['Unanswered:', str(result['unanswered_questions'])],
            ['Final Score:', f"{result['score']}/{result['max_score']}"],
            ['Percentage:', f"{result['percentage']:.1f}%"]
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
        
        # Build PDF
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
        uid = session.get("user_id")
        tok = session.get("token")
        
        session.clear()
        
        if uid and tok:
            def cleanup():
                try:
                    from sessions import invalidate_session, set_exam_active
                    set_exam_active(uid, tok, is_active=False)
                    invalidate_session(uid, token=tok)
                except Exception as e:
                    print(f"[logout] Background cleanup error: {e}")
            
            import threading
            cleanup_thread = threading.Thread(target=cleanup, daemon=True)
            cleanup_thread.start()
        
        flash("Logout successful!", "success")
        return redirect(url_for("home"))
        
    except Exception as e:
        print(f"[logout] Error: {e}")
        session.clear()
        flash("Logout successful.", "success")
        return redirect(url_for("home"))



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
    try:
        data = request.get_json()
        if not data or not data.get('username') or not data.get('email'):
            return jsonify({'success': False, 'message': 'Username and email are required'}), 400

        username = data['username'].strip()
        email = data['email'].strip().lower()

        users_df = load_csv_with_cache('users.csv', force_reload=True)
        if users_df.empty:
            return jsonify({'success': False, 'message': 'User database is unavailable'}), 500

        users_df['username_lower'] = users_df['username'].astype(str).str.strip().str.lower()
        users_df['email_lower'] = users_df['email'].astype(str).str.strip().str.lower()

        user_row = users_df[
            (users_df['username_lower'] == username.lower()) &
            (users_df['email_lower'] == email.lower())
        ]

        if user_row.empty:
            return jsonify({'success': False, 'message': 'User does not exist with provided username and email combination'}), 404

        user = user_row.iloc[0]
        current_access = str(user.get('role', 'user')).strip().lower()
        
        
        init_requests_raised_if_needed()
        requests_df = load_csv_with_cache('requests_raised.csv', force_reload=True)
        if requests_df is None:
            requests_df = pd.DataFrame(columns=[
                'request_id', 'username', 'email', 'current_access',
                'requested_access', 'request_date', 'request_status', 'reason'
            ])

        user_requests = []
        if not requests_df.empty:
            user_requests_df = requests_df[
                (requests_df['username'].astype(str).str.strip().str.lower() == username.lower()) &
                (requests_df['email'].astype(str).str.strip().str.lower() == email.lower())
            ]

            for _, req in user_requests_df.iterrows():
                reason_val = req.get('reason', None)
                try:
                    if pd.isna(reason_val):
                        reason_safe = None
                    else:
                        reason_safe = reason_val if reason_val != '' else None
                except Exception:
                    try:
                        if isinstance(reason_val, float) and math.isnan(reason_val):
                            reason_safe = None
                        else:
                            reason_safe = reason_val if reason_val != '' else None
                    except Exception:
                        reason_safe = None

                try:
                    req_id = int(req['request_id'])
                except Exception:
                    try:
                        req_id = int(pd.to_numeric(req['request_id'], errors='coerce'))
                    except Exception:
                        req_id = None

                user_requests.append({
                    'request_id': req_id,
                    'requested_access': req.get('requested_access', ''),
                    'request_date': str(req.get('request_date', '')),
                    'status': req.get('request_status', ''),
                    'reason': reason_safe
                })

        available_requests = []
        if current_access == 'user':
            available_requests = ['admin', 'user,admin']
        elif current_access == 'admin':
            available_requests = ['user', 'user,admin']
        elif current_access in ['user,admin', 'admin,user']:
            available_requests = []
        else:
            available_requests = ['admin', 'user,admin']

        has_pending = any((str(req.get('status', '')).lower() == 'pending') for req in user_requests)

        response_payload = {
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

        return jsonify(response_payload)
    except Exception as e:
        print(f"Error validating user for request: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'System error occurred'}), 500




@app.route('/api/submit-access-request', methods=['POST'])
def api_submit_access_request():
    try:
        data = request.get_json()
        required_fields = ['username', 'email', 'current_access', 'requested_access']

        for field in required_fields:
            if not data or not data.get(field):
                return jsonify({'success': False, 'message': f'{field.replace("_", " ").title()} is required'}), 400

        username = data['username'].strip()
        email = data['email'].strip().lower()
        current_access = data['current_access'].strip().lower()
        requested_access = data['requested_access'].strip().lower()

        users_df = load_csv_with_cache('users.csv')
        if users_df.empty:
            return jsonify({'success': False, 'message': 'User database unavailable'}), 500

        users_df['username_lower'] = users_df['username'].astype(str).str.strip().str.lower()
        users_df['email_lower'] = users_df['email'].astype(str).str.strip().str.lower()

        user_exists = not users_df[
            (users_df['username_lower'] == username.lower()) &
            (users_df['email_lower'] == email.lower())
        ].empty

        if not user_exists:
            return jsonify({'success': False, 'message': 'User validation failed'}), 400

        try:
            init_requests_raised_if_needed()
            requests_df = load_csv_with_cache('requests_raised.csv')
            if requests_df is None or requests_df.empty:
                requests_df = pd.DataFrame(columns=[
                    'request_id', 'username', 'email', 'current_access',
                    'requested_access', 'request_date', 'request_status', 'reason'
                ])
        except Exception as e:
            print(f"Error loading requests_raised.csv: {e}")
            requests_df = pd.DataFrame(columns=[
                'request_id', 'username', 'email', 'current_access',
                'requested_access', 'request_date', 'request_status', 'reason'
            ])

        if not requests_df.empty:
            pending_requests = requests_df[
                (requests_df['username'].astype(str).str.strip().str.lower() == username.lower()) &
                (requests_df['email'].astype(str).str.strip().str.lower() == email.lower()) &
                (requests_df['request_status'].astype(str).str.lower() == 'pending')
            ]

            if not pending_requests.empty:
                return jsonify({'success': False, 'message': 'You already have a pending request. Please wait for admin approval.'}), 400

        try:
            if requests_df.empty or 'request_id' not in requests_df.columns:
                next_id = 1
            else:
                numeric_ids = pd.to_numeric(requests_df['request_id'], errors='coerce')
                valid_ids = numeric_ids.dropna()
                next_id = int(valid_ids.max()) + 1 if not valid_ids.empty else 1
        except Exception:
            next_id = 1

        new_request = {
            'request_id': next_id,
            'username': username,
            'email': email,
            'current_access': current_access,
            'requested_access': requested_access,
            'request_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'request_status': 'pending',
            'reason': ''
        }

        new_df = pd.concat([requests_df, pd.DataFrame([new_request])], ignore_index=True)
        success = safe_csv_save_with_retry(new_df, 'requests_raised')

        if not success:
            return jsonify({'success': False, 'message': 'Failed to save request. Please try again.'}), 500

        requests_df = load_csv_with_cache('requests_raised.csv', force_reload=True)
        if requests_df is None:
            requests_df = pd.DataFrame(columns=[
                'request_id', 'username', 'email', 'current_access',
                'requested_access', 'request_date', 'request_status', 'reason'
            ])

        user_requests = []
        if not requests_df.empty:
            user_requests_df = requests_df[
                (requests_df['username'].astype(str).str.strip().str.lower() == username.lower()) &
                (requests_df['email'].astype(str).str.strip().str.lower() == email.lower())
            ]

            for _, req in user_requests_df.iterrows():
                reason_val = req.get('reason', None)
                try:
                    if pd.isna(reason_val):
                        reason_safe = None
                    else:
                        reason_safe = reason_val if reason_val != '' else None
                except Exception:
                    try:
                        if isinstance(reason_val, float) and math.isnan(reason_val):
                            reason_safe = None
                        else:
                            reason_safe = reason_val if reason_val != '' else None
                    except Exception:
                        reason_safe = None

                try:
                    req_id = int(req['request_id'])
                except Exception:
                    try:
                        req_id = int(pd.to_numeric(req['request_id'], errors='coerce'))
                    except Exception:
                        req_id = None

                user_requests.append({
                    'request_id': req_id,
                    'requested_access': req.get('requested_access', ''),
                    'request_date': str(req.get('request_date', '')),
                    'status': req.get('request_status', ''),
                    'reason': reason_safe
                })

        current_access = current_access
        available_requests = []
        if current_access == 'user':
            available_requests = ['admin', 'user,admin']
        elif current_access == 'admin':
            available_requests = ['user', 'user,admin']
        elif current_access in ['user,admin', 'admin,user']:
            available_requests = []
        else:
            available_requests = ['admin', 'user,admin']

        has_pending = any((str(req.get('status', '')).lower() == 'pending') for req in user_requests)

        response_payload = {
            'success': True,
            'message': 'Access request submitted successfully. Please wait for admin approval.',
            'request_id': next_id,
            'user': {
                'username': username,
                'email': email,
                'current_access': current_access,
                'full_name': username
            },
            'requests': user_requests,
            'available_requests': available_requests,
            'has_pending_request': has_pending,
            'can_request': len(available_requests) > 0 and not has_pending
        }

        return jsonify(response_payload)
    except Exception as e:
        print(f"Error submitting access request: {e}")
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
    """API endpoint to request password reset via email."""
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

        # Load users to check if email exists
        users_df = load_csv_with_cache('users.csv')
        if users_df is None or users_df.empty:
            return jsonify({
                'success': True,
                'message': success_message
            })

        # Check if user exists
        user_exists = email in users_df['email'].str.lower().values
        
        if user_exists:
            try:
                user_row = users_df[users_df['email'].str.lower() == email]
                user = user_row.iloc[0]
                full_name = user.get('full_name', 'User')
                username = user.get('username', email.split('@')[0])  # Get username or fallback
                
                # Generate reset token
                reset_token = create_password_token(email, 'reset')
                
                # Send reset email with username - UPDATED: now includes 4 parameters
                email_sent, email_message = send_password_reset_email(email, full_name, username, reset_token)
                
                if not email_sent:
                    print(f"Failed to send reset email to {email}: {email_message}")
                
            except Exception as e:
                print(f"Error processing reset request for {email}: {e}")

        # Always return success to prevent email enumeration
        return jsonify({
            'success': True,
            'message': success_message
        })

    except Exception as e:
        print(f"Error in password reset request: {e}")
        return jsonify({
            'success': False,
            'message': 'System error occurred. Please try again.'
        }), 500

# REPLACE THE PASSWORD RESET ROUTE IN main.py WITH THIS:

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password_page():
    """Password reset page route with POST-Redirect-GET pattern."""
    if request.method == 'POST':
        try:
            email = request.form.get('email', '').strip().lower()
            
            if not email:
                flash('Please enter your email address.', 'error')
                return redirect(url_for('reset_password_page'))  # Redirect instead of render

            client_ip = get_client_ip()
            
            # Always show success message to prevent email enumeration
            success_message = "If an account exists with this email, a password reset link has been sent. Please check your inbox and spam folder."

            # Load users to check if email exists
            users_df = load_csv_with_cache('users.csv')
            
            if users_df is not None and not users_df.empty:
                user_exists = email in users_df['email'].str.lower().values
                
                if user_exists:
                    try:
                        user_row = users_df[users_df['email'].str.lower() == email]
                        user = user_row.iloc[0]
                        full_name = user.get('full_name', 'User')
                        username = user.get('username', email.split('@')[0])  # Get username or fallback
                        
                        # Generate reset token
                        reset_token = create_password_token(email, 'reset')
                        
                        # Send reset email with username
                        email_sent, email_message = send_password_reset_email(email, full_name, username, reset_token)
                        
                        if not email_sent:
                            print(f"Failed to send reset email to {email}: {email_message}")
                        
                    except Exception as e:
                        print(f"Error processing reset request for {email}: {e}")

            # Flash the success message and redirect (POST-Redirect-GET pattern)
            flash(success_message, 'success')
            return redirect(url_for('reset_password_page'))  # Redirect instead of render
            
        except Exception as e:
            print(f"Error in password reset: {e}")
            flash('System error occurred. Please try again.', 'error')
            return redirect(url_for('reset_password_page'))  # Redirect instead of render
    
    # GET request - show the form (after redirect or direct access)
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

# -------------------------
# Run App - CRITICAL INITIALIZATION
# -------------------------
if __name__ == '__main__':
    print("🚀 Starting FIXED Exam Portal...")
    
    # CRITICAL: Force initialization during startup
    print("🔧 Forcing Google Drive service initialization...")
    if init_drive_service():
        print("✅ Google Drive integration: ACTIVE")
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
    else:
        print("❌ Production Google Drive integration: FAILED")

        print("📋 Check environment variables and credentials")
