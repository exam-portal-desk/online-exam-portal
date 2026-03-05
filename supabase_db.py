import os
from supabase import create_client, Client
from dotenv import load_dotenv
from typing import Optional, List, Dict, Any
from datetime import datetime

load_dotenv()

# Supabase connection
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ==========================================
# USERS TABLE FUNCTIONS
# ==========================================

def get_user_by_username(username: str) -> Optional[Dict]:
    """Get user by username"""
    try:
        response = supabase.table('users').select('*').eq('username', username).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        print(f"Error getting user by username: {e}")
        return None

def get_user_by_id(user_id: int) -> Optional[Dict]:
    """Get user by ID"""
    try:
        response = supabase.table('users').select('*').eq('id', user_id).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        print(f"Error getting user by id: {e}")
        return None

def get_user_by_email(email: str) -> Optional[Dict]:
    """Get user by email"""
    try:
        response = supabase.table('users').select('*').eq('email', email).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        print(f"Error getting user by email: {e}")
        return None

def get_all_users() -> List[Dict]:
    """Get all users"""
    try:
        response = supabase.table('users').select('*').execute()
        return response.data
    except Exception as e:
        print(f"Error getting all users: {e}")
        return []

def create_user(user_data: Dict) -> Optional[Dict]:
    """Create new user"""
    try:
        response = supabase.table('users').insert(user_data).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        print(f"Error creating user: {e}")
        return None

def update_user(user_id: int, user_data: Dict) -> bool:
    """Update user"""
    try:
        response = supabase.table('users').update(user_data).eq('id', user_id).execute()
        return True
    except Exception as e:
        print(f"Error updating user: {e}")
        return False

def delete_user(user_id: int) -> bool:
    """Delete user"""
    try:
        supabase.table('users').delete().eq('id', user_id).execute()
        return True
    except Exception as e:
        print(f"Error deleting user: {e}")
        return False

# ==========================================
# EXAMS TABLE FUNCTIONS
# ==========================================

def get_all_exams() -> List[Dict]:
    """Get all exams"""
    try:
        response = supabase.table('exams').select('*').order('id').execute()
        return response.data
    except Exception as e:
        print(f"Error getting exams: {e}")
        return []

def get_exam_by_id(exam_id: int) -> Optional[Dict]:
    """Get exam by ID"""
    try:
        response = supabase.table('exams').select('*').eq('id', exam_id).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        print(f"Error getting exam: {e}")
        return None

def create_exam(exam_data: Dict) -> Optional[Dict]:
    """Create new exam"""
    try:
        response = supabase.table('exams').insert(exam_data).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        print(f"Error creating exam: {e}")
        return None

def update_exam(exam_id: int, exam_data: Dict) -> bool:
    """Update exam"""
    try:
        supabase.table('exams').update(exam_data).eq('id', exam_id).execute()
        return True
    except Exception as e:
        print(f"Error updating exam: {e}")
        return False

def delete_exam(exam_id: int) -> bool:
    """Delete exam"""
    try:
        supabase.table('exams').delete().eq('id', exam_id).execute()
        return True
    except Exception as e:
        print(f"Error deleting exam: {e}")
        return False

# ==========================================
# QUESTIONS TABLE FUNCTIONS
# ==========================================

def get_questions_by_exam(exam_id: int) -> List[Dict]:
    """Get all questions for an exam"""
    try:
        response = supabase.table('questions').select('*').eq('exam_id', exam_id).order('id').execute()
        return response.data
    except Exception as e:
        print(f"Error getting questions: {e}")
        return []

def create_question(question_data: Dict) -> Optional[Dict]:
    """Create new question"""
    try:
        response = supabase.table('questions').insert(question_data).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        print(f"Error creating question: {e}")
        return None

def update_question(question_id: int, question_data: Dict) -> bool:
    """Update question"""
    try:
        supabase.table('questions').update(question_data).eq('id', question_id).execute()
        return True
    except Exception as e:
        print(f"Error updating question: {e}")
        return False

def delete_question(question_id: int) -> bool:
    """Delete question"""
    try:
        supabase.table('questions').delete().eq('id', question_id).execute()
        return True
    except Exception as e:
        print(f"Error deleting question: {e}")
        return False

# ==========================================
# SESSIONS TABLE FUNCTIONS
# ==========================================

def create_session(session_data: Dict) -> bool:
    """Create new session"""
    try:
        from datetime import datetime, timezone
        
        # ✅ Add timestamps in UTC
        session_data['created_at'] = datetime.now(timezone.utc).isoformat()
        session_data['last_seen'] = datetime.now(timezone.utc).isoformat()
        
        supabase.table('sessions').insert(session_data).execute()
        return True
    except Exception as e:
        print(f"Error creating session: {e}")
        import traceback
        traceback.print_exc()
        return False

def get_session_by_token(token: str) -> Optional[Dict]:
    """Get session by token"""
    try:
        response = supabase.table('sessions').select('*').eq('token', token).eq('active', True).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        print(f"Error getting session: {e}")
        return None

def invalidate_session(user_id: int, token: Optional[str] = None) -> bool:
    """Invalidate session(s)"""
    try:
        if token:
            supabase.table('sessions').update({'active': False}).eq('token', token).execute()
        else:
            supabase.table('sessions').update({'active': False}).eq('user_id', user_id).execute()
        return True
    except Exception as e:
        print(f"Error invalidating session: {e}")
        return False

def update_session_last_seen(token: str) -> bool:
    """Update last seen timestamp"""
    try:
        from datetime import datetime
        supabase.table('sessions').update({
            'last_seen': datetime.now().isoformat()
        }).eq('token', token).execute()
        return True
    except Exception as e:
        print(f"Error updating last seen: {e}")
        return False

# ==========================================
# LOGIN ATTEMPTS TABLE FUNCTIONS
# ==========================================

def check_login_attempts(identifier: str, ip_address: str) -> tuple[bool, str, int]:
    """Check if login attempts are within allowed limits"""
    try:
        from datetime import datetime, timedelta
        
        response = supabase.table('login_attempts').select('*').eq('identifier', identifier).eq('ip_address', ip_address).execute()
        
        if not response.data:
            return True, "", 5
        
        attempt = response.data[0]
        
        # Check if blocked
        if attempt.get('blocked_until'):
            blocked_until = datetime.fromisoformat(attempt['blocked_until'])
            if datetime.now() < blocked_until:
                minutes_left = int((blocked_until - datetime.now()).total_seconds() / 60) + 1
                return False, f"Too many failed attempts. Try again in {minutes_left} minutes.", 0
        
        # Check if attempt window expired (15 minutes)
        first_failed = datetime.fromisoformat(attempt['first_failed_at'])
        if datetime.now() - first_failed > timedelta(minutes=15):
            # Clear old attempt
            supabase.table('login_attempts').delete().eq('id', attempt['id']).execute()
            return True, "", 5
        
        failed_count = attempt.get('failed_count', 0)
        remaining = max(0, 5 - failed_count)
        
        if remaining <= 0:
            return False, "Too many failed attempts. Account temporarily locked.", 0
        
        return True, "", remaining
        
    except Exception as e:
        print(f"Error checking login attempts: {e}")
        return True, "", 5

def record_failed_login(identifier: str, ip_address: str) -> bool:
    """Record a failed login attempt"""
    try:
        from datetime import datetime, timedelta
        
        response = supabase.table('login_attempts').select('*').eq('identifier', identifier).eq('ip_address', ip_address).execute()
        
        now = datetime.now()
        
        if not response.data:
            # Create new record
            supabase.table('login_attempts').insert({
                'identifier': identifier.lower(),
                'ip_address': ip_address,
                'failed_count': 1,
                'first_failed_at': now.isoformat(),
                'last_failed_at': now.isoformat()
            }).execute()
        else:
            # Update existing
            attempt = response.data[0]
            failed_count = attempt.get('failed_count', 0) + 1
            
            update_data = {
                'failed_count': failed_count,
                'last_failed_at': now.isoformat()
            }
            
            # Block if 5 attempts reached
            if failed_count >= 5:
                blocked_until = now + timedelta(minutes=15)
                update_data['blocked_until'] = blocked_until.isoformat()
            
            supabase.table('login_attempts').update(update_data).eq('id', attempt['id']).execute()
        
        return True
        
    except Exception as e:
        print(f"Error recording failed login: {e}")
        return False

def clear_login_attempts(identifier: str, ip_address: str) -> bool:
    """Clear login attempts for successful login"""
    try:
        supabase.table('login_attempts').delete().eq('identifier', identifier).eq('ip_address', ip_address).execute()
        return True
    except Exception as e:
        print(f"Error clearing login attempts: {e}")
        return False



# ==========================================
# RESULTS TABLE FUNCTIONS
# ==========================================

def get_all_results() -> List[Dict]:
    """Get all results"""
    try:
        response = supabase.table('results').select('*').order('completed_at', desc=True).execute()
        return response.data if response.data else []
    except Exception as e:
        print(f"Error getting results: {e}")
        return []

def get_result_by_id(result_id: int) -> Optional[Dict]:
    """Get result by ID"""
    try:
        response = supabase.table('results').select('*').eq('id', result_id).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        print(f"Error getting result: {e}")
        return None

def get_results_by_user(user_id: int) -> List[Dict]:
    """Get all results for a user"""
    try:
        response = supabase.table('results').select('*').eq('student_id', user_id).order('completed_at', desc=True).execute()
        return response.data if response.data else []
    except Exception as e:
        print(f"Error getting user results: {e}")
        return []

def get_results_by_exam(exam_id: int) -> List[Dict]:
    """Get all results for an exam"""
    try:
        response = supabase.table('results').select('*').eq('exam_id', exam_id).order('completed_at', desc=True).execute()
        return response.data if response.data else []
    except Exception as e:
        print(f"Error getting exam results: {e}")
        return []

def create_result(result_data: Dict) -> Optional[Dict]:
    """Create new result"""
    try:
        response = supabase.table('results').insert(result_data).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        print(f"Error creating result: {e}")
        return None

# ==========================================
# RESPONSES TABLE FUNCTIONS
# ==========================================

def get_responses_by_result(result_id: int) -> List[Dict]:
    """Get all responses for a result"""
    try:
        response = supabase.table('responses').select('*').eq('result_id', result_id).order('question_id').execute()
        return response.data if response.data else []
    except Exception as e:
        print(f"Error getting responses: {e}")
        return []

def create_response(response_data: Dict) -> Optional[Dict]:
    """Create new response"""
    try:
        response = supabase.table('responses').insert(response_data).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        print(f"Error creating response: {e}")
        return None

def create_responses_bulk(responses_data: List[Dict]) -> bool:
    """Create multiple responses at once"""
    try:
        supabase.table('responses').insert(responses_data).execute()
        return True
    except Exception as e:
        print(f"Error creating bulk responses: {e}")
        return False



# ==========================================
# EXAM ATTEMPTS FUNCTIONS (for main.py)
# ==========================================

def get_latest_attempt(user_id: int, exam_id: int) -> Optional[Dict]:
    """Get latest attempt for user-exam combo"""
    try:
        response = supabase.table('exam_attempts').select('*')\
            .eq('student_id', user_id)\
            .eq('exam_id', exam_id)\
            .order('id', desc=True)\
            .limit(1)\
            .execute()
        
        return response.data[0] if response.data else None
    except Exception as e:
        print(f"Error getting latest attempt: {e}")
        return None

def get_completed_attempts_count(user_id: int, exam_id: int) -> int:
    """Count completed attempts for user-exam"""
    try:
        response = supabase.table('exam_attempts').select('*')\
            .eq('student_id', user_id)\
            .eq('exam_id', exam_id)\
            .eq('status', 'completed')\
            .execute()
        
        return len(response.data) if response.data else 0
    except Exception as e:
        print(f"Error counting attempts: {e}")
        return 0

def create_exam_attempt(attempt_data: Dict) -> Optional[Dict]:
    """Create new exam attempt"""
    try:
        response = supabase.table('exam_attempts').insert(attempt_data).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        print(f"Error creating attempt: {e}")
        return None

def update_exam_attempt(attempt_id: int, updates: Dict) -> bool:
    """Update exam attempt"""
    try:
        supabase.table('exam_attempts').update(updates).eq('id', attempt_id).execute()
        return True
    except Exception as e:
        print(f"Error updating attempt: {e}")
        return False

# ==========================================
# PASSWORD TOKENS FUNCTIONS
# ==========================================

def get_password_token(token: str) -> Optional[Dict]:
    """Get password token by token string"""
    try:
        response = supabase.table('pw_tokens').select('*').eq('token', token).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        print(f"Error getting token: {e}")
        return None

def create_password_token(token_data: Dict) -> Optional[Dict]:
    """Create new password token"""
    try:
        response = supabase.table('pw_tokens').insert(token_data).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        print(f"Error creating token: {e}")
        return None

def mark_token_used(token: str) -> bool:
    """Mark token as used"""
    try:
        supabase.table('pw_tokens').update({'used': True}).eq('token', token).execute()
        return True
    except Exception as e:
        print(f"Error marking token used: {e}")
        return False

# ==========================================
# AI CHAT FUNCTIONS
# ==========================================

def get_chat_history(user_id: int, limit: int = 50) -> List[Dict]:
    """Get chat history for user"""
    try:
        response = supabase.table('ai_chat_history').select('*')\
            .eq('user_id', user_id)\
            .order('timestamp', desc=True)\
            .limit(limit)\
            .execute()
        
        return response.data if response.data else []
    except Exception as e:
        print(f"Error getting chat history: {e}")
        return []

def save_chat_message(message_data: Dict) -> bool:
    """Save chat message to Supabase"""
    try:
        # ✅ Ensure proper types
        safe_data = {
            'user_id': int(message_data.get('user_id')),
            'message': str(message_data.get('message', '')),
            'is_user': bool(message_data.get('is_user', False)),
            'timestamp': message_data.get('timestamp') or datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        print(f"💬 [SAVE_CHAT] Saving message for user {safe_data['user_id']}: {safe_data['message'][:50]}...")
        
        response = supabase.table('ai_chat_history').insert(safe_data).execute()
        
        if response.data:
            print(f"✅ [SAVE_CHAT] Message saved successfully!")
            return True
        else:
            print(f"❌ [SAVE_CHAT] No data returned from insert")
            return False
            
    except Exception as e:
        print(f"❌ [SAVE_CHAT] Error: {e}")
        import traceback
        traceback.print_exc()
        return False

def delete_user_chat_history(user_id: int) -> bool:
    """Delete all chat history for user"""
    try:
        supabase.table('ai_chat_history').delete().eq('user_id', user_id).execute()
        return True
    except Exception as e:
        print(f"Error deleting chat history: {e}")
        return False

# ==========================================
# AI USAGE TRACKING FUNCTIONS
# ==========================================

def get_today_usage(user_id: int) -> Optional[Dict]:
    """Get today's usage for user"""
    try:
        from datetime import datetime
        today = datetime.now().strftime('%Y-%m-%d')
        
        response = supabase.table('ai_usage_tracking').select('*')\
            .eq('user_id', user_id)\
            .eq('date', today)\
            .execute()
        
        return response.data[0] if response.data else None
    except Exception as e:
        print(f"Error getting usage: {e}")
        return None

def increment_usage(user_id: int) -> bool:
    """Increment usage count for today"""
    try:
        from datetime import datetime
        today = datetime.now().strftime('%Y-%m-%d')
        
        existing = get_today_usage(user_id)
        
        if existing:
            # Update existing
            new_count = int(existing.get('questions_used', 0)) + 1
            supabase.table('ai_usage_tracking')\
                .update({'questions_used': new_count})\
                .eq('user_id', user_id)\
                .eq('date', today)\
                .execute()
        else:
            # Create new
            supabase.table('ai_usage_tracking').insert({
                'user_id': user_id,
                'date': today,
                'questions_used': 1
            }).execute()
        
        return True
    except Exception as e:
        print(f"Error incrementing usage: {e}")
        return False



# ==========================================
# PASSWORD TOKENS FUNCTIONS (Migration from CSV)
# ==========================================

def create_password_token_db(email: str, token_type: str, token: str, expires_at: str) -> bool:
    """Create password token in Supabase"""
    try:
        token_data = {
            'token': token,
            'email': email.lower(),
            'type': token_type,
            'expires_at': expires_at,
            'used': False,
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        response = supabase.table('pw_tokens').insert(token_data).execute()
        return bool(response.data)
        
    except Exception as e:
        print(f"Error creating password token: {e}")
        return False


def get_password_token_db(token: str) -> Optional[Dict]:
    """Get password token from Supabase"""
    try:
        response = supabase.table('pw_tokens').select('*').eq('token', token).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        print(f"Error getting password token: {e}")
        return None


def mark_token_used_db(token: str) -> bool:
    """Mark token as used in Supabase"""
    try:
        response = supabase.table('pw_tokens').update({'used': True}).eq('token', token).execute()
        return bool(response.data)
    except Exception as e:
        print(f"Error marking token used: {e}")
        return False


def delete_expired_tokens() -> int:
    """Delete expired tokens (cleanup job)"""
    try:
        from datetime import datetime
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Supabase doesn't support DELETE with WHERE directly in Python SDK
        # So we get expired tokens first, then delete them
        expired = supabase.table('pw_tokens').select('id').lt('expires_at', now).execute()
        
        if expired.data:
            for token_record in expired.data:
                supabase.table('pw_tokens').delete().eq('id', token_record['id']).execute()
            return len(expired.data)
        
        return 0
    except Exception as e:
        print(f"Error deleting expired tokens: {e}")
        return 0



# ==========================================
# TEST CONNECTION
# ==========================================
if __name__ == "__main__":
    print("Testing Supabase connection...")
    users = get_all_users()
    print(f"✅ Connected! Found {len(users)} users")
    for user in users:
        print(f"  - {user.get('username')} ({user.get('role')})")