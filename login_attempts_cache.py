from datetime import datetime, timedelta
from supabase_db import supabase

def check_login_attempts(username: str, ip_address: str) -> tuple:
    """Check if login attempts exceeded - SUPABASE VERSION"""
    try:
        identifier = f"{username}_{ip_address}"  # ✅ Just username_ip (no separator needed based on your data)
        
        # Get attempt record
        response = supabase.table('login_attempts').select('*').eq('identifier', identifier).eq('ip_address', ip_address).execute()
        
        if not response.data:
            return True, "", 3  # No attempts yet
        
        attempt = response.data[0]
        
        # ✅ FIXED: Use correct column name 'blocked_until'
        if attempt.get('blocked_until'):
            try:
                blocked_until = datetime.fromisoformat(attempt['blocked_until'].replace('Z', '+00:00'))
            except:
                blocked_until = datetime.strptime(attempt['blocked_until'], '%Y-%m-%d %H:%M:%S.%f')
            
            if datetime.now() < blocked_until:
                remaining = int((blocked_until - datetime.now()).total_seconds() / 60)
                return False, f"Account locked. Try again in {remaining} minutes.", 0
            else:
                # Lock expired, reset
                supabase.table('login_attempts').update({
                    'failed_count': 0,
                    'blocked_until': None
                }).eq('identifier', identifier).eq('ip_address', ip_address).execute()
                return True, "", 3
        
        # Check failed count
        failed_count = int(attempt.get('failed_count', 0))
        if failed_count >= 3:
            # Lock account
            blocked_until = (datetime.now() + timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S.%f')
            supabase.table('login_attempts').update({
                'blocked_until': blocked_until
            }).eq('identifier', identifier).eq('ip_address', ip_address).execute()
            return False, "Too many failed attempts. Account locked for 15 minutes.", 0
        
        remaining = 3 - failed_count
        return True, "", remaining
    
    except Exception as e:
        print(f"Error checking login attempts: {e}")
        import traceback
        traceback.print_exc()
        return True, "", 3  # Fail open


def record_failed_login(username: str, ip_address: str):
    """Record failed login attempt - SUPABASE VERSION"""
    try:
        identifier = f"{username}_{ip_address}"
        
        print(f"[LOGIN_ATTEMPTS] Recording failed login: {identifier}")
        
        # Check if exists
        response = supabase.table('login_attempts').select('*').eq('identifier', identifier).eq('ip_address', ip_address).execute()
        
        if response.data:
            # ✅ Update existing
            attempt = response.data[0]
            new_count = int(attempt.get('failed_count', 0)) + 1
            
            print(f"[LOGIN_ATTEMPTS] Updating count: {new_count}")
            
            supabase.table('login_attempts').update({
                'failed_count': new_count,
                'last_failed_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')  # ✅ FIXED column name
            }).eq('identifier', identifier).eq('ip_address', ip_address).execute()
            
            print(f"[LOGIN_ATTEMPTS] ✅ Updated to {new_count} attempts")
        else:
            # ✅ Create new
            print(f"[LOGIN_ATTEMPTS] Creating new record")
            
            now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
            
            supabase.table('login_attempts').insert({
                'identifier': identifier,
                'ip_address': ip_address,
                'failed_count': 1,
                'first_failed_at': now_str,  # ✅ FIXED column name
                'last_failed_at': now_str,   # ✅ FIXED column name
                'blocked_until': None
            }).execute()
            
            print(f"[LOGIN_ATTEMPTS] ✅ Created new record with 1 attempt")
    
    except Exception as e:
        print(f"❌ Error recording failed login: {e}")
        import traceback
        traceback.print_exc()


def clear_login_attempts(username: str, ip_address: str):
    """Clear login attempts after successful login - SUPABASE VERSION"""
    try:
        identifier = f"{username}_{ip_address}"
        
        print(f"[LOGIN_ATTEMPTS] Clearing attempts for: {identifier}")
        
        supabase.table('login_attempts').delete().eq('identifier', identifier).eq('ip_address', ip_address).execute()
        
        print(f"[LOGIN_ATTEMPTS] ✅ Cleared successfully")
    except Exception as e:
        print(f"❌ Error clearing login attempts: {e}")
        import traceback
        traceback.print_exc()