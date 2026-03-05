import os
import json
import time
from io import StringIO, BytesIO
from datetime import datetime
import pandas as pd

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
from google.oauth2.service_account import Credentials
from dotenv import load_dotenv
from google.oauth2.credentials import Credentials as UserCredentials
from google_auth_oauthlib.flow import InstalledAppFlow  
import urllib.parse

load_dotenv()

# -------------------------------------------------------------------
# GLOBAL SERVICE INSTANCE - REUSE TO AVOID MULTIPLE INITIALIZATIONS
# -------------------------------------------------------------------
_global_service_instance = None
_service_initialized = False

# -------------------------------------------------------------------
# Small in-memory caches (CSV/file lookups/URLs) with TTL timestamps
# -------------------------------------------------------------------
_file_cache = {}
_folder_cache = {}
_image_cache = {}
_cache_timestamps = {}

def _is_cache_valid(key: str, ttl_seconds: int) -> bool:
    ts = _cache_timestamps.get(key)
    return bool(ts and (time.time() - ts) < ttl_seconds)

def _set_cache(key: str, value, bucket: dict):
    bucket[key] = value
    _cache_timestamps[key] = time.time()

def clear_cache():
    _file_cache.clear()
    _folder_cache.clear()
    _image_cache.clear()
    _cache_timestamps.clear()
    print("✅ Cleared all caches")

# -------------------------------------------------------------------
# Credentials loader
# -------------------------------------------------------------------
def _load_service_account_info():
    env_value = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON")
    try:
        # Case 1: env contains JSON itself
        if env_value and env_value.strip().startswith("{"):
            return json.loads(env_value)

        # Case 2: env contains a file path (recommended)
        if env_value and os.path.exists(env_value):
            with open(env_value, "r", encoding="utf-8") as f:
                return json.load(f)

        # Case 3: fallback file
        fallback = os.path.join(os.path.dirname(__file__), "credentials.json")
        if os.path.exists(fallback):
            with open(fallback, "r", encoding="utf-8") as f:
                return json.load(f)

        print("❌ No service account JSON found. "
              "Set GOOGLE_SERVICE_ACCOUNT_JSON to a JSON string or file path.")
        return None
    except Exception as e:
        print(f"❌ Failed to load service account JSON: {e}")
        return None

def _scopes():
    # Full Drive scope + file scope + readonly (safe for reading CSVs)
    return [
        "https://www.googleapis.com/auth/drive",
        "https://www.googleapis.com/auth/drive.file",
        "https://www.googleapis.com/auth/drive.readonly",
    ]

# -------------------------------------------------------------------
# OPTIMIZED Service factory - REUSE GLOBAL INSTANCE
# -------------------------------------------------------------------
import threading
from datetime import datetime, timedelta

_service_lock = threading.RLock()
_service_last_used = None
_service_health_check_interval = 300

def create_drive_service():
    global _global_service_instance, _service_initialized, _service_last_used
    
    with _service_lock:
        current_time = datetime.now()
        
        if _service_initialized and _global_service_instance is not None:
            try:
                if (_service_last_used and 
                    (current_time - _service_last_used).seconds < 30):
                    return _global_service_instance
                
                if (_service_last_used is None or 
                    (current_time - _service_last_used).seconds > _service_health_check_interval):
                    _global_service_instance.about().get(fields="user(emailAddress)").execute()
                    _service_last_used = current_time
                    
                return _global_service_instance
                
            except Exception as e:
                print(f"Service health check failed, reinitializing: {e}")
                _service_initialized = False
                _global_service_instance = None
                _service_last_used = None
        
        try:
            print("Initializing Google Drive service...")
            info = _load_service_account_info()
            if not info:
                print("No service-account JSON found.")
                return None

            if "private_key" in info and "\\n" in info["private_key"]:
                info["private_key"] = info["private_key"].replace("\\n", "\n")

            sa_creds = Credentials.from_service_account_info(info, scopes=_scopes())
            service = build("drive", "v3", credentials=sa_creds, cache_discovery=False)
            
            if not _service_initialized:
                try:
                    about = service.about().get(fields="user(emailAddress)").execute()
                    print(f"SA ready as: {about.get('user', {}).get('emailAddress', 'unknown')}")
                except Exception as e:
                    print(f"SA about() warn: {e}")
            
            _global_service_instance = service
            _service_initialized = True
            _service_last_used = current_time
            
            return service
            
        except Exception as e:
            print(f"create_drive_service error: {e}")
            _service_initialized = False
            _global_service_instance = None
            _service_last_used = None
            return None

# -------------------------------------------------------------------
# PERFORMANCE: Get service instance with reuse
# -------------------------------------------------------------------
def get_drive_service():
    """Get the global Drive service instance, creating it if needed"""
    return create_drive_service()

def clear_csv_cache(file_id: str | None = None):
    """
    Clear CSV cache for a specific file_id (or all if file_id is None).
    Used by main app to ensure fresh reads after save.
    """
    try:
        if file_id:
            ckey = f"csv::{file_id}"
            _file_cache.pop(ckey, None)
            _cache_timestamps.pop(ckey, None)
        else:
            _file_cache.clear()
            _cache_timestamps.clear()
        print(f"✅ Cleared csv cache for {file_id or 'ALL'}")
    except Exception as e:
        print(f"⚠️ clear_csv_cache error: {e}")

# -------------------------------------------------------------------
# CSV helpers - UPDATED TO USE GLOBAL SERVICE
# -------------------------------------------------------------------
def load_csv_from_drive(service, file_id: str, max_retries: int = 3, **kwargs) -> pd.DataFrame:
    # If no service passed, get the global service
    if not service:
        service = get_drive_service()
    
    if not service:
        print("❌ load_csv_from_drive: no service available")
        return pd.DataFrame()

    if not file_id or len(str(file_id)) < 8:
        print(f"❌ load_csv_from_drive: invalid file_id '{file_id}'")
        return pd.DataFrame()

    cache_key = f"csv::{file_id}"
    if _is_cache_valid(cache_key, 300):
        print("💾 Using cached CSV")
        return _file_cache[cache_key].copy()

    for attempt in range(1, max_retries + 1):
        try:
            print(f"📥 Loading CSV (try {attempt}/{max_retries}) id={file_id}")
            meta = service.files().get(fileId=file_id, fields="id,name,size,mimeType").execute()

            if not isinstance(meta, dict):
                print(f"⚠️ Unexpected meta type ({type(meta)}) for file_id={file_id}")
                raise RuntimeError("Unexpected metadata type returned from Drive API")

            mime = meta.get("mimeType", "")
            print(f"📄 File: {meta.get('name')} ({meta.get('size', '0')} bytes, {mime})")

            if 'folder' in mime:
                print(f"❌ File id {file_id} is a FOLDER. Returning empty DataFrame.")
                return pd.DataFrame()

            size = meta.get("size")
            if size in [None, "0", 0]:
                print(f"⚠️ File id {file_id} has size={size} (empty). Returning empty DataFrame.")
                return pd.DataFrame()

            # Download media
            req = service.files().get_media(fileId=file_id)
            buf = BytesIO()
            downloader = MediaIoBaseDownload(buf, req)
            done = False
            while not done:
                status, done = downloader.next_chunk()
                if status:
                    prog = int(status.progress() * 100)
                    if prog % 25 == 0:
                        print(f"📊 Download progress: {prog}%")
            
            buf.seek(0)
            content = buf.read().decode("utf-8", errors="replace")
            if not content.strip():
                print("⚠️ CSV empty (no textual content)")
                return pd.DataFrame()

            # 🔧 FIX: Handle header-only files properly
            lines = content.strip().split('\n')
            if len(lines) <= 1:
                # Only headers, no data rows
                df = pd.read_csv(StringIO(content))
                print(f"📋 Header-only CSV detected: {list(df.columns)}")
                _set_cache(cache_key, df.copy(), _file_cache)
                return df
            
            df = pd.read_csv(StringIO(content))
            if df is None:
                print("⚠️ Parsed DataFrame is None")
                return pd.DataFrame()

            _set_cache(cache_key, df.copy(), _file_cache)
            print(f"✅ Loaded {len(df)} rows, {len(df.columns)} cols")
            return df

        except HttpError as he:
            status_code = getattr(he.resp, "status", None)
            print(f"❌ HTTP {status_code} on load: {he}")
            if status_code in (403, 404):
                print("⚠️ Received 403/404 from Drive; returning empty DataFrame")
                return pd.DataFrame()
            time.sleep(2 * attempt)

        except Exception as e:
            import ssl
            es = str(e)
            if isinstance(e, ssl.SSLError) or 'WRONG_VERSION_NUMBER' in es or 'SSLError' in es or 'DECRYPTION_FAILED' in es:
                print(f"❌ SSL error while loading CSV (try {attempt}): {e}")
                if attempt < max_retries:
                    time.sleep(3 * attempt)  # Longer delay for SSL issues
                    continue
            else:
                print(f"❌ load error (try {attempt}): {e}")
            time.sleep(1 * attempt)

    print(f"⚠️ All {max_retries} attempts failed for id={file_id}. Returning empty DataFrame.")
    return pd.DataFrame()

def save_csv_to_drive(service, df: pd.DataFrame, file_id: str, max_retries: int = 3) -> bool:
    # If no service passed, get the global service
    if not service:
        service = get_drive_service()
    
    if not service:
        print("❌ save_csv_to_drive: no service available")
        return False
        
    if df is None:
        print("⚠️ save_csv_to_drive: None DataFrame")
        return False
    
    if not hasattr(df, 'columns') or len(df.columns) == 0:
        print("⚠️ save_csv_to_drive: DataFrame has no columns")
        return False
    if not file_id or len(str(file_id)) < 8:
        print(f"❌ save_csv_to_drive: invalid file_id '{file_id}'")
        return False

    for attempt in range(1, max_retries + 1):
        try:
            print(f"💾 Saving CSV (try {attempt}/{max_retries}) id={file_id}")
            csv_buf = StringIO()
            df.to_csv(csv_buf, index=False)
            content = csv_buf.getvalue()

            media = MediaIoBaseUpload(
                BytesIO(content.encode("utf-8")),
                mimetype="text/csv",
                resumable=True,
            )

            service.files().update(
                fileId=file_id,
                media_body=media,
                fields="id,name,size"
            ).execute()

            # bust CSV cache
            ckey = f"csv::{file_id}"
            _file_cache.pop(ckey, None)
            _cache_timestamps.pop(ckey, None)
            print("✅ CSV saved & cache cleared")
            return True
        except HttpError as he:
            status_code = getattr(he.resp, "status", None)
            print(f"❌ HTTP {status_code} on save: {he}")
            if status_code in (403, 404):
                break
            time.sleep(2 * attempt)
        except Exception as e:
            print(f"❌ save error (try {attempt}): {e}")
            time.sleep(1 * attempt)
    return False

# -------------------------------------------------------------------
# Drive search helpers - UPDATED TO USE GLOBAL SERVICE
# -------------------------------------------------------------------
def find_file_by_name(service, filename: str, parent_folder_id: str | None = None, max_retries: int = 2):
    # If no service passed, get the global service
    if not service:
        service = get_drive_service()
    
    if not service:
        print("❌ find_file_by_name: no service available")
        return None
    if not filename:
        return None

    cache_key = f"file::{parent_folder_id or 'root'}::{filename}"
    if _is_cache_valid(cache_key, 600):
        return _file_cache.get(cache_key)

    query = f"name = '{filename}' and trashed = false"
    if parent_folder_id:
        query += f" and '{parent_folder_id}' in parents"

    for attempt in range(1, max_retries + 1):
        try:
            # Order by modifiedTime desc so the most recently uploaded file is returned first.
            res = service.files().list(
                q=query,
                spaces="drive",
                fields="files(id,name,modifiedTime)",
                orderBy="modifiedTime desc",
                pageSize=10
            ).execute()
            files = res.get("files", [])
            if files:
                fid = files[0]["id"]
                _set_cache(cache_key, fid, _file_cache)
                print(f"✅ Found file '{filename}': {fid}")
                return fid
            return None
        except Exception as e:
            print(f"❌ find_file_by_name (try {attempt}): {e}")
            time.sleep(1)
    return None

def find_folder_by_name(service, folder_name: str, parent_folder_id: str | None = None, max_retries: int = 2):
    # If no service passed, get the global service
    if not service:
        service = get_drive_service()
    
    if not service:
        print("❌ find_folder_by_name: no service available")
        return None
    if not folder_name:
        return None

    cache_key = f"folder::{parent_folder_id or 'root'}::{folder_name}"
    if _is_cache_valid(cache_key, 600):
        return _folder_cache.get(cache_key)

    query = (
        f"name = '{folder_name}' and mimeType = 'application/vnd.google-apps.folder' "
        f"and trashed = false"
    )
    if parent_folder_id:
        query += f" and '{parent_folder_id}' in parents"

    for attempt in range(1, max_retries + 1):
        try:
            res = service.files().list(
                q=query,
                spaces="drive",
                fields="files(id,name)",
                pageSize=5
            ).execute()
            folders = res.get("files", [])
            if folders:
                fid = folders[0]["id"]
                _set_cache(cache_key, fid, _folder_cache)
                print(f"✅ Found folder '{folder_name}': {fid}")
                return fid
            return None
        except Exception as e:
            print(f"❌ find_folder_by_name (try {attempt}): {e}")
            time.sleep(1)
    return None

def list_drive_files(service, folder_id: str | None = None, max_retries: int = 2):
    # If no service passed, get the global service
    if not service:
        service = get_drive_service()
    
    if not service:
        print("❌ list_drive_files: no service available")
        return []

    query = "trashed = false"
    if folder_id:
        query += f" and '{folder_id}' in parents"

    for attempt in range(1, max_retries + 1):
        try:
            res = service.files().list(
                q=query,
                spaces="drive",
                fields="files(id,name,mimeType)",
                pageSize=200
            ).execute()
            return res.get("files", [])
        except Exception as e:
            print(f"❌ list_drive_files (try {attempt}): {e}")
            time.sleep(1)
    return []

# -------------------------------------------------------------------
# Public URL helper (sets 'anyone with link' if needed) - UPDATED
# -------------------------------------------------------------------
def get_public_url(service, file_id: str, max_retries: int = 2, force_refresh: bool = False):
    """Get public URL with STRONG cache-busting"""
    if not service:
        service = get_drive_service()
    
    if not file_id:
        return None

    cache_key = f"url::{file_id}"
    
    # ✅ FORCE REFRESH: Clear cache FIRST
    if force_refresh:
        _image_cache.pop(cache_key, None)
        _cache_timestamps.pop(cache_key, None)
        print(f"🔥 [IMAGE] Force refresh - cleared cache for {file_id}")
    else:
        # Check cache if NOT force refresh
        if _is_cache_valid(cache_key, 10):
            cached_url = _image_cache.get(cache_key)
            if cached_url:
                print(f"💾 [IMAGE] Using cached URL: {cached_url[:60]}...")
                return cached_url

    for attempt in range(1, max_retries + 1):
        try:
            # ✅ CRITICAL: Make file public FIRST
            try:
                service.permissions().create(
                    fileId=file_id,
                    body={"type": "anyone", "role": "reader"}
                ).execute()
                print(f"🔓 [IMAGE] Made file public: {file_id}")
            except Exception as e:
                print(f"⚠️ [IMAGE] Permission warning: {e}")

            # ✅ Get metadata for STRONG cache-bust token
            bust_token = None
            try:
                meta = service.files().get(
                    fileId=file_id, 
                    fields="modifiedTime,md5Checksum,version"
                ).execute()
                
                # Priority: md5 > version > modifiedTime
                if meta.get('md5Checksum'):
                    bust_token = str(meta['md5Checksum'])[:16]  # First 16 chars of MD5
                    print(f"📌 [IMAGE] Using MD5 cache-bust: {bust_token}")
                elif meta.get('version'):
                    bust_token = f"v{meta['version']}"
                    print(f"📌 [IMAGE] Using version cache-bust: {bust_token}")
                elif meta.get('modifiedTime'):
                    from datetime import datetime
                    dt = datetime.fromisoformat(meta['modifiedTime'].replace('Z', '+00:00'))
                    bust_token = str(int(dt.timestamp()))
                    print(f"📌 [IMAGE] Using timestamp cache-bust: {bust_token}")
                
            except Exception as e:
                print(f"⚠️ [IMAGE] Metadata fetch failed: {e}")
                # Fallback to timestamp
                bust_token = str(int(time.time()))
                print(f"📌 [IMAGE] Using fallback timestamp: {bust_token}")

            # ✅ Build URL with STRONG token
            if bust_token:
                url = f"https://drive.google.com/thumbnail?id={file_id}&sz=w1000&v={bust_token}"
            else:
                url = f"https://drive.google.com/thumbnail?id={file_id}&sz=w1000&t={int(time.time())}"

            # ✅ Cache the NEW URL
            _set_cache(cache_key, url, _image_cache)
            
            print(f"✅ [IMAGE] Generated URL: {url[:100]}...")
            return url

        except Exception as e:
            print(f"❌ [IMAGE] get_public_url error (attempt {attempt}): {e}")
            time.sleep(1)

    # Final fallback with random token
    import random
    fallback_url = f"https://drive.google.com/thumbnail?id={file_id}&sz=w1000&t={int(time.time())}&r={random.randint(1000,9999)}"
    print(f"⚠️ [IMAGE] Using fallback URL: {fallback_url[:100]}...")
    return fallback_url


# -------------------------------------------------------------------
# File/CSV creation helper - UPDATED
# -------------------------------------------------------------------
def create_file_if_not_exists(service, filename: str, parent_folder_id: str | None = None):
    # If no service passed, get the global service
    if not service:
        service = get_drive_service()
    
    if not service:
        return None
    try:
        existing = find_file_by_name(service, filename, parent_folder_id)
        if existing:
            return existing

        meta = {"name": filename, "mimeType": "text/csv"}
        if parent_folder_id:
            meta["parents"] = [parent_folder_id]

        csv = StringIO()
        pd.DataFrame().to_csv(csv, index=False)
        media = MediaIoBaseUpload(BytesIO(csv.getvalue().encode("utf-8")), mimetype="text/csv")

        f = service.files().create(body=meta, media_body=media, fields="id").execute()
        print(f"✅ Created CSV '{filename}' → {f.get('id')}")
        return f.get("id")
    except Exception as e:
        print(f"❌ create_file_if_not_exists error: {e}")
        return None

# -------------------------------------------------------------------
# Folder creation for Subjects - UPDATED
# -------------------------------------------------------------------
def create_subject_folder(service, subject_name: str):
    # If no service passed, get the global service
    if not service:
        service = get_drive_service()
    
    if not service:
        raise RuntimeError("create_subject_folder: no service available")

    parent = os.getenv("IMAGES_FOLDER_ID") or os.getenv("ROOT_FOLDER_ID")
    if not parent:
        raise RuntimeError("IMAGES_FOLDER_ID/ROOT_FOLDER_ID not set in environment")

    try:
        q = (
            "mimeType='application/vnd.google-apps.folder' and "
            f"'{parent}' in parents and trashed=false"
        )
        res = service.files().list(q=q, fields="files(id,name)").execute()
        for f in res.get("files", []):
            if f["name"].strip().lower() == subject_name.strip().lower():
                print(f"📂 Reusing existing subject folder: {f['name']} ({f['id']})")
                return f["id"], datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    except Exception as e:
        print(f"⚠️ list existing subject folders warn: {e}")

    meta = {
        "name": subject_name.strip(),
        "mimeType": "application/vnd.google-apps.folder",
        "parents": [parent]
    }
    f = service.files().create(body=meta, fields="id").execute()
    print(f"✅ Created subject folder '{subject_name}' → {f.get('id')}")
    return f.get("id"), datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# -------------------------------------------------------------------
# USER OAuth Drive client for uploads - UPDATED
# -------------------------------------------------------------------
def create_drive_service_user():
    """
    Try to build a Drive service using a user OAuth token file.
    """
    token_path = os.getenv("GOOGLE_SERVICE_TOKEN_JSON", "token.json")
    scopes = _scopes()

    try:
        if not token_path or not os.path.exists(token_path):
            print(f"❌ token file not found. Set GOOGLE_SERVICE_TOKEN_JSON (got: {token_path})")
            return None

        with open(token_path, "r", encoding="utf-8") as f:
            raw = f.read().strip()

        data = json.loads(raw)

        # CASE 1: Already an authorized-user token.json
        if all(k in data for k in ("refresh_token", "token_uri", "client_id", "client_secret")):
            creds = UserCredentials.from_authorized_user_info(data, scopes=scopes)
            service = build("drive", "v3", credentials=creds, cache_discovery=False)
            try:
                about = service.about().get(fields="user").execute()
                print(f"✅ User OAuth client ready (existing token). Acting as: {about.get('user',{}).get('emailAddress','Unknown')}")
            except Exception:
                print("✅ User OAuth client ready (existing token).")
            return service

        # CASE 2: Client secret JSON → run OAuth flow and save proper token.json back to same path
        if "installed" in data or "web" in data:
            client_config = {"installed": data["installed"]} if "installed" in data else {"web": data["web"]}
            flow = InstalledAppFlow.from_client_config(client_config, scopes=scopes)
            creds = flow.run_local_server(port=0, prompt="consent")

            service = build("drive", "v3", credentials=creds, cache_discovery=False)
            try:
                about = service.about().get(fields="user").execute()
                print(f"✅ User OAuth client ready (new token). Acting as: {about.get('user',{}).get('emailAddress','Unknown')}")
            except Exception:
                print("✅ User OAuth client ready (new token).")

            # Persist authorized token in the SAME file for future runs
            token_to_save = {
                "token": creds.token,
                "refresh_token": creds.refresh_token,
                "token_uri": creds.token_uri,
                "client_id": creds.client_id,
                "client_secret": creds.client_secret,
                "scopes": list(creds.scopes or scopes),
                "expiry": creds.expiry.isoformat() if getattr(creds, "expiry", None) else None,
            }
            with open(token_path, "w", encoding="utf-8") as f:
                json.dump(token_to_save, f)
            print(f"💾 Saved authorized token to {token_path}")
            return service

        # CASE 3: Unknown format → cannot proceed
        print("❌ Provided file is neither an authorized token nor a client secret (web/installed).")
        return None

    except Exception as e:
        print(f"❌ Failed to build user OAuth Drive client: {e}")
        return None

def get_drive_service_for_upload():
    """
    Prefer user OAuth client for uploads. If not available, raise a clear error
    (do NOT silently fall back to service account, which has 0 quota on My Drive).
    """
    user_service = create_drive_service_user()
    if user_service:
        return user_service

    raise RuntimeError(
        "Uploads require a user OAuth token (token.json). "
        "Set GOOGLE_SERVICE_TOKEN_JSON to your token.json or client_secret.json path. "
        "If you provide client_secret.json, a one-time browser window will open to create token.json."
    )
    


def clear_image_cache_immediate(file_id=None):
    if file_id:
        cache_key = f"url::{file_id}"
        _image_cache.pop(cache_key, None)
        _cache_timestamps.pop(cache_key, None)
        print(f"✅ Cleared image cache for file: {file_id}")
    else:
        _image_cache.clear()
        for key in list(_cache_timestamps.keys()):
            if key.startswith("url::"):
                _cache_timestamps.pop(key, None)
        print("✅ Cleared all image caches")    