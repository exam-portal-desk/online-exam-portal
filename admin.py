import os
import mimetypes
import pandas as pd
from functools import wraps
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.utils import secure_filename
from googleapiclient.errors import HttpError
import json
import pandas as pd
from flask import request, jsonify, render_template
import os, json
from flask import session, redirect, url_for, request
from markupsafe import escape
import html
from latex_editor import latex_bp


from sessions import generate_session_token, save_session_record, invalidate_session, get_session_by_token, require_admin_role
from datetime import datetime
from flask import abort, send_file



# ✅ Supabase import
from supabase_db import (
    get_user_by_username, get_user_by_id, get_all_users,
    create_user, update_user, delete_user,
    get_all_exams, get_exam_by_id, create_exam, update_exam, delete_exam,
    get_questions_by_exam, create_question, update_question, delete_question,
    create_session, invalidate_session,
    get_all_results, get_result_by_id, get_results_by_user, get_results_by_exam,
    get_responses_by_result, supabase
)

# Google Drive imports (will be gradually deprecated as we migrate to BigQuery)
from google_drive_service import (
    get_drive_service,
    create_subject_folder,
    find_file_by_name,
    get_drive_service_for_upload
)


# ========== Blueprint ==========
admin_bp = Blueprint("admin", __name__, url_prefix="/admin", template_folder="templates")
admin_bp.register_blueprint(latex_bp)
# ========== Config ==========
#USERS_FILE_ID     = os.environ.get("USERS_FILE_ID")
#EXAMS_FILE_ID     = os.environ.get("EXAMS_FILE_ID")
#QUESTIONS_FILE_ID = os.environ.get("QUESTIONS_FILE_ID")
SUBJECTS_FILE_ID  = os.environ.get("SUBJECTS_FILE_ID")
#REQUESTS_RAISED_FILE_ID = os.environ.get("REQUESTS_RAISED_FILE_ID")
#RESULTS_FILE_ID  = os.environ.get("RESULTS_FILE_ID")
#RESPONSES_FILE_ID  = os.environ.get("RESPONSES_FILE_ID")

UPLOAD_TMP_DIR = os.path.join(os.path.dirname(__file__), "uploads_tmp")
os.makedirs(UPLOAD_TMP_DIR, exist_ok=True)

ALLOWED_IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}
MAX_FILE_SIZE_MB = 15

# Allowed HTML tags for question text (very limited)
BLEACH_ALLOWED_TAGS = ["br", "b", "i", "u", "sup", "sub", "strong", "em"]
BLEACH_ALLOWED_ATTRIBUTES = {}  # no attributes allowed

EXAM_ATTEMPTS_FILE_ID = os.environ.get("EXAM_ATTEMPTS_FILE_ID")

# ========== Helpers ==========
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "admin_id" not in session:
            flash("Admin login required.", "warning")
            return redirect(url_for("admin.admin_login"))
        return f(*args, **kwargs)
    return wrapper

def _get_subject_folders(service=None):
    """Get subject folders from Supabase"""
    out = []
    try:
        from supabase_db import supabase
        
        # Get all subjects from Supabase
        response = supabase.table('subjects').select('*').order('subject_name').execute()
        subjects = response.data if response.data else []
        
        if not subjects:
            return out
        
        for subject in subjects:
            folder_id = str(subject.get('subject_folder_id', '')).strip()
            if folder_id:
                out.append({
                    "id": int(subject.get('id', 0)),
                    "name": str(subject.get('subject_name', '')).strip(),
                    "folder_id": folder_id,
                })
    except Exception as e:
        print(f"⚠️ _get_subject_folders error: {e}")
        import traceback
        traceback.print_exc()
    
    out.sort(key=lambda x: x["name"].lower())
    return out


def sanitize_for_display(text):
    if not text:
        return ""
    # HTML escape sab kuch
    safe = html.escape(str(text))
    # But allow <br> and mathjax ($$...$$)
    safe = safe.replace("&lt;br&gt;", "<br>")
    safe = safe.replace("&lt;br/&gt;", "<br>")
    safe = safe.replace("&dollar;&dollar;", "$$")
    return safe


def sanitize_html(s):
    """
    Lightweight sanitizer used by admin listing.
    - Normalizes newlines (CRLF -> LF)
    - Escapes HTML special chars to prevent injection
    - Returns a plain string (safe for template rendering without |safe)
    """
    if s is None:
        return ""
    s = str(s)
    # normalize newlines
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    # escape HTML special chars
    return str(escape(s))


# Add at top of admin.py after imports:

def safe_float(value, default=0.0):
    """Safely convert to float"""
    if value is None or str(value).strip() in ['', 'None', 'null']:
        return default
    try:
        return float(value)
    except (ValueError, TypeError):
        return default

def safe_int(value, default=0):
    """Safely convert to int"""
    if value is None or str(value).strip() in ['', 'None', 'null']:
        return default
    try:
        return int(float(value))  # Handle "5.0" strings
    except (ValueError, TypeError):
        return default


@admin_bp.route("/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "GET":
        return render_template("admin/admin_login.html")

    if request.method == "POST":
        try:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()

            if not username or not password:
                flash("Username and password required.", "error")
                return redirect(url_for("admin.admin_login"))

            print(f"[admin_login] Login attempt: {username}")

            # ✅ Get user from Supabase
            user = get_user_by_username(username)
            
            if not user:
                flash("Invalid username or password.", "error")
                return redirect(url_for("admin.admin_login"))

            # ✅ VERIFY PASSWORD - Handle both hashed and plain
            stored_password = str(user.get("password", "")).strip()
            
            if not stored_password:
                flash("Account setup incomplete. Please contact administrator.", "error")
                return redirect(url_for("admin.admin_login"))
            
            # Check if password is hashed (bcrypt format)
            password_valid = False
            
            # Import bcrypt functions from main.py
            from main import is_password_hashed, verify_password
            
            if is_password_hashed(stored_password):
                # ✅ BCRYPT VERIFICATION
                password_valid = verify_password(password, stored_password)
                print(f"🔐 [ADMIN_LOGIN] Bcrypt verification for {username}: {password_valid}")
            else:
                # ✅ PLAIN TEXT (backward compatibility)
                password_valid = (stored_password == password)
                print(f"⚠️ [ADMIN_LOGIN] Plain text verification for {username}: {password_valid}")
            
            if not password_valid:
                from login_attempts_cache import record_failed_login, check_login_attempts
                
                record_failed_login(username, request.remote_addr)
                
                # Get remaining attempts
                allowed, error_msg, remaining = check_login_attempts(username, request.remote_addr)
                
                if not allowed:
                    flash(error_msg, "error")
                elif remaining > 0:
                    flash(f"Invalid credentials! {remaining} attempts remaining.", "error")
                else:
                    flash("Invalid credentials!", "error")
                
                return redirect(url_for("admin.admin_login"))

            # ✅ Check admin role
            role = str(user.get("role", "")).lower()
            if "admin" not in role:
                flash("You do not have admin access.", "error")
                return redirect(url_for("admin.admin_login"))
            
            print(f"[admin_login] ✅ Admin verified: {username}")

            # ✅ Invalidate old sessions
            invalidate_session(int(user["id"]))
            session.clear()

            # ✅ Create new session
            import secrets
            token = secrets.token_urlsafe(32)
            
            session_data = {
                "token": token,
                "user_id": int(user["id"]),
                "device_info": request.headers.get("User-Agent", "admin"),
                "is_exam_active": False,
                "admin_session": True,
                "active": True
            }

            create_session(session_data)

            # ✅ Set Flask session
            session.permanent = True
            session['user_id'] = int(user["id"])
            session['admin_id'] = int(user["id"])
            session['token'] = token
            session['username'] = user.get("username")
            session['full_name'] = user.get("full_name", user.get("username"))
            session['is_admin'] = True
            session.modified = True

            print(f"[admin_login] ✅ Login successful!")
            flash("Admin login successful!", "success")
            return redirect(url_for("admin.dashboard"))

        except Exception as e:
            print(f"[admin_login] ERROR: {e}")
            import traceback
            traceback.print_exc()
            flash("Login error.", "error")
            return redirect(url_for("admin.admin_login"))


def _parse_max_attempts(raw):
    if raw is None:
        return None
    s = str(raw).strip()
    if s == "":
        return None
    if not s.isdigit():
        raise ValueError("max_attempts must be a non-negative integer")
    val = int(s)
    if val < 0:
        raise ValueError("max_attempts must be non-negative")
    return val

@admin_bp.route("/logout")
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
                    print(f"[admin_logout] Background cleanup error: {e}")
            
            import threading
            cleanup_thread = threading.Thread(target=cleanup, daemon=True)
            cleanup_thread.start()
        
        flash("Admin logout successful.", "success")
        return render_template('logout_redirect.html', is_admin=True)
        
    except Exception as e:
        print(f"[admin_logout] Error: {e}")
        session.clear()
        flash("Admin logout successful.", "success")
        return render_template('logout_redirect.html', is_admin=True)

# ========== Dashboard ==========
@admin_bp.route("/dashboard")
@require_admin_role
def dashboard():
    try:
        # ✅ Get data from Supabase
        exams = get_all_exams()
        users = get_all_users()

        total_exams = len(exams) if exams else 0
        total_users = len(users) if users else 0

        # Count admins
        admins_count = 0
        if users:
            for user in users:
                role = str(user.get('role', '')).strip().lower()
                if 'admin' in role:
                    admins_count += 1

        stats = {
            "total_exams": total_exams,
            "total_users": total_users,
            "total_admins": admins_count,
        }
        return render_template("admin/dashboard.html", stats=stats)
    
    except Exception as e:
        print(f"Dashboard error: {e}")
        flash("Error loading dashboard.", "error")
        return render_template("admin/dashboard.html", stats={})

# ========== Subjects ==========
@admin_bp.route("/subjects", methods=["GET", "POST"])
@require_admin_role
def subjects():
    """Subjects management using Supabase"""
    
    if request.method == "POST":
        subject_name = request.form["subject_name"].strip()
        if not subject_name:
            flash("Subject name required.", "danger")
            return redirect(url_for("admin.subjects"))
        
        # Check if subject already exists in Supabase
        from supabase_db import supabase
        
        try:
            response = supabase.table('subjects').select('*').eq('subject_name', subject_name).execute()
            if response.data:
                flash("Subject already exists.", "warning")
                return redirect(url_for("admin.subjects"))
        except:
            pass
        
        # Create Drive folder
        try:
            drive_owner = get_drive_service_for_upload()
        except Exception as e:
            flash(f"Cannot create folder: {e}", "danger")
            return redirect(url_for("admin.subjects"))
        
        folder_id, created_at = create_subject_folder(drive_owner, subject_name)
        
        # Insert into Supabase
        new_subject = {
            "subject_name": subject_name,
            "subject_folder_id": folder_id,
            "subject_folder_created_at": created_at
        }
        
        try:
            supabase.table('subjects').insert(new_subject).execute()
            flash(f"Subject '{subject_name}' created successfully.", "success")
        except Exception as e:
            print(f"Error creating subject: {e}")
            flash("Failed to create subject in database.", "danger")
        
        return redirect(url_for("admin.subjects"))
    
    # GET: Load subjects from Supabase
    from supabase_db import supabase
    
    try:
        response = supabase.table('subjects').select('*').order('subject_name').execute()
        subjects_list = response.data if response.data else []
    except Exception as e:
        print(f"Error loading subjects: {e}")
        subjects_list = []
    
    return render_template("admin/subjects.html", subjects=subjects_list)

@admin_bp.route("/subjects/edit/<int:subject_id>", methods=["POST"])
@require_admin_role
def edit_subject(subject_id):
    """Edit subject using Supabase"""
    
    from supabase_db import supabase
    
    # Get subject from Supabase
    try:
        response = supabase.table('subjects').select('*').eq('id', subject_id).execute()
        subject = response.data[0] if response.data else None
    except:
        subject = None
    
    if not subject:
        flash("Subject not found.", "danger")
        return redirect(url_for("admin.subjects"))
    
    new_name = request.form.get("subject_name", "").strip()
    if not new_name:
        flash("Subject name required.", "danger")
        return redirect(url_for("admin.subjects"))
    
    folder_id = subject.get("subject_folder_id", "")
    
    # Update Drive folder name
    try:
        drive_owner = get_drive_service_for_upload()
        drive_owner.files().update(fileId=folder_id, body={"name": new_name}).execute()
    except Exception as e:
        print(f"⚠️ Rename folder failed: {e}")
        flash("Drive folder rename failed; database updated.", "warning")
    
    # Update in Supabase
    try:
        supabase.table('subjects').update({'subject_name': new_name}).eq('id', subject_id).execute()
        flash("Subject updated successfully.", "success")
    except Exception as e:
        print(f"Error updating subject: {e}")
        flash("Failed to update subject in database.", "danger")
    
    return redirect(url_for("admin.subjects"))

@admin_bp.route("/subjects/delete/<int:subject_id>")
@require_admin_role
def delete_subject(subject_id):
    """Delete subject using Supabase"""
    
    from supabase_db import supabase
    
    # Get subject from Supabase
    try:
        response = supabase.table('subjects').select('*').eq('id', subject_id).execute()
        subject = response.data[0] if response.data else None
    except:
        subject = None
    
    if not subject:
        flash("Subject not found.", "warning")
        return redirect(url_for("admin.subjects"))
    
    folder_id = str(subject.get("subject_folder_id", "")).strip()
    
    # Try to delete Drive folder
    if folder_id:
        try:
            drive_owner = get_drive_service_for_upload()
            try:
                drive_owner.files().delete(fileId=folder_id, supportsAllDrives=True).execute()
                print(f"✅ Deleted folder {folder_id}")
            except Exception as e_del:
                print(f"⚠ Delete failed: {e_del} — trying to trash")
                try:
                    drive_owner.files().update(fileId=folder_id, body={"trashed": True}, supportsAllDrives=True).execute()
                    print(f"♻ Trashed folder {folder_id}")
                except Exception as e_trash:
                    print(f"❌ Failed to trash: {e_trash}")
        except Exception as e:
            print(f"⚠ Drive service error: {e}")
    
    # Delete from Supabase
    try:
        supabase.table('subjects').delete().eq('id', subject_id).execute()
        flash("Subject deleted successfully.", "info")
    except Exception as e:
        print(f"Error deleting subject: {e}")
        flash("Failed to delete subject from database.", "danger")
    
    return redirect(url_for("admin.subjects"))

# ========== Exams ==========
@admin_bp.route("/exams", methods=["GET", "POST"])
@require_admin_role
def exams():
    """Exams management using Supabase"""
    
    if request.method == "POST":
        form = request.form
        
        try:
            parsed_max = _parse_max_attempts(form.get("max_attempts", ""))
        except ValueError as e:
            flash(str(e), "danger")
            return redirect(url_for("admin.exams"))
        
        new_exam = {
            "name": form.get("name", "").strip(),
            "date": form.get("date", "").strip(),
            "start_time": form.get("start_time", "").strip(),
            "duration": int(form.get("duration") or 60),
            "total_questions": int(form.get("total_questions") or 0),
            "status": form.get("status", "draft").strip(),
            "instructions": form.get("instructions", "").strip(),
            "positive_marks": form.get("positive_marks", "1").strip(),
            "negative_marks": form.get("negative_marks", "0").strip(),
            "max_attempts": parsed_max
        }
        
        result = create_exam(new_exam)
        
        if result:
            flash("Exam created successfully.", "success")
        else:
            flash("Failed to create exam.", "error")
            
        return redirect(url_for("admin.exams"))
    
    exams_list = get_all_exams()
    return render_template("admin/exams.html", exams=exams_list)


@admin_bp.route("/exams/edit/<int:exam_id>", methods=["GET", "POST"])
@require_admin_role
def edit_exam(exam_id):
    """Edit exam using Supabase"""
    
    exam = get_exam_by_id(exam_id)
    if not exam:
        flash("Exam not found.", "danger")
        return redirect(url_for("admin.exams"))
    
    if request.method == "POST":
        form = request.form
        try:
            duration_val = int(form.get("duration") or 0)
            total_q_val = int(form.get("total_questions") or 0)
        except Exception:
            flash("Duration and Total Questions must be integers.", "danger")
            return redirect(url_for("admin.edit_exam", exam_id=exam_id))
        
        try:
            parsed_max = _parse_max_attempts(form.get("max_attempts", ""))
        except ValueError as e:
            flash(str(e), "danger")
            return redirect(url_for("admin.edit_exam", exam_id=exam_id))
        
        updated_fields = {
            "name": form.get("name", "").strip(),
            "date": form.get("date", "").strip(),
            "start_time": form.get("start_time", "").strip(),
            "duration": duration_val,
            "total_questions": total_q_val,
            "status": form.get("status", "").strip(),
            "instructions": form.get("instructions", "").strip(),
            "positive_marks": form.get("positive_marks", "").strip(),
            "negative_marks": form.get("negative_marks", "").strip(),
            "max_attempts": parsed_max
        }
        
        if update_exam(exam_id, updated_fields):
            flash("Exam updated successfully.", "success")
            return redirect(url_for("admin.exams"))
        else:
            flash("Failed to save exam changes.", "danger")
            return redirect(url_for("admin.edit_exam", exam_id=exam_id))
    
    return render_template("admin/edit_exam.html", exam=exam)

@admin_bp.route("/exams/delete/<int:exam_id>", methods=["POST"])  # ✅ POST only
@require_admin_role
def delete_exam(exam_id):
    """Delete exam with cascade (questions, results, responses)"""
    try:
        from supabase_db import supabase
        
        # Get exam name
        exam = get_exam_by_id(exam_id)
        if not exam:
            return jsonify({"success": False, "message": "Exam not found"}), 404
        
        exam_name = exam.get('name', f'Exam {exam_id}')
        
        # ✅ CASCADE DELETE
        try:
            # 1. Delete responses (via results)
            results = get_results_by_exam(exam_id)
            for result in results:
                supabase.table('responses').delete().eq('result_id', result['id']).execute()
            
            # 2. Delete results
            supabase.table('results').delete().eq('exam_id', exam_id).execute()
            
            # 3. Delete attempts
            supabase.table('exam_attempts').delete().eq('exam_id', exam_id).execute()
            
            # 4. Delete questions
            supabase.table('questions').delete().eq('exam_id', exam_id).execute()
            
            # 5. Delete exam
            supabase.table('exams').delete().eq('id', exam_id).execute()
            
            return jsonify({
                "success": True, 
                "message": f"Exam '{exam_name}' and all related data deleted successfully"
            })
        
        except Exception as e:
            print(f"Error in cascade delete: {e}")
            return jsonify({"success": False, "message": str(e)}), 500
    
    except Exception as e:
        print(f"Error deleting exam: {e}")
        return jsonify({"success": False, "message": str(e)}), 500



@admin_bp.route("/questions", methods=["GET"])
@require_admin_role
def questions_index():
    """Questions listing using Supabase"""
    
    # Get all exams for filter
    exams = get_all_exams()
    exams_list = []
    for exam in exams:
        exams_list.append({
            "id": int(exam.get("id")),
            "name": exam.get("name", f"Exam {exam.get('id')}")
        })
    
    # Get selected exam
    selected_exam_id = request.args.get("exam_id", type=int)
    if not selected_exam_id and exams_list:
        selected_exam_id = exams_list[0]["id"]
    
    # Get questions for selected exam
    questions_list = []
    if selected_exam_id:
        questions = get_questions_by_exam(selected_exam_id)
        for q in questions:
            questions_list.append({
                "id": int(q.get("id")),
                "exam_id": int(q.get("exam_id")),
                "question_text": sanitize_html(q.get("question_text", "")),
                "option_a": sanitize_html(q.get("option_a", "")),
                "option_b": sanitize_html(q.get("option_b", "")),
                "option_c": sanitize_html(q.get("option_c", "")),
                "option_d": sanitize_html(q.get("option_d", "")),
                "correct_answer": q.get("correct_answer", ""),
                "question_type": q.get("question_type", "MCQ"),
                "image_path": q.get("image_path", ""),
                "positive_marks": q.get("positive_marks", "4"),
                "negative_marks": q.get("negative_marks", "1"),
                "tolerance": q.get("tolerance", "")
            })
    
    return render_template("admin/questions.html",
                         exams=exams_list,
                         selected_exam_id=selected_exam_id,
                         questions=questions_list)

@admin_bp.route("/questions/add", methods=["GET", "POST"])
@require_admin_role
def add_question():
    """Add question using Supabase"""
    
    # Get exams for dropdown
    exams = get_all_exams()
    exams_list = []
    for exam in exams:
        exams_list.append({
            "id": int(exam.get("id")),
            "name": exam.get("name", f"Exam {exam.get('id')}")
        })
    
    if request.method == "POST":
        data = request.form.to_dict()
        
        new_question = {
            "exam_id": int(data.get("exam_id") or 0),
            "question_text": data.get("question_text", "").strip(),
            "option_a": data.get("option_a", "").strip(),
            "option_b": data.get("option_b", "").strip(),
            "option_c": data.get("option_c", "").strip(),
            "option_d": data.get("option_d", "").strip(),
            "correct_answer": data.get("correct_answer", "").strip(),
            "question_type": data.get("question_type", "MCQ").strip(),
            "image_path": data.get("image_path", "").strip(),
            "tolerance": safe_float(data.get("tolerance"), 0),
            "positive_marks": safe_int(data.get("positive_marks"), 4),
            "negative_marks": safe_float(data.get("negative_marks"), 1)
        }
        
        result = create_question(new_question)
        
        if result:
            flash("Question added successfully.", "success")
            return redirect(url_for("admin.questions_index", exam_id=new_question["exam_id"]))
        else:
            flash("Failed to add question.", "danger")
            return redirect(url_for("admin.add_question"))
    
    return render_template("admin/add_question.html", exams=exams_list, question=None, form_mode="add")

@admin_bp.route("/questions/edit/<int:question_id>", methods=["GET", "POST"])
@require_admin_role
def edit_question(question_id):
    """Edit question using Supabase"""
    
    # Get exams for dropdown
    exams = get_all_exams()
    exams_list = []
    for exam in exams:
        exams_list.append({
            "id": int(exam.get("id")),
            "name": exam.get("name", f"Exam {exam.get('id')}")
        })
    
    # Get question
    from supabase_db import supabase
    
    try:
        response = supabase.table('questions').select('*').eq('id', question_id).execute()
        question = response.data[0] if response.data else None
    except:
        question = None
    
    if not question:
        flash("Question not found.", "danger")
        return redirect(url_for("admin.questions_index"))
    
    if request.method == "POST":
        data = request.form.to_dict()
        
        updated_data = {
            "exam_id": int(data.get("exam_id") or question.get("exam_id")),
            "question_text": data.get("question_text", "").strip(),
            "option_a": data.get("option_a", "").strip(),
            "option_b": data.get("option_b", "").strip(),
            "option_c": data.get("option_c", "").strip(),
            "option_d": data.get("option_d", "").strip(),
            "correct_answer": data.get("correct_answer", "").strip(),
            "question_type": data.get("question_type", "MCQ").strip(),
            "image_path": data.get("image_path", "").strip(),
            "tolerance": safe_float(data.get("tolerance"), 0),
            "positive_marks": safe_int(data.get("positive_marks"), 4),
            "negative_marks": safe_float(data.get("negative_marks"), 1)
        }
        
        if update_question(question_id, updated_data):
            flash("Question updated successfully.", "success")
            return redirect(url_for("admin.questions_index", exam_id=updated_data["exam_id"]))
        else:
            flash("Failed to update question.", "danger")
            return redirect(url_for("admin.edit_question", question_id=question_id))
    
    return render_template("admin/edit_question.html", exams=exams_list, question=question, form_mode="edit")

@admin_bp.route("/questions/delete/<int:question_id>", methods=["POST"])
@require_admin_role
def delete_question(question_id):
    """Delete question from Supabase"""
    
    # Get question to find exam_id
    from supabase_db import supabase
    
    try:
        response = supabase.table('questions').select('exam_id').eq('id', question_id).execute()
        exam_id = response.data[0]['exam_id'] if response.data else None
    except:
        exam_id = None
    
    # Delete question
    from supabase_db import delete_question as db_delete_question
    
    if db_delete_question(question_id):
        flash("Question deleted successfully.", "info")
    else:
        flash("Failed to delete question.", "danger")
    
    if exam_id:
        return redirect(url_for("admin.questions_index", exam_id=exam_id))
    else:
        return redirect(url_for("admin.questions_index"))

@admin_bp.route("/questions/delete-multiple", methods=["POST"])
@require_admin_role
def delete_multiple_questions():
    """Delete multiple questions from Supabase"""
    try:
        payload = request.get_json(force=True)
        if not payload or "ids" not in payload:
            return jsonify({"success": False, "message": "Invalid payload"}), 400

        ids = payload.get("ids") or []
        if not isinstance(ids, list) or not ids:
            return jsonify({"success": False, "message": "No IDs provided"}), 400

        ids_int = [int(i) for i in ids if str(i).strip()]

        from supabase_db import supabase
        
        deleted_count = 0
        for question_id in ids_int:
            try:
                supabase.table('questions').delete().eq('id', question_id).execute()
                deleted_count += 1
            except Exception as e:
                print(f"Failed to delete question {question_id}: {e}")
                continue

        return jsonify({"success": True, "deleted": deleted_count})

    except Exception as e:
        print(f"❌ delete_multiple_questions error: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

@admin_bp.route("/questions/bulk-update", methods=["POST"])
@require_admin_role
def questions_bulk_update():
    """Bulk update questions marks/tolerance in Supabase"""
    try:
        payload = request.get_json(force=True)
        if not payload:
            return jsonify({"success": False, "message": "Empty payload"}), 400

        exam_id = payload.get("exam_id")
        qtype = str(payload.get("question_type") or "").strip()
        pos = payload.get("positive_marks")
        neg = payload.get("negative_marks")
        tol = payload.get("tolerance")

        if not exam_id:
            return jsonify({"success": False, "message": "exam_id required"}), 400
        if not qtype:
            return jsonify({"success": False, "message": "question_type required"}), 400

        # Get questions for this exam and type
        questions = get_questions_by_exam(exam_id)
        
        matching_questions = [
            q for q in questions 
            if str(q.get('question_type', '')).strip().upper() == qtype.upper()
        ]

        if not matching_questions:
            return jsonify({"success": True, "updated": 0, "message": "No matching questions found"}), 200

        from supabase_db import supabase
        
        updated_count = 0
        for q in matching_questions:
            question_id = int(q.get('id'))
            
            update_data = {}
            if pos is not None and str(pos).strip() != "":
                update_data['positive_marks'] = int(pos)
            if neg is not None and str(neg).strip() != "":
                update_data['negative_marks'] = float(neg)
            if tol is not None:
                update_data['tolerance'] = float(tol)
            
            if update_data:
                try:
                    supabase.table('questions').update(update_data).eq('id', question_id).execute()
                    updated_count += 1
                except Exception as e:
                    print(f"Failed to update question {question_id}: {e}")
                    continue

        return jsonify({"success": True, "updated": updated_count}), 200

    except Exception as e:
        print(f"❌ questions_bulk_update error: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

# ========== Upload Images ==========
from googleapiclient.http import MediaIoBaseUpload  # add near other imports
import io

@admin_bp.route("/upload-images", methods=["GET", "POST"])
@require_admin_role
def upload_images_page():
    if request.method == "POST":
        try:
            folder_id = request.form.get("subject_folder_id", "").strip()
            files = request.files.getlist("images")

            if not folder_id:
                return jsonify({"success": False, "message": "No folder selected."}), 400
            if not files:
                return jsonify({"success": False, "message": "No files received."}), 400

            try:
                drive_upload = get_drive_service_for_upload()
            except Exception as e:
                return jsonify({"success": False, "message": str(e)}), 500

            uploaded = 0
            failed = []

            for f in files:
                if not f or not f.filename:
                    continue
                safe_name = secure_filename(f.filename)
                ext = os.path.splitext(safe_name)[1].lower()
                if ext not in ALLOWED_IMAGE_EXTS:
                    failed.append({"filename": safe_name, "error": f"Not allowed type ({ext})"})
                    continue

                f.seek(0, os.SEEK_END)
                size_mb = f.tell() / (1024 * 1024)
                f.seek(0)
                if size_mb > MAX_FILE_SIZE_MB:
                    failed.append({"filename": safe_name, "error": f"Exceeds {MAX_FILE_SIZE_MB} MB"})
                    continue

                temp_path = os.path.join(UPLOAD_TMP_DIR, safe_name)
                f.save(temp_path)

                fh = None
                try:
                    existing_id = find_file_by_name(drive_upload, safe_name, folder_id)
                    mime, _ = mimetypes.guess_type(safe_name)
                    fh = open(temp_path, "rb")
                    media = MediaIoBaseUpload(fh, mimetype=mime or "application/octet-stream", resumable=True)

                    new_file_id = None
                    if existing_id:
                        # Capture response; some update calls return metadata
                        try:
                            res = drive_upload.files().update(fileId=existing_id, media_body=media, fields="id").execute()
                            new_file_id = res.get('id') if isinstance(res, dict) and res.get('id') else existing_id
                        except Exception:
                            # fallback: assume existing_id still valid
                            new_file_id = existing_id
                    else:
                        res = drive_upload.files().create(
                            body={"name": safe_name, "parents": [folder_id]},
                            media_body=media,
                            fields="id"
                        ).execute()
                        new_file_id = res.get('id') if isinstance(res, dict) else None

                    uploaded += 1

                    # Clear caches for this file so latest image appears immediately
                    try:
                        from google_drive_service import clear_image_cache_immediate
                        from main import app_cache

                        if new_file_id:
                            clear_image_cache_immediate(new_file_id)

                            # Remove any app_cache image entries that reference this file id (URL contains id=)
                            imgs = app_cache.get('images', {})
                            if imgs:
                                keys_to_remove = [k for k, v in list(imgs.items()) if v and str(new_file_id) in str(v)]
                                for k in keys_to_remove:
                                    imgs.pop(k, None)
                                    app_cache.get('timestamps', {}).pop(k, None)

                            # Set force_refresh so the next preload will rebuild session image URLs
                            app_cache['force_refresh'] = True
                            try:
                                from flask import session
                                session['force_refresh'] = True
                                session.modified = True
                            except Exception:
                                pass

                            print(f"✅ Cleared image caches for uploaded file: {new_file_id}")
                    except Exception as cache_err:
                        print(f"⚠️ Cache clear after upload failed: {cache_err}")
                except HttpError as e:
                    failed.append({"filename": safe_name, "error": str(e)})
                except Exception as e:
                    failed.append({"filename": safe_name, "error": str(e)})
                finally:
                    try:
                        if fh and not fh.closed:
                            fh.close()
                    except Exception as _close_err:
                        print(f"⚠ Could not close temp file handle for {temp_path}: {_close_err}")
                    try:
                        if os.path.exists(temp_path):
                            os.remove(temp_path)
                    except Exception as rm_err:
                        print(f"⚠ Could not remove temp file {temp_path}: {rm_err}")

            return jsonify({"success": True, "uploaded": uploaded, "failed": failed}), 200

        except Exception as e:
            return jsonify({"success": False, "message": f"Unexpected error: {str(e)}"}), 500

    sa = get_drive_service()
    subjects = _get_subject_folders(sa)
    load_error = None if subjects else "No subjects found (or subjects.csv missing)."
    return render_template(
        "admin/upload_images.html",
        subjects=subjects,
        load_error=load_error
    )

@admin_bp.route("/questions/batch-add", methods=["POST"])
@require_admin_role
def questions_batch_add():
    """Batch add questions to Supabase"""
    try:
        payload = request.get_json(force=True)
        if not payload or "questions" not in payload or "exam_id" not in payload:
            return jsonify({"success": False, "message": "Invalid payload"}), 400

        exam_id = int(payload.get("exam_id"))
        items = payload.get("questions", [])
        if not items:
            return jsonify({"success": False, "message": "No questions provided"}), 400

        from supabase_db import supabase
        
        new_rows = []
        added_count = 0
        
        for it in items:
            qt = (it.get("question_text") or "").strip()
            if not qt:
                continue
            
            row = {
                "exam_id": exam_id,
                "question_text": qt,
                "option_a": (it.get("option_a") or "").strip(),
                "option_b": (it.get("option_b") or "").strip(),
                "option_c": (it.get("option_c") or "").strip(),
                "option_d": (it.get("option_d") or "").strip(),
                "correct_answer": (it.get("correct_answer") or "").strip(),
                "question_type": (it.get("question_type") or "MCQ").strip(),
                "image_path": (it.get("image_path") or "").strip(),
                "positive_marks": safe_int(it.get("positive_marks"), 4),
                "negative_marks": safe_float(it.get("negative_marks") or 1),
                "tolerance": safe_float(it.get("tolerance") or 0)
            }
            new_rows.append(row)

        if not new_rows:
            return jsonify({"success": False, "message": "No valid rows to add"}), 400

        # Insert all at once
        try:
            supabase.table('questions').insert(new_rows).execute()
            added_count = len(new_rows)
        except Exception as e:
            print(f"Batch insert failed: {e}")
            return jsonify({"success": False, "message": "Failed to save to Supabase"}), 500

        return jsonify({"success": True, "added": added_count})

    except Exception as e:
        print(f"❌ questions_batch_add error: {e}")
        return jsonify({"success": False, "message": str(e)}), 500
    
    
# ========== Publish ==========
@admin_bp.route("/publish", methods=["GET", "POST"])
@require_admin_role
def publish():
    """Enhanced publish with proper force refresh flags"""
    
    if request.method == "POST":
        try:
            print("🔄 [PUBLISH] Starting cache clear...")
            
            # ✅ 1. Clear Drive cache
            from google_drive_service import clear_cache, clear_image_cache_immediate
            clear_cache()
            clear_image_cache_immediate()
            print("✅ [PUBLISH] Drive image cache cleared")
            
            # ✅ 2. Clear app cache
            from main import app_cache, clear_user_cache
            
            app_cache['data'].clear()
            app_cache['images'].clear()
            app_cache['timestamps'].clear()
            app_cache['force_refresh'] = True  # ✅ SET FLAG
            
            clear_user_cache()
            
            print("✅ [PUBLISH] App cache cleared")
            
            # ✅ 3. Set GLOBAL session flag (for ALL users)
            try:
                from flask import current_app
                with current_app.app_context():
                    # Store in app config (survives across requests)
                    import time
                    current_app.config['FORCE_REFRESH_TIMESTAMP'] = time.time()
                    print(f"✅ [PUBLISH] Global refresh timestamp: {current_app.config['FORCE_REFRESH_TIMESTAMP']}")
            except Exception as e:
                print(f"⚠️ [PUBLISH] Global flag error: {e}")
            
            # ✅ 4. Set session flag (for current admin)
            session["force_refresh"] = True  # ✅ SET FLAG
            session.modified = True
            print("✅ [PUBLISH] Session refresh flag set")
            
            print("🎉 [PUBLISH] Cache clear completed!")
            flash("✅ All caches cleared! Fresh data and images will load now.", "success")
            
        except Exception as e:
            print(f"❌ [PUBLISH] Error: {e}")
            import traceback
            traceback.print_exc()
            flash("⚠️ Cache clear completed with some errors.", "warning")
        
        return redirect(url_for("admin.dashboard"))
    
    return render_template("admin/publish.html")

# --- START: Web OAuth routes for admin (paste into admin.py) ---


# Make sure your Flask app sets a secret key (main.py already may do this).
# These routes are under admin_bp (url_prefix="/admin"), so redirect URIs must include /admin/oauth2callback

@admin_bp.route("/authorize", methods=["GET"])
@require_admin_role
def admin_oauth_authorize():
    """
    Start web-OAuth flow (one-time). User (admin) must visit this and approve Google Drive scopes.
    Requires GOOGLE_OAUTH_CLIENT_JSON env (client_secret.json content or path).
    """
    from google_auth_oauthlib.flow import Flow

    raw = os.getenv("GOOGLE_OAUTH_CLIENT_JSON")
    if not raw:
        return "Missing GOOGLE_OAUTH_CLIENT_JSON env. Paste your client_secret_web.json here.", 500

    # Accept either raw JSON text or a file path
    try:
        cfg = json.loads(raw) if raw.strip().startswith("{") else json.load(open(raw, "r", encoding="utf-8"))
    except Exception as e:
        return f"Failed to load client JSON: {e}", 500

    # prefer 'web' key if present
    client_cfg = {"web": cfg.get("web")} if "web" in cfg else {"installed": cfg.get("installed", cfg)}
    scopes = ["https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/drive.file", "https://www.googleapis.com/auth/drive.readonly"]

    flow = Flow.from_client_config(client_cfg, scopes=scopes)
    # redirect URI must match EXACTLY what's in Google Cloud Console (see instructions)
    flow.redirect_uri = url_for("admin.admin_oauth_callback", _external=True)

    auth_url, state = flow.authorization_url(access_type="offline", include_granted_scopes="true", prompt="consent")
    session["oauth_state"] = state
    return redirect(auth_url)

@admin_bp.route("/oauth2callback", methods=["GET"])
@require_admin_role
def admin_oauth_callback():
    """
    OAuth callback for admin authorize. Exchanges code -> token and attempts to save token.json.
    If server can't write file, it will return the token JSON so you can paste it into Render env.
    """
    from google_auth_oauthlib.flow import Flow
    from google.oauth2.credentials import Credentials as UserCredentials
    from googleapiclient.discovery import build
    import datetime

    raw = os.getenv("GOOGLE_OAUTH_CLIENT_JSON")
    if not raw:
        return "Missing GOOGLE_OAUTH_CLIENT_JSON env. Cannot complete auth.", 500

    try:
        cfg = json.loads(raw) if raw.strip().startswith("{") else json.load(open(raw, "r", encoding="utf-8"))
    except Exception as e:
        return f"Failed to load client JSON: {e}", 500

    client_cfg = {"web": cfg.get("web")} if "web" in cfg else {"installed": cfg.get("installed", cfg)}
    scopes = ["https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/drive.file", "https://www.googleapis.com/auth/drive.readonly"]

    state = session.get("oauth_state")
    flow = Flow.from_client_config(client_cfg, scopes=scopes, state=state)
    flow.redirect_uri = url_for("admin.admin_oauth_callback", _external=True)

    # Exchange code
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials

    token_obj = {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": list(creds.scopes or scopes),
        "expiry": creds.expiry.isoformat() if getattr(creds, "expiry", None) else None
    }

    # Try to save to disk (token.json path) — fallback is to display JSON for manual copy
    token_path = os.getenv("GOOGLE_SERVICE_TOKEN_JSON", "token.json")
    try:
        with open(token_path, "w", encoding="utf-8") as f:
            json.dump(token_obj, f)
        # Try to read Drive user email to confirm
        try:
            creds_obj = UserCredentials.from_authorized_user_info(token_obj, scopes=scopes)
            svc = build("drive", "v3", credentials=creds_obj, cache_discovery=False)
            about = svc.about().get(fields="user").execute()
            email = about.get("user", {}).get("emailAddress", "unknown")
            return f"Success — token saved to <code>{token_path}</code>. Authorized as: {email}"
        except Exception:
            return f"Success — token saved to <code>{token_path}</code>. Authorization complete."
    except Exception as e:
        # If cannot write, return token JSON so user can copy-paste into Render env
        pretty = json.dumps(token_obj, indent=2)
        return (
            "Could not write token.json on server. Copy the JSON below and set it as the value of the "
            "<code>GOOGLE_SERVICE_TOKEN_JSON</code> environment variable in Render (paste full JSON):"
            + "<pre>" + pretty + "</pre>"
        )

# --- END: Web OAuth routes for admin ---

@admin_bp.route("/attempts")
@require_admin_role
def attempts():
    """Display exam attempts using Supabase"""
    
    from supabase_db import supabase
    
    try:
        # Get data from Supabase
        users_response = supabase.table('users').select('*').execute()
        users = users_response.data if users_response.data else []
        
        exams_response = supabase.table('exams').select('*').execute()
        exams = exams_response.data if exams_response.data else []
        
        attempts_response = supabase.table('exam_attempts').select('*').execute()
        attempts = attempts_response.data if attempts_response.data else []
    except Exception as e:
        print(f"Error loading attempts data: {e}")
        users = []
        exams = []
        attempts = []
    
    rows = []
    for u in users:
        for e in exams:
            student_id, exam_id = str(u["id"]), str(e["id"])
            user_attempts = [a for a in attempts
                           if str(a["student_id"]) == student_id and str(a["exam_id"]) == exam_id]
            used = len(user_attempts)
            
            max_att_raw = e.get("max_attempts", "")
            
            if max_att_raw is None or max_att_raw == "":
                max_att = ""
            else:
                max_att = str(max_att_raw).strip()
            
            if max_att == "" or max_att == "0" or max_att.lower() == "nan":
                remaining = "∞"
                display_max = "∞"
            else:
                try:
                    max_attempts_int = int(float(max_att))
                    remaining = max(max_attempts_int - used, 0)
                    display_max = str(max_attempts_int)
                except (ValueError, TypeError):
                    remaining = "?"
                    display_max = max_att
            
            rows.append({
                "student_id": student_id,
                "username": u.get("username"),
                "exam_id": exam_id,
                "exam_name": e.get("name"),
                "max_attempts": display_max,
                "attempts_used": used,
                "remaining": remaining
            })
    
    return render_template("admin/attempts.html", rows=rows)


@admin_bp.route("/attempts/modify", methods=["POST"])
@require_admin_role
def attempts_modify():
    """Modify attempts using Supabase"""
    
    from supabase_db import supabase
    from datetime import datetime
    
    try:
        payload = request.get_json(force=True)
        student_id = str(payload.get("student_id"))
        exam_id = str(payload.get("exam_id"))
        action = payload.get("action")
        amount = int(payload.get("amount") or 0)
        
        # Get current attempts
        response = supabase.table('exam_attempts').select('*').eq('student_id', student_id).eq('exam_id', exam_id).execute()
        current_attempts = response.data if response.data else []
        used = len(current_attempts)
        
        if action == "reset":
            # Delete all attempts for this user-exam combo
            for attempt in current_attempts:
                supabase.table('exam_attempts').delete().eq('id', attempt['id']).execute()
        
        elif action == "decrease":
            if used >= amount:
                # Delete last N attempts
                sorted_attempts = sorted(current_attempts, key=lambda x: x.get('id', 0))
                to_delete = sorted_attempts[-amount:]
                for attempt in to_delete:
                    supabase.table('exam_attempts').delete().eq('id', attempt['id']).execute()
            else:
                return jsonify({"success": False, "message": f"Not enough attempts to remove"}), 400
        
        elif action == "increase":
            # Add new attempts
            for i in range(amount):
                new_attempt = {
                    "student_id": int(student_id),
                    "exam_id": int(exam_id),
                    "attempt_number": used + i + 1,
                    "status": "manual_add",
                    "start_time": datetime.now().isoformat(),
                    "end_time": None
                }
                supabase.table('exam_attempts').insert(new_attempt).execute()
        
        return jsonify({"success": True})
    
    except Exception as e:
        print(f"Error modifying attempts: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "message": str(e)}), 500




@admin_bp.route("/requests")
@require_admin_role
def requests_dashboard():
    """Requests dashboard with new and history tabs"""
    return render_template("admin/requests.html")

@admin_bp.route("/requests/new")
@require_admin_role
def new_requests():
    """View new (pending) access requests from Supabase"""
    try:
        from supabase_db import supabase
        
        # Get pending requests from Supabase
        response = supabase.table('requests_raised').select('*').eq('request_status', 'pending').order('request_date', desc=True).execute()
        
        pending_requests = response.data if response.data else []
        
        # Convert to list for template
        requests_list = []
        for req in pending_requests:
            requests_list.append({
                'request_id': int(req.get('request_id', 0)),
                'username': req.get('username', ''),
                'email': req.get('email', ''),
                'current_access': req.get('current_access', ''),
                'requested_access': req.get('requested_access', ''),
                'request_date': req.get('request_date', ''),
                'status': req.get('request_status', ''),
                'reason': req.get('reason', '')  # ✅ ADD THIS LINE
            })
        
        return render_template("admin/new_requests.html", requests=requests_list)
    
    except Exception as e:
        print(f"Error loading new requests: {e}")
        flash("Error loading requests data.", "error")
        return render_template("admin/new_requests.html", requests=[])

@admin_bp.route("/requests/history")
@require_admin_role
def requests_history():
    """View completed/denied requests history from Supabase"""
    try:
        from supabase_db import supabase
        
        # Get completed/denied requests from Supabase
        response = supabase.table('requests_raised').select('*').in_('request_status', ['completed', 'denied']).order('request_date', desc=True).execute()
        
        history_requests_filtered = response.data if response.data else []
        
        # Convert to list for template
        history_requests = []
        for req in history_requests_filtered:
            history_requests.append({
                'request_id': int(req.get('request_id', 0)),
                'username': req.get('username', ''),
                'email': req.get('email', ''),
                'current_access': req.get('current_access', ''),
                'requested_access': req.get('requested_access', ''),
                'request_date': req.get('request_date', ''),
                'status': req.get('request_status', ''),
                'reason': req.get('reason', ''),
                'processed_by': req.get('processed_by', 'Admin'),
                'processed_date': req.get('processed_date', '')
            })
        
        return render_template("admin/requests_history.html", requests=history_requests)
    
    except Exception as e:
        print(f"Error loading requests history: {e}")
        flash("Error loading requests history.", "error")
        return render_template("admin/requests_history.html", requests=[])

@admin_bp.route("/requests/approve/<int:request_id>", methods=["POST"])
@require_admin_role
def approve_request(request_id):
    """Approve an access request using Supabase"""
    try:
        from supabase_db import supabase
        from datetime import datetime
        
        data = request.get_json()
        approved_access = data.get('approved_access')
        
        if not approved_access:
            return jsonify({
                'success': False,
                'message': 'Please select an access level to approve'
            }), 400
        
        # Get request from Supabase
        req_response = supabase.table('requests_raised').select('*').eq('request_id', request_id).eq('request_status', 'pending').execute()
        
        if not req_response.data:
            return jsonify({
                'success': False,
                'message': 'Request not found or already processed'
            }), 404
        
        request_data = req_response.data[0]
        username = request_data['username']
        email = request_data['email']
        
        # Get user from Supabase
        user_response = supabase.table('users').select('*').eq('username', username).eq('email', email).execute()
        
        if not user_response.data:
            return jsonify({
                'success': False,
                'message': 'User not found in database'
            }), 404
        
        user = user_response.data[0]
        user_id = user['id']
        
        # Update user role
        supabase.table('users').update({
            'role': approved_access,
            'updated_at': datetime.now().isoformat()
        }).eq('id', user_id).execute()
        
        # Update request status
        # Get existing reason (user's reason)
        existing_reason = request_data.get('reason', '')

        # Append admin approval reason
        admin_reason = f"\n[ADMIN APPROVAL] Approved: {approved_access}"
        final_reason = existing_reason + admin_reason if existing_reason else admin_reason

        # Update request status
        supabase.table('requests_raised').update({
            'request_status': 'completed',
            'reason': final_reason,
            'processed_by': session.get('username', 'Admin'),
            'processed_date': datetime.now().isoformat()
        }).eq('request_id', request_id).execute()
        
        return jsonify({
            'success': True,
            'message': f'Request approved successfully. User {username} now has {approved_access} access.'
        })
    
    except Exception as e:
        print(f"Error approving request: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'message': 'System error occurred'
        }), 500

@admin_bp.route("/requests/deny/<int:request_id>", methods=["POST"])
@require_admin_role
def deny_request(request_id):
    """Deny an access request using Supabase"""
    try:
        from supabase_db import supabase
        from datetime import datetime
        
        data = request.get_json()
        denial_reason = data.get('reason', '').strip()
        
        if not denial_reason:
            return jsonify({
                'success': False,
                'message': 'Please provide a reason for denial'
            }), 400
        
        # Check if request exists and is pending
        req_response = supabase.table('requests_raised').select('*').eq('request_id', request_id).eq('request_status', 'pending').execute()
        
        if not req_response.data:
            return jsonify({
                'success': False,
                'message': 'Request not found or already processed'
            }), 404
        
        # Update request status
        # Get request data to preserve user reason
        req_response = supabase.table('requests_raised').select('*').eq('request_id', request_id).eq('request_status', 'pending').execute()

        if not req_response.data:
            return jsonify({
                'success': False,
                'message': 'Request not found or already processed'
            }), 404

        request_data = req_response.data[0]
        existing_reason = request_data.get('reason', '')

        # Append admin denial reason
        admin_reason = f"\n[ADMIN DENIAL] {denial_reason}"
        final_reason = existing_reason + admin_reason if existing_reason else admin_reason

        # Update request status
        supabase.table('requests_raised').update({
            'request_status': 'denied',
            'reason': final_reason,
            'processed_by': session.get('username', 'Admin'),
            'processed_date': datetime.now().isoformat()
        }).eq('request_id', request_id).execute()
        
        return jsonify({
            'success': True,
            'message': 'Request denied successfully.'
        })
    
    except Exception as e:
        print(f"Error denying request: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'message': 'System error occurred'
        }), 500

@admin_bp.route("/api/requests/stats")
@require_admin_role
def api_requests_stats():
    """API endpoint for request statistics from Supabase"""
    try:
        from supabase_db import supabase
        
        # Get all requests
        response = supabase.table('requests_raised').select('request_status').execute()
        requests = response.data if response.data else []
        
        # Count by status
        pending = sum(1 for r in requests if r.get('request_status', '').lower() == 'pending')
        completed = sum(1 for r in requests if r.get('request_status', '').lower() == 'completed')
        denied = sum(1 for r in requests if r.get('request_status', '').lower() == 'denied')
        
        return jsonify({
            'pending': pending,
            'completed': completed,
            'denied': denied,
            'total': len(requests)
        })
    
    except Exception as e:
        print(f"Error getting request stats: {e}")
        return jsonify({
            'pending': 0,
            'completed': 0,
            'denied': 0,
            'total': 0
        })




# Add these routes to your admin.py file

@admin_bp.route("/users/manage")
@require_admin_role
def users_manage():
    """View users management page from Supabase"""
    try:
        from supabase_db import supabase
        
        # Get all users from Supabase
        response = supabase.table('users').select('*').order('username').execute()
        users_data = response.data if response.data else []
        
        # Prepare users list
        users_list = []
        for user in users_data:
            users_list.append({
                'id': int(user.get('id', 0)),
                'username': user.get('username', ''),
                'email': user.get('email', ''),
                'full_name': user.get('full_name', ''),
                'role': user.get('role', 'user'),
                'created_at': user.get('created_at', ''),
                'updated_at': user.get('updated_at', '')
            })
        
        return render_template("admin/users_manage.html", users=users_list)
    
    except Exception as e:
        print(f"Error loading users management: {e}")
        flash("Error loading users data.", "error")
        return render_template("admin/users_manage.html", users=[])

@admin_bp.route("/users/update-role", methods=["POST"])
@require_admin_role
def update_user_role():
    """Update user role using Supabase"""
    try:
        from supabase_db import supabase
        from datetime import datetime
        
        data = request.get_json()
        user_id = data.get('user_id')
        new_role = data.get('new_role', '').strip()
        
        if not user_id or not new_role:
            return jsonify({
                'success': False,
                'message': 'User ID and role are required'
            }), 400
        
        # Validate role
        valid_roles = ['user', 'admin', 'user,admin']
        if new_role not in valid_roles:
            return jsonify({
                'success': False,
                'message': 'Invalid role selected'
            }), 400
        
        # Get user from Supabase
        user_response = supabase.table('users').select('*').eq('id', user_id).execute()
        
        if not user_response.data:
            return jsonify({
                'success': False,
                'message': 'User not found'
            }), 404
        
        user = user_response.data[0]
        username = user.get('username')
        current_role = user.get('role', 'user')
        
        # Check if role actually changed
        if current_role == new_role:
            return jsonify({
                'success': True,
                'message': f'User {username} already has {new_role} role',
                'no_change': True
            })
        
        # Update user role
        supabase.table('users').update({
            'role': new_role,
            'updated_at': datetime.now().isoformat()
        }).eq('id', user_id).execute()
        
        return jsonify({
            'success': True,
            'message': f'Successfully updated {username} role from {current_role} to {new_role}',
            'user_id': user_id,
            'new_role': new_role,
            'username': username
        })
    
    except Exception as e:
        print(f"Error updating user role: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'message': 'System error occurred'
        }), 500

@admin_bp.route("/users/bulk-update-roles", methods=["POST"])
@require_admin_role
def bulk_update_user_roles():
    """Bulk update multiple user roles using Supabase"""
    try:
        from supabase_db import supabase
        from datetime import datetime
        
        data = request.get_json()
        updates = data.get('updates', [])
        
        if not updates:
            return jsonify({
                'success': False,
                'message': 'No updates provided'
            }), 400
        
        valid_roles = ['user', 'admin', 'user,admin']
        updated_count = 0
        errors = []
        
        for update in updates:
            user_id = update.get('user_id')
            new_role = update.get('new_role', '').strip()
            
            if not user_id or not new_role:
                errors.append(f'Invalid update data for user {user_id}')
                continue
            
            if new_role not in valid_roles:
                errors.append(f'Invalid role {new_role} for user {user_id}')
                continue
            
            try:
                # Update user
                supabase.table('users').update({
                    'role': new_role,
                    'updated_at': datetime.now().isoformat()
                }).eq('id', user_id).execute()
                
                updated_count += 1
            except Exception as e:
                errors.append(f'User {user_id}: {str(e)}')
        
        if updated_count > 0:
            message = f'Successfully updated {updated_count} user roles'
            if errors:
                message += f' ({len(errors)} errors occurred)'
            
            return jsonify({
                'success': True,
                'message': message,
                'updated_count': updated_count,
                'errors': errors
            })
        else:
            return jsonify({
                'success': False,
                'message': 'No valid updates to apply',
                'errors': errors
            }), 400
    
    except Exception as e:
        print(f"Error in bulk update: {e}")
        return jsonify({
            'success': False,
            'message': 'System error occurred'
        }), 500

@admin_bp.route("/api/users/stats")
@require_admin_role
def api_users_stats():
    """API endpoint for user statistics from Supabase"""
    try:
        from supabase_db import supabase
        
        # Get all users
        response = supabase.table('users').select('role').execute()
        users = response.data if response.data else []
        
        # Count by role
        role_counts = {'user': 0, 'admin': 0, 'both': 0}
        
        for user in users:
            role = str(user.get('role', 'user')).lower().strip()
            if ',' in role or ('user' in role and 'admin' in role):
                role_counts['both'] += 1
            elif 'admin' in role:
                role_counts['admin'] += 1
            else:
                role_counts['user'] += 1
        
        return jsonify({
            'total_users': len(users),
            'user_role': role_counts['user'],
            'admin_role': role_counts['admin'],
            'both_roles': role_counts['both']
        })
    
    except Exception as e:
        print(f"Error getting user stats: {e}")
        return jsonify({
            'total_users': 0,
            'user_role': 0,
            'admin_role': 0,
            'both_roles': 0
        })       
        
        


# Add these CORRECTED routes to admin.py (replace the existing analytics routes)

@admin_bp.route("/users-analytics")
@require_admin_role
def users_analytics():
    """Main users analytics dashboard"""
    return render_template("admin/users_analytics.html")

@admin_bp.route("/api/users-analytics/stats")
@require_admin_role
def api_users_analytics_stats():
    """API endpoint for users analytics overview stats from Supabase"""
    try:
        # Get data from Supabase
        users = get_all_users()
        exams = get_all_exams()
        results = get_all_results()
        
        # Count responses
        responses_count = 0
        for result in results:
            responses = get_responses_by_result(result['id'])
            responses_count += len(responses)
        
        stats = {
            'total_users': len(users),
            'total_exams': len(exams),
            'total_results': len(results),
            'total_responses': responses_count
        }
        
        return jsonify(stats)
    
    except Exception as e:
        print(f"Error getting analytics stats: {e}")
        return jsonify({
            'total_users': 0,
            'total_exams': 0,
            'total_results': 0,
            'total_responses': 0
        })

@admin_bp.route("/users-analytics/results")
@require_admin_role
def users_analytics_results():
    """Results tab content for users analytics from Supabase"""
    try:
        # Get filter parameters
        user_filter = request.args.get('user', '')
        exam_filter = request.args.get('exam', '')
        date_from = request.args.get('dateFrom', '')
        date_to = request.args.get('dateTo', '')
        page = int(request.args.get('page', 1))
        per_page = 20
        
        # Load data from Supabase
        all_results = get_all_results()
        users = get_all_users()
        exams = get_all_exams()
        
        # Create lookup maps
        users_map = {str(u['id']): u for u in users}
        exams_map = {str(e['id']): e for e in exams}
        
        # Filter results
        filtered_results = []
        for result in all_results:
            # Apply filters
            if user_filter and str(result.get('student_id')) != user_filter:
                continue
            if exam_filter and str(result.get('exam_id')) != exam_filter:
                continue
            
            # Date filters
            completed_at = result.get('completed_at', '')
            if date_from and completed_at:
                try:
                    if completed_at < date_from:
                        continue
                except:
                    pass
            if date_to and completed_at:
                try:
                    if completed_at > date_to:
                        continue
                except:
                    pass
            
            filtered_results.append(result)
        
        # Pagination
        total_results = len(filtered_results)
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_results = filtered_results[start_idx:end_idx]
        
        # Convert to list for template
        results_list = []
        for result in paginated_results:
            student_id = str(result.get('student_id', ''))
            exam_id = str(result.get('exam_id', ''))
            
            user = users_map.get(student_id, {})
            exam = exams_map.get(exam_id, {})
            
            results_list.append({
                'id': int(result.get('id', 0)),
                'username': user.get('username', 'Unknown'),
                'full_name': user.get('full_name', 'Unknown'),
                'exam_id': int(result.get('exam_id', 0)),
                'exam_name': exam.get('name', 'Unknown Exam'),
                'subject_name': 'N/A',
                'score': result.get('score', 0),
                'max_score': result.get('max_score', 0),
                'percentage': float(result.get('percentage', 0)),
                'grade': result.get('grade', 'N/A'),
                'duration': f"{result.get('time_taken_minutes', 0):.1f} min" if result.get('time_taken_minutes') else 'N/A',
                'created_at': result.get('completed_at', 'N/A')
            })
        
        # Create pagination object
        pagination = {
            'page': page,
            'per_page': per_page,
            'total': total_results,
            'start': start_idx + 1 if results_list else 0,
            'end': min(end_idx, total_results),
            'has_prev': page > 1,
            'has_next': end_idx < total_results,
            'prev_num': page - 1 if page > 1 else None,
            'next_num': page + 1 if end_idx < total_results else None
        }
        
        def iter_pages():
            total_pages = (total_results + per_page - 1) // per_page
            for p in range(max(1, page - 2), min(total_pages + 1, page + 3)):
                yield p
        pagination['iter_pages'] = iter_pages
        
        # Get users and exams for filters
        users_list = [{'id': int(u['id']), 'username': u.get('username', ''), 'full_name': u.get('full_name', '')} for u in users]
        exams_list = [{'id': int(e['id']), 'name': e.get('name', '')} for e in exams]
        
        return render_template("admin/users_analytics_results.html",
                             results=results_list,
                             users=users_list,
                             exams=exams_list,
                             pagination=pagination)
    
    except Exception as e:
        print(f"Error loading results analytics: {e}")
        import traceback
        traceback.print_exc()
        return render_template("admin/users_analytics_results.html",
                             results=[],
                             users=[],
                             exams=[],
                             pagination=None)









@admin_bp.route("/users-analytics/view-result/<int:result_id>/<int:exam_id>")
@require_admin_role
def users_analytics_view_result(result_id, exam_id):
    """View result popup from Supabase"""
    try:
        # Get result from Supabase
        result = get_result_by_id(result_id)
        if not result:
            abort(404)
        
        # Get user
        student_id = result.get('student_id')
        user = get_user_by_id(student_id) if student_id else None
        if not user:
            user = {'id': student_id, 'username': 'Unknown', 'full_name': 'Unknown', 'email': ''}
        
        # Get exam
        exam = get_exam_by_id(exam_id)
        if not exam:
            exam = {'id': exam_id, 'name': 'Unknown Exam', 'description': ''}
        
        # Get responses
        responses = get_responses_by_result(result_id)
        
        # Normalize result data
        normalized_result = {
            'id': str(result.get('id', result_id)),
            'student_id': str(result.get('student_id', '')),
            'score': float(result.get('score', 0)),
            'max_score': float(result.get('max_score', 0)),
            'total_questions': int(result.get('total_questions', 0)),
            'correct_answers': int(result.get('correct_answers', 0)),
            'incorrect_answers': int(result.get('incorrect_answers', 0)),
            'unanswered_questions': int(result.get('unanswered_questions', 0)),
            'attempted_questions': int(result.get('total_questions', 0)) - int(result.get('unanswered_questions', 0)),
            'percentage': float(result.get('percentage', 0)),
            'grade': result.get('grade', ''),
            'time_taken_minutes': float(result.get('time_taken_minutes', 0)),
            'completed_at': result.get('completed_at', '')
        }
        
        return render_template("admin/view_result_popup.html",
                             result=normalized_result,
                             user=user,
                             exam=exam,
                             responses=responses)
    
    except Exception as e:
        print(f"Error in view-result: {e}")
        import traceback
        traceback.print_exc()
        abort(500)



@admin_bp.route("/users-analytics/view-responses/<int:result_id>/<int:exam_id>")
@require_admin_role
def users_analytics_view_responses(result_id, exam_id):
    """View responses popup from Supabase"""
    try:
        # Get result
        result = get_result_by_id(result_id)
        if not result:
            abort(404)
        
        # Get user
        student_id = result.get('student_id')
        user = get_user_by_id(student_id) if student_id else None
        if not user:
            user = {'id': student_id, 'username': 'Unknown', 'full_name': 'Unknown', 'email': ''}
        
        # Get exam
        exam = get_exam_by_id(exam_id)
        if not exam:
            exam = {'id': exam_id, 'name': 'Unknown Exam', 'description': ''}
        
        # Get responses
        raw_responses = get_responses_by_result(result_id)
        
        # Get all questions for this exam
        questions = get_questions_by_exam(exam_id)
        questions_map = {str(q['id']): q for q in questions}
        
        # Normalize responses
        normalized_responses = []
        for resp in raw_responses:
            question_id = str(resp.get('question_id', ''))
            question = questions_map.get(question_id, {})
            
            given_answer = str(resp.get('given_answer', ''))
            if not given_answer or given_answer in ['None', 'nan', '']:
                given_answer = 'Not Answered'
            
            correct_answer = str(resp.get('correct_answer', ''))
            if not correct_answer or correct_answer in ['None', 'nan', '']:
                correct_answer = 'N/A'
            
            # Parse is_correct and is_attempted
            is_correct = resp.get('is_correct', False)
            if isinstance(is_correct, str):
                is_correct = is_correct.lower() in ['true', '1', 'yes']
            
            is_attempted = resp.get('is_attempted', False)
            if isinstance(is_attempted, str):
                is_attempted = is_attempted.lower() in ['true', '1', 'yes']
            
            # Determine status
            if not is_attempted or given_answer == 'Not Answered':
                status = 'unanswered'
            elif is_correct:
                status = 'correct'
            else:
                status = 'incorrect'
            
            normalized_responses.append({
                'question_id': question_id,
                'question_text': question.get('question_text', 'Question not found'),
                'user_answer': given_answer,
                'correct_answer': correct_answer,
                'status': status,
                'explanation': resp.get('explanation', ''),
                'marks_obtained': resp.get('marks_obtained', 0)
            })
        
        return render_template("admin/view_responses_popup.html",
                             result=result,
                             user=user,
                             exam=exam,
                             responses=normalized_responses)
    
    except Exception as e:
        print(f"Error in view-responses: {e}")
        import traceback
        traceback.print_exc()
        abort(500)



@admin_bp.route("/users-analytics/download-result/<int:result_id>")
@require_admin_role
def users_analytics_download_result(result_id):
    """Generate PDF for result from Supabase"""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from io import BytesIO
        
        # Get result
        result = get_result_by_id(result_id)
        if not result:
            abort(404)
        
        # Get user
        student_id = result.get('student_id')
        user = get_user_by_id(student_id) if student_id else {'username': 'Unknown', 'full_name': 'Unknown'}
        
        # Get exam
        exam_id = result.get('exam_id')
        exam = get_exam_by_id(exam_id) if exam_id else {'name': 'Unknown Exam'}
        
        # Get responses
        user_responses = get_responses_by_result(result_id)
        
        if not user_responses:
            # Simple summary PDF
            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=50, leftMargin=50, topMargin=50, bottomMargin=50)
            
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle('CustomTitle', parent=styles['Title'], fontSize=18, textColor=colors.HexColor('#2c3e50'), spaceAfter=20, alignment=TA_CENTER)
            
            story = []
            story.append(Paragraph("Exam Response Analysis", title_style))
            story.append(Paragraph(f"<b>Exam:</b> {exam.get('name', 'Unknown')}", styles['Normal']))
            story.append(Paragraph(f"<b>Student:</b> {user.get('full_name', user.get('username', 'Unknown'))}", styles['Normal']))
            story.append(Paragraph(f"<b>Score:</b> {result.get('score', 0)}/{result.get('max_score', 0)}", styles['Normal']))
            story.append(Spacer(1, 20))
            story.append(Paragraph("No detailed responses available.", styles['Normal']))
            
            doc.build(story)
            pdf_bytes = buffer.getvalue()
            buffer.close()
            
            return send_file(BytesIO(pdf_bytes), as_attachment=True, download_name=f"result_{result_id}.pdf", mimetype='application/pdf')
        
        # Get questions
        questions = get_questions_by_exam(exam_id)
        questions_map = {str(q['id']): q for q in questions}
        
        # Create detailed PDF
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=50, leftMargin=50, topMargin=50, bottomMargin=50)
        
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle('CustomTitle', parent=styles['Title'], fontSize=18, textColor=colors.HexColor('#2c3e50'), spaceAfter=20, alignment=TA_CENTER)
        heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'], fontSize=14, textColor=colors.HexColor('#2c3e50'), spaceAfter=10)
        
        story = []
        story.append(Paragraph("Exam Response Analysis", title_style))
        
        # Header table
        header_data = [
            ['Exam:', str(exam.get('name', 'Unknown'))],
            ['Student:', f"{user.get('full_name', user.get('username', 'Unknown'))} ({user.get('username', 'Unknown')})"],
            ['Score:', f"{result.get('score', 0)}/{result.get('max_score', 0)} ({result.get('percentage', 0):.1f}%)"],
            ['Grade:', str(result.get('grade', 'N/A'))],
            ['Completed:', str(result.get('completed_at', 'N/A'))]
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
        question_num = 1
        for response in user_responses:
            question_id = str(response.get('question_id', ''))
            question = questions_map.get(question_id, {})
            
            if not question:
                continue
            
            story.append(Paragraph(f"Question {question_num}", heading_style))
            
            question_text = str(question.get('question_text', 'Question text not available'))
            story.append(Paragraph(f"<b>Question:</b> {question_text}", styles['Normal']))
            story.append(Spacer(1, 10))
            
            # Options for MCQ/MSQ
            question_type = str(response.get('question_type', question.get('question_type', 'MCQ')))
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
            
            # Answers
            given_answer = str(response.get('given_answer', ''))
            if given_answer in ['nan', 'None', '', None]:
                given_answer = 'Not Answered'
            
            correct_answer = str(response.get('correct_answer', ''))
            if correct_answer in ['nan', 'None', '', None]:
                correct_answer = 'N/A'
            
            is_correct = response.get('is_correct', False)
            if isinstance(is_correct, str):
                is_correct = is_correct.lower() in ['true', '1', 'yes']
            
            is_attempted = response.get('is_attempted', False)
            if isinstance(is_attempted, str):
                is_attempted = is_attempted.lower() in ['true', '1', 'yes']
            
            marks = float(response.get('marks_obtained', 0) or 0)
            
            if not is_attempted or given_answer == 'Not Answered':
                status = 'Not Attempted'
            elif is_correct:
                status = 'Correct'
            else:
                status = 'Incorrect'
            
            answer_data = [
                ['Your Answer:', given_answer],
                ['Correct Answer:', correct_answer],
                ['Question Type:', question_type],
                ['Marks Obtained:', str(marks)],
                ['Status:', status]
            ]
            
            status_color = colors.lightgreen if status == 'Correct' else colors.lightcoral if status == 'Incorrect' else colors.lightblue
            
            answer_table = Table(answer_data, colWidths=[1.5*inch, 4*inch])
            answer_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightblue),
                ('BACKGROUND', (0, 4), (1, 4), status_color),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('PADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(answer_table)
            story.append(Spacer(1, 20))
            question_num += 1
        
        # Summary
        story.append(Paragraph("Performance Summary", heading_style))
        
        summary_data = [
            ['Total Questions:', str(result.get('total_questions', 0))],
            ['Correct Answers:', str(result.get('correct_answers', 0))],
            ['Incorrect Answers:', str(result.get('incorrect_answers', 0))],
            ['Unanswered:', str(result.get('unanswered_questions', 0))],
            ['Final Score:', f"{result.get('score', 0)}/{result.get('max_score', 0)}"],
            ['Percentage:', f"{result.get('percentage', 0):.1f}%"],
            ['Time Taken:', f"{result.get('time_taken_minutes', 0):.1f} minutes"]
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
        story.append(Spacer(1, 30))
        story.append(Paragraph(f"Generated by Admin Portal on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        
        doc.build(story)
        
        pdf_bytes = buffer.getvalue()
        buffer.close()
        
        student_name = user.get('username', 'student')
        exam_name = str(exam.get('name', 'exam')).replace(' ', '_')
        filename = f"{exam_name}_{student_name}_result_{result_id}.pdf"
        
        return send_file(BytesIO(pdf_bytes), as_attachment=True, download_name=filename, mimetype='application/pdf')
    
    except Exception as e:
        print(f"Error generating PDF: {e}")
        import traceback
        traceback.print_exc()
        abort(500)






def _parse_datetime_series(df, candidates):
    for c in candidates:
        if c in df.columns:
            try:
                return pd.to_datetime(df[c], errors='coerce')
            except Exception:
                return pd.to_datetime(df[c].astype(str), errors='coerce')
    return pd.Series([pd.NaT] * len(df), index=df.index)

@admin_bp.route("/users-analytics/analytics")
@require_admin_role
def users_analytics_analytics():
    """Render analytics page with exams from Supabase"""
    try:
        exams = get_all_exams()
        exams_list = [{'id': int(e['id']), 'name': e.get('name', f"Exam {e['id']}")} for e in exams]
        return render_template("admin/users_analytics_analytics.html", exams=exams_list)
    except Exception as e:
        print(f"Error rendering analytics: {e}")
        return render_template("admin/users_analytics_analytics.html", exams=[])


@admin_bp.route("/api/users-analytics/data")
@require_admin_role
def users_analytics_data_api():
    """JSON API for analytics from Supabase"""
    try:
        from datetime import datetime as dt, timedelta
        
        # Get query params
        time_period = (request.args.get('timePeriod') or 'all').lower()
        exam_filter = (request.args.get('exam') or '').strip()
        start_date = request.args.get('startDate') or ''
        end_date = request.args.get('endDate') or ''
        
        # Get data from Supabase
        all_results = get_all_results()
        users = get_all_users()
        exams = get_all_exams()
        
        if not all_results:
            return jsonify({
                "summary": {"avgScore": 0.0, "totalAttempts": 0, "passRate": 0.0, "activeUsers": 0,
                           "scoreChange": 0.0, "attemptsChange": 0.0, "passRateChange": 0.0, "usersChange": 0.0},
                "charts": {"scoreDistribution": [0,0,0,0], "performanceTrends": {"labels":[], "data":[]},
                          "examPerformance": {"labels":[], "data":[]}, "userActivity": {"labels":[], "data":[]}},
                "tables": {"topPerformers": [], "examStats": [], "recentActivity": []}
            })
        
        # Build maps
        exam_map = {str(e['id']): e.get('name', f"Exam {e['id']}") for e in exams}
        user_map = {str(u['id']): u for u in users}
        
        # Filter by time
        now = dt.now()
        filtered = []
        
        for r in all_results:
            completed_at = r.get('completed_at', '')
            
            # Time filter
            if time_period != 'all' and completed_at:
                try:
                    completed_dt = dt.fromisoformat(completed_at.replace('Z', '+00:00'))
                    
                    if time_period == 'today':
                        if completed_dt.date() != now.date():
                            continue
                    elif time_period == 'week':
                        week_start = now - timedelta(days=now.weekday())
                        if completed_dt < week_start:
                            continue
                    elif time_period == 'month':
                        if completed_dt.month != now.month or completed_dt.year != now.year:
                            continue
                    elif time_period == 'custom' and start_date and end_date:
                        if completed_at < start_date or completed_at > end_date:
                            continue
                except:
                    pass
            
            # Exam filter
            if exam_filter and str(r.get('exam_id')) != exam_filter:
                continue
            
            filtered.append(r)
        
        # Calculate stats
        total_attempts = len(filtered)
        avg_score = sum(float(r.get('percentage', 0)) for r in filtered) / total_attempts if total_attempts > 0 else 0.0
        pass_rate = sum(1 for r in filtered if float(r.get('percentage', 0)) >= 40) / total_attempts * 100 if total_attempts > 0 else 0.0
        active_users = len(set(str(r.get('student_id')) for r in filtered))
        
        summary = {
            "avgScore": round(avg_score, 2),
            "totalAttempts": total_attempts,
            "passRate": round(pass_rate, 2),
            "activeUsers": active_users,
            "scoreChange": 0.0,
            "attemptsChange": 0.0,
            "passRateChange": 0.0,
            "usersChange": 0.0
        }
        
        # Score distribution
        excellent = sum(1 for r in filtered if float(r.get('percentage', 0)) >= 90)
        good = sum(1 for r in filtered if 75 <= float(r.get('percentage', 0)) < 90)
        average = sum(1 for r in filtered if 60 <= float(r.get('percentage', 0)) < 75)
        poor = sum(1 for r in filtered if float(r.get('percentage', 0)) < 60)
        
        # Exam performance
        exam_perf = {}
        for r in filtered:
            exam_id = str(r.get('exam_id', ''))
            exam_name = exam_map.get(exam_id, f"Exam {exam_id}")
            if exam_name not in exam_perf:
                exam_perf[exam_name] = []
            exam_perf[exam_name].append(float(r.get('percentage', 0)))
        
        exam_labels = list(exam_perf.keys())
        exam_data = [round(sum(scores)/len(scores), 2) if scores else 0 for scores in exam_perf.values()]
        
        # Top performers
        student_scores = {}
        for r in filtered:
            sid = str(r.get('student_id', ''))
            if sid not in student_scores:
                student_scores[sid] = []
            student_scores[sid].append(float(r.get('percentage', 0)))
        
        top_performers = []
        for sid, scores in sorted(student_scores.items(), key=lambda x: sum(x[1])/len(x[1]) if x[1] else 0, reverse=True)[:10]:
            user = user_map.get(sid, {})
            top_performers.append({
                "student_id": sid,
                "username": user.get('username', sid),
                "full_name": user.get('full_name', ''),
                "avgScore": round(sum(scores)/len(scores), 2) if scores else 0,
                "attempts": len(scores)
            })
        
        # Exam stats
        exam_stats = []
        for exam_name, scores in exam_perf.items():
            pass_count = sum(1 for s in scores if s >= 40)
            exam_stats.append({
                "name": exam_name,
                "attempts": len(scores),
                "avgScore": round(sum(scores)/len(scores), 2) if scores else 0,
                "passRate": round(pass_count/len(scores)*100, 2) if scores else 0
            })
        
        # Recent activity
        recent_activity = []
        for r in sorted(filtered, key=lambda x: x.get('completed_at', ''), reverse=True)[:10]:
            user = user_map.get(str(r.get('student_id', '')), {})
            exam_name = exam_map.get(str(r.get('exam_id', '')), 'Unknown')
            recent_activity.append({
                "created_at": r.get('completed_at', ''),
                "username": user.get('username', 'Unknown'),
                "full_name": user.get('full_name', ''),
                "exam_name": exam_name,
                "score": r.get('score'),
                "max_score": r.get('max_score'),
                "percentage": round(float(r.get('percentage', 0)), 2)
            })
        
        return jsonify({
            "summary": summary,
            "charts": {
                "scoreDistribution": [excellent, good, average, poor],
                "performanceTrends": {"labels": [], "data": []},
                "examPerformance": {"labels": exam_labels, "data": exam_data},
                "userActivity": {"labels": [], "data": []}
            },
            "tables": {
                "topPerformers": top_performers,
                "examStats": exam_stats,
                "recentActivity": recent_activity
            }
        })
    
    except Exception as e:
        print(f"Analytics error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Failed to compute analytics", "message": str(e)}), 500       





@admin_bp.route("/attempts/bulk-modify", methods=["POST"])
@require_admin_role  
def attempts_bulk_modify():
    """Bulk modify attempts using Supabase"""
    
    from supabase_db import supabase
    from datetime import datetime
    
    try:
        data = request.get_json()
        items = data.get('items', [])
        action = data.get('action', '')
        amount = data.get('amount', 1)
        
        if not items or not action:
            return jsonify({'success': False, 'message': 'Missing required data'})
        
        processed_count = 0
        errors = []
        
        for item in items:
            student_id = str(item.get('student_id'))
            exam_id = str(item.get('exam_id'))
            
            try:
                # Get current attempts
                response = supabase.table('exam_attempts').select('*').eq('student_id', student_id).eq('exam_id', exam_id).execute()
                current_attempts = response.data if response.data else []
                used = len(current_attempts)
                
                if action == "reset":
                    for attempt in current_attempts:
                        supabase.table('exam_attempts').delete().eq('id', attempt['id']).execute()
                    processed_count += 1
                
                elif action == "decrease":
                    if used >= amount:
                        sorted_attempts = sorted(current_attempts, key=lambda x: x.get('id', 0))
                        to_delete = sorted_attempts[-amount:]
                        for attempt in to_delete:
                            supabase.table('exam_attempts').delete().eq('id', attempt['id']).execute()
                        processed_count += 1
                    else:
                        errors.append(f"Student {student_id}, Exam {exam_id}: Not enough attempts to remove")
                
                elif action == "increase":
                    for i in range(amount):
                        new_attempt = {
                            "student_id": int(student_id),
                            "exam_id": int(exam_id),
                            "attempt_number": used + i + 1,
                            "status": "manual_add",
                            "start_time": datetime.now().isoformat(),
                            "end_time": None
                        }
                        supabase.table('exam_attempts').insert(new_attempt).execute()
                    processed_count += 1
            
            except Exception as e:
                errors.append(f"Student {student_id}, Exam {exam_id}: {str(e)}")
        
        if processed_count > 0:
            return jsonify({
                'success': True, 
                'processed': processed_count,
                'errors': errors if errors else None
            })
        else:
            return jsonify({
                'success': False, 
                'message': f'Failed to save changes. Errors: {"; ".join(errors)}'
            })
    
    except Exception as e:
        print(f"Bulk modify error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500    



        
@admin_bp.route("/questions/export-csv/<int:exam_id>")
@require_admin_role
def export_questions_csv(exam_id):
    """Export questions for selected exam as CSV"""
    try:
        import io
        from flask import Response
        
        # Get exam
        exam = get_exam_by_id(exam_id)
        if not exam:
            flash("Exam not found.", "error")
            return redirect(url_for("admin.questions_index"))
        
        # Get questions for this exam
        questions = get_questions_by_exam(exam_id)
        
        if not questions:
            flash("No questions found for this exam.", "warning")
            return redirect(url_for("admin.questions_index", exam_id=exam_id))
        
        # Create CSV data (WITHOUT question_id - database manages it)
        csv_data = []
        for q in questions:
            row = {
                'exam_id': int(q.get('exam_id', 0)),
                'question_text': str(q.get('question_text', '')).strip(),
                'option_a': str(q.get('option_a', '')).strip(),
                'option_b': str(q.get('option_b', '')).strip(),
                'option_c': str(q.get('option_c', '')).strip(),
                'option_d': str(q.get('option_d', '')).strip(),
                'correct_answer': str(q.get('correct_answer', '')).strip(),
                'question_type': str(q.get('question_type', 'MCQ')).strip(),
                'image_path': str(q.get('image_path', '')).strip(),
                'positive_marks': int(q.get('positive_marks', 4)),
                'negative_marks': float(q.get('negative_marks', 1)),
                'tolerance': float(q.get('tolerance', 0) or 0)
            }
            csv_data.append(row)
        
        # Convert to DataFrame
        df = pd.DataFrame(csv_data)
        
        # Ensure column order matches import format
        columns_order = [
            'exam_id', 'question_text', 'option_a', 'option_b', 'option_c', 'option_d',
            'correct_answer', 'question_type', 'image_path', 'positive_marks', 
            'negative_marks', 'tolerance'
        ]
        df = df[columns_order]
        
        # Create CSV string
        output = io.StringIO()
        df.to_csv(output, index=False, encoding='utf-8')
        csv_string = output.getvalue()
        output.close()
        
        # Create response
        exam_name = str(exam.get('name', 'exam')).replace(' ', '_').lower()
        filename = f"questions_{exam_name}_{exam_id}.csv"
        
        return Response(
            csv_string,
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename={filename}'}
        )
    
    except Exception as e:
        print(f"Error exporting questions CSV: {e}")
        import traceback
        traceback.print_exc()
        flash("Failed to export questions.", "error")
        return redirect(url_for("admin.questions_index"))


@admin_bp.route("/questions/import-csv", methods=["POST"])
@require_admin_role
def import_questions_csv():
    """Import questions from CSV file"""
    try:
        # Check if file was uploaded
        if 'csv_file' not in request.files:
            return jsonify({"success": False, "message": "No file uploaded"}), 400
        
        file = request.files['csv_file']
        
        if file.filename == '':
            return jsonify({"success": False, "message": "No file selected"}), 400
        
        if not file.filename.endswith('.csv'):
            return jsonify({"success": False, "message": "File must be a CSV"}), 400
        
        # Read CSV
        try:
            df = pd.read_csv(file)
        except Exception as e:
            return jsonify({"success": False, "message": f"Failed to read CSV: {str(e)}"}), 400
        
        # Validate required columns
        required_columns = [
            'exam_id', 'question_text', 'option_a', 'option_b', 'option_c', 'option_d',
            'correct_answer', 'question_type', 'image_path', 'positive_marks',
            'negative_marks', 'tolerance'
        ]
        
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            return jsonify({
                "success": False, 
                "message": f"Missing required columns: {', '.join(missing_columns)}"
            }), 400
        
        # Validate data
        if df.empty:
            return jsonify({"success": False, "message": "CSV file is empty"}), 400
        
        # Get all valid exam IDs
        all_exams = get_all_exams()
        valid_exam_ids = {int(exam['id']) for exam in all_exams}
        
        # Check for invalid exam IDs
        csv_exam_ids = set(df['exam_id'].dropna().astype(int).unique())
        invalid_exam_ids = csv_exam_ids - valid_exam_ids
        
        if invalid_exam_ids:
            return jsonify({
                "success": False,
                "message": f"Invalid exam IDs found in CSV: {', '.join(map(str, invalid_exam_ids))}. Please ensure exams exist before importing."
            }), 400
        
        # Process and insert questions
        from supabase_db import supabase
        
        inserted_count = 0
        skipped_count = 0
        errors = []
        
        for idx, row in df.iterrows():
            try:
                # Validate exam_id
                exam_id = int(row['exam_id']) if pd.notna(row['exam_id']) else None
                if not exam_id or exam_id not in valid_exam_ids:
                    skipped_count += 1
                    errors.append(f"Row {idx + 2}: Invalid exam_id {exam_id}")
                    continue
                
                # Validate question_text
                question_text = str(row['question_text']).strip() if pd.notna(row['question_text']) else ''
                if not question_text:
                    skipped_count += 1
                    errors.append(f"Row {idx + 2}: Empty question_text")
                    continue
                
                # Build question data
                question_data = {
                    'exam_id': exam_id,
                    'question_text': question_text,
                    'option_a': str(row['option_a']).strip() if pd.notna(row['option_a']) else '',
                    'option_b': str(row['option_b']).strip() if pd.notna(row['option_b']) else '',
                    'option_c': str(row['option_c']).strip() if pd.notna(row['option_c']) else '',
                    'option_d': str(row['option_d']).strip() if pd.notna(row['option_d']) else '',
                    'correct_answer': str(row['correct_answer']).strip() if pd.notna(row['correct_answer']) else '',
                    'question_type': str(row['question_type']).strip() if pd.notna(row['question_type']) else 'MCQ',
                    'image_path': str(row['image_path']).strip() if pd.notna(row['image_path']) else '',
                    'positive_marks': int(row['positive_marks']) if pd.notna(row['positive_marks']) else 4,
                    'negative_marks': float(row['negative_marks']) if pd.notna(row['negative_marks']) else 1,
                    'tolerance': float(row['tolerance']) if pd.notna(row['tolerance']) else 0
                }
                
                # Insert into Supabase
                supabase.table('questions').insert(question_data).execute()
                inserted_count += 1
            
            except Exception as e:
                skipped_count += 1
                errors.append(f"Row {idx + 2}: {str(e)}")
                continue
        
        # Build response message
        if inserted_count > 0:
            message = f"Successfully imported {inserted_count} question(s)"
            if skipped_count > 0:
                message += f". Skipped {skipped_count} row(s) due to errors."
            
            return jsonify({
                "success": True,
                "message": message,
                "inserted": inserted_count,
                "skipped": skipped_count,
                "errors": errors[:10] if errors else None  # Return first 10 errors
            }), 200
        else:
            return jsonify({
                "success": False,
                "message": f"No questions imported. {skipped_count} row(s) had errors.",
                "errors": errors[:10] if errors else None
            }), 400
    
    except Exception as e:
        print(f"Error importing CSV: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "message": f"Import failed: {str(e)}"}), 500    

# ========================
# AI COMMAND CENTRE ROUTES
# ========================

@admin_bp.route("/ai-command-centre", methods=["GET"])
@require_admin_role
def ai_command_centre():
    """Main AI Command Centre dashboard"""
    try:
        # Get all exams for dropdown
        exams = get_all_exams()
        return render_template('admin/ai_command_centre.html', exams=exams)
    except Exception as e:
        print(f"Error loading AI Command Centre: {e}")
        flash('Error loading AI Command Centre', 'error')
        return redirect(url_for('admin.dashboard'))


@admin_bp.route("/ai-command-centre/generate", methods=["POST"])
@require_admin_role
def ai_generate_questions():
    """Generate questions using AI"""
    try:
        # Get form data
        mode = request.form.get('mode')  # 'extract', 'mine', or 'pure'
        exam_id = int(request.form.get('exam_id'))
        difficulty = request.form.get('difficulty', 'Medium')
        
        # Question counts and marks
        config = {
            'exam_id': exam_id,
            'difficulty': difficulty,
            'mcq_count': int(request.form.get('mcq_count', 0)),
            'msq_count': int(request.form.get('msq_count', 0)),
            'numeric_count': int(request.form.get('numeric_count', 0)),
            'mcq_plus': float(request.form.get('mcq_plus', 4)),
            'mcq_minus': float(request.form.get('mcq_minus', 1)),
            'msq_plus': float(request.form.get('msq_plus', 4)),
            'msq_minus': float(request.form.get('msq_minus', 2)),
            'numeric_plus': float(request.form.get('numeric_plus', 3)),
            'numeric_tolerance': float(request.form.get('numeric_tolerance', 0.01)),
            'custom_instructions': request.form.get('custom_instructions', '')
        }
        
        # Import AI generator
        from ai_question_generator import generate_questions
        
        # Handle file upload for Card A & B
        pdf_path = None
        if mode in ['extract', 'mine']:
            if 'pdf_file' not in request.files:
                return jsonify({'success': False, 'message': 'PDF file required'}), 400
            
            file = request.files['pdf_file']
            if file.filename == '':
                return jsonify({'success': False, 'message': 'No file selected'}), 400
            
            # Save temporarily
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp:
                file.save(tmp.name)
                pdf_path = tmp.name
        
        # Get topic for Card C
        topic = None
        if mode == 'pure':
            topic = request.form.get('topic', '')
            if not topic:
                return jsonify({'success': False, 'message': 'Topic required'}), 400
        
        try:
            # Generate questions
            questions = generate_questions(
                mode=mode,
                config=config,
                pdf_path=pdf_path,
                topic=topic
            )
            
            return jsonify({
                'success': True,
                'questions': questions,
                'count': len(questions)
            })
        
        finally:
            # Cleanup temp file
            if pdf_path and os.path.exists(pdf_path):
                try:
                    os.unlink(pdf_path)
                except:
                    pass
    
    except Exception as e:
        print(f"AI Generation Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'message': f'Generation failed: {str(e)}'
        }), 500


@admin_bp.route("/ai-command-centre/save", methods=["POST"])
@require_admin_role
def ai_save_questions():
    """Bulk save generated questions to database"""
    try:
        data = request.get_json()
        questions = data.get('questions', [])
        
        if not questions:
            return jsonify({'success': False, 'message': 'No questions to save'}), 400
        
        # Prepare for bulk insert
        questions_to_insert = []
        for q in questions:
            questions_to_insert.append({
                'exam_id': q['exam_id'],
                'question_text': q['question_text'],
                'option_a': q.get('option_a', ''),
                'option_b': q.get('option_b', ''),
                'option_c': q.get('option_c', ''),
                'option_d': q.get('option_d', ''),
                'correct_answer': q['correct_answer'],
                'question_type': q.get('question_type', 'MCQ'),
                'image_path': None,
                'positive_marks': int(q.get('positive_marks', 4)),
                'negative_marks': float(q.get('negative_marks', 1)),
                'tolerance': float(q.get('tolerance', 0))
            })
        
        # Bulk insert to Supabase
        from supabase_db import supabase
        response = supabase.table('questions').insert(questions_to_insert).execute()
        
        if response.data:
            return jsonify({
                'success': True,
                'message': f'Successfully saved {len(questions_to_insert)} questions',
                'count': len(questions_to_insert)
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to save questions to database'
            }), 500
    
    except Exception as e:
        print(f"Save Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'message': f'Save failed: {str(e)}'
        }), 500


@admin_bp.route("/ai-command-centre/export-csv", methods=["POST"])
@require_admin_role
def ai_export_csv():
    """Export generated questions to CSV"""
    try:
        data = request.get_json()
        questions = data.get('questions', [])
        
        if not questions:
            return jsonify({'success': False, 'message': 'No questions to export'}), 400
        
        # Create CSV content
        import io
        import csv
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'exam_id', 'question_text', 'option_a', 'option_b', 'option_c', 'option_d',
            'correct_answer', 'question_type', 'image_path', 'positive_marks',
            'negative_marks', 'tolerance'
        ])
        
        # Write questions
        for q in questions:
            writer.writerow([
                q['exam_id'],
                q['question_text'],
                q.get('option_a', ''),
                q.get('option_b', ''),
                q.get('option_c', ''),
                q.get('option_d', ''),
                q['correct_answer'],
                q.get('question_type', 'MCQ'),
                '',  # image_path
                q.get('positive_marks', 4),
                q.get('negative_marks', 1),
                q.get('tolerance', 0)
            ])
        
        # Create response
        csv_content = output.getvalue()
        output.close()
        
        from flask import Response
        return Response(
            csv_content,
            mimetype='text/csv',
            headers={
                'Content-Disposition': 'attachment; filename=ai_generated_questions.csv'
            }
        )
    
    except Exception as e:
        print(f"Export Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'message': f'Export failed: {str(e)}'
        }), 500