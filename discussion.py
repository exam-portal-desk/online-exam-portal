from flask import Blueprint, request, jsonify, session
from supabase_db import supabase
import threading, time, html, re
from datetime import datetime

discussion_bp = Blueprint('discussion', __name__)

_rate_cache = {}
_rate_lock = threading.Lock()
RATE_LIMIT_SECONDS = 10
MAX_MSG_LEN = 500

_count_cache = {}
_count_lock = threading.Lock()

def _sync_count(question_id, delta):
    with _count_lock:
        _count_cache[question_id] = max(0, _count_cache.get(question_id, 0) + delta)
    try:
        existing = supabase.table('discussion_counts').select('count').eq('question_id', question_id).execute()
        if existing.data:
            new_val = max(0, existing.data[0]['count'] + delta)
            supabase.table('discussion_counts').update({'count': new_val}).eq('question_id', question_id).execute()
        else:
            supabase.table('discussion_counts').insert({'question_id': question_id, 'count': max(0, delta)}).execute()
    except Exception as e:
        print(f"[Disc] count sync error: {e}")

def _get_count(question_id):
    with _count_lock:
        if question_id in _count_cache:
            return _count_cache[question_id]
    try:
        res = supabase.table('discussion_counts').select('count').eq('question_id', question_id).execute()
        count = res.data[0]['count'] if res.data else 0
        with _count_lock:
            _count_cache[question_id] = count
        return count
    except:
        return 0

def _sanitize(text):
    text = html.escape(text.strip())
    return re.sub(r'\s+', ' ', text)

def _rate_ok(user_id):
    now = time.time()
    with _rate_lock:
        if now - _rate_cache.get(user_id, 0) < RATE_LIMIT_SECONDS:
            return False
        _rate_cache[user_id] = now
        return True

def _build_thread(rows):
    by_id = {r['id']: {**r, 'replies': []} for r in rows}
    roots = []
    for r in rows:
        if r['parent_id'] and r['parent_id'] in by_id:
            by_id[r['parent_id']]['replies'].append(by_id[r['id']])
        elif not r['parent_id']:
            roots.append(by_id[r['id']])
    return roots

def _is_admin():
    return 'admin' in str(session.get('role', ''))

@discussion_bp.route('/api/discussion/<int:question_id>', methods=['GET'])
def get_discussion(question_id):
    if 'user_id' not in session:
        return jsonify({'success': False}), 401
    try:
        res = supabase.table('question_discussions')\
            .select('id,question_id,exam_id,user_id,username,message,parent_id,is_pinned,is_best_answer,is_edited,created_at,updated_at')\
            .eq('question_id', question_id).eq('is_deleted', False)\
            .order('created_at', desc=False).execute()
        rows = res.data or []
        current_uid = session['user_id']
        for r in rows:
            r['is_own'] = (r['user_id'] == current_uid)
            r.pop('user_id', None)
        return jsonify({'success': True, 'comments': _build_thread(rows), 'count': _get_count(question_id)})
    except Exception as e:
        print(f"[Disc] GET error: {e}")
        return jsonify({'success': False}), 500

@discussion_bp.route('/api/discussion/<int:question_id>', methods=['POST'])
def post_comment(question_id):
    if 'user_id' not in session:
        return jsonify({'success': False}), 401
    uid = session['user_id']
    if not _rate_ok(uid):
        return jsonify({'success': False, 'message': f'Wait {RATE_LIMIT_SECONDS}s before posting again.'}), 429
    data = request.get_json() or {}
    msg = data.get('message', '').strip()
    if not msg:
        return jsonify({'success': False, 'message': 'Message is empty'}), 400
    if len(msg) > MAX_MSG_LEN:
        return jsonify({'success': False, 'message': f'Max {MAX_MSG_LEN} characters allowed'}), 400
    msg = _sanitize(msg)
    username = session.get('full_name') or session.get('username', 'User')
    record = {
        'question_id': question_id,
        'exam_id': data.get('exam_id'),
        'user_id': uid,
        'username': username,
        'message': msg,
        'parent_id': data.get('parent_id'),
        'is_pinned': False,
        'is_best_answer': False,
        'is_deleted': False,
        'is_edited': False,
        'created_at': datetime.utcnow().isoformat(),
        'updated_at': datetime.utcnow().isoformat()
    }
    try:
        supabase.table('question_discussions').insert(record).execute()
        _sync_count(question_id, +1)
        return jsonify({'success': True})
    except Exception as e:
        print(f"[Disc] insert error: {e}")
        return jsonify({'success': False, 'message': 'Failed to save'}), 500

@discussion_bp.route('/api/discussion/edit/<int:comment_id>', methods=['PUT'])
def edit_comment(comment_id):
    if 'user_id' not in session:
        return jsonify({'success': False}), 401
    uid = session['user_id']
    data = request.get_json() or {}
    msg = data.get('message', '').strip()
    if not msg or len(msg) > MAX_MSG_LEN:
        return jsonify({'success': False, 'message': 'Invalid message'}), 400
    msg = _sanitize(msg)
    try:
        row = supabase.table('question_discussions').select('user_id').eq('id', comment_id).execute()
        if not row.data or (row.data[0]['user_id'] != uid and not _is_admin()):
            return jsonify({'success': False, 'message': 'Forbidden'}), 403
        supabase.table('question_discussions').update({
            'message': msg, 'is_edited': True, 'updated_at': datetime.utcnow().isoformat()
        }).eq('id', comment_id).execute()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False}), 500

@discussion_bp.route('/api/discussion/delete/<int:comment_id>', methods=['DELETE'])
def delete_comment(comment_id):
    if 'user_id' not in session:
        return jsonify({'success': False}), 401
    uid = session['user_id']
    try:
        row = supabase.table('question_discussions').select('user_id,question_id').eq('id', comment_id).execute()
        if not row.data:
            return jsonify({'success': False}), 404
        if row.data[0]['user_id'] != uid and not _is_admin():
            return jsonify({'success': False, 'message': 'Forbidden'}), 403
        supabase.table('question_discussions').update({'is_deleted': True}).eq('id', comment_id).execute()
        _sync_count(row.data[0]['question_id'], -1)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False}), 500

@discussion_bp.route('/api/discussion/admin/pin/<int:comment_id>', methods=['PUT'])
def admin_pin(comment_id):
    if not _is_admin():
        return jsonify({'success': False}), 403
    try:
        row = supabase.table('question_discussions').select('is_pinned').eq('id', comment_id).execute()
        if not row.data:
            return jsonify({'success': False}), 404
        new_val = not row.data[0]['is_pinned']
        supabase.table('question_discussions').update({'is_pinned': new_val}).eq('id', comment_id).execute()
        return jsonify({'success': True, 'is_pinned': new_val})
    except:
        return jsonify({'success': False}), 500

@discussion_bp.route('/api/discussion/admin/best/<int:comment_id>', methods=['PUT'])
def admin_best(comment_id):
    if not _is_admin():
        return jsonify({'success': False}), 403
    try:
        row = supabase.table('question_discussions').select('is_best_answer,question_id').eq('id', comment_id).execute()
        if not row.data:
            return jsonify({'success': False}), 404
        qid = row.data[0]['question_id']
        new_val = not row.data[0]['is_best_answer']
        if new_val:
            supabase.table('question_discussions').update({'is_best_answer': False}).eq('question_id', qid).execute()
        supabase.table('question_discussions').update({'is_best_answer': new_val}).eq('id', comment_id).execute()
        return jsonify({'success': True, 'is_best_answer': new_val})
    except:
        return jsonify({'success': False}), 500
    
    
@discussion_bp.route('/api/discussion/counts/bulk', methods=['POST'])
def bulk_counts():
    if 'user_id' not in session:
        return jsonify({'success': False}), 401
    data = request.get_json() or {}
    qids = data.get('question_ids', [])
    if not qids or len(qids) > 100:
        return jsonify({'success': False}), 400
    try:
        res = supabase.table('discussion_counts')\
            .select('question_id,count')\
            .in_('question_id', qids)\
            .execute()
        counts = {row['question_id']: row['count'] for row in (res.data or [])}
        result = {str(qid): counts.get(qid, 0) for qid in qids}
        return jsonify({'success': True, 'counts': result})
    except Exception as e:
        print(f"[Disc] bulk counts error: {e}")
        return jsonify({'success': False}), 500    