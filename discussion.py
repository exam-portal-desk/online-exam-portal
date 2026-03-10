from flask import Blueprint, request, jsonify, session
from flask_socketio import SocketIO, join_room, leave_room, emit
from supabase_db import supabase
import threading, time, html, re, uuid
from datetime import datetime
from collections import defaultdict, deque

discussion_bp = Blueprint('discussion', __name__)

socketio = None

def init_socketio(sio):
    global socketio
    socketio = sio

RATE_LIMIT_SECONDS = 10
MAX_MSG_LEN = 500

_rate_cache = {}
_rate_lock = threading.Lock()

_count_cache = {}
_count_lock = threading.Lock()

_msg_buffer = deque()
_buffer_lock = threading.Lock()
BUFFER_FLUSH_INTERVAL = 3
BUFFER_MAX_SIZE = 50

def _flush_buffer():
    while True:
        time.sleep(BUFFER_FLUSH_INTERVAL)
        with _buffer_lock:
            if not _msg_buffer:
                continue
            batch = list(_msg_buffer)
            _msg_buffer.clear()
        try:
            supabase.table('question_discussions').insert(batch).execute()
            for rec in batch:
                _sync_count_db(rec['question_id'], +1)
        except Exception as e:
            print(f"[Disc] flush error: {e}")
            with _buffer_lock:
                _msg_buffer.extendleft(reversed(batch))

threading.Thread(target=_flush_buffer, daemon=True).start()

def _sync_count_db(question_id, delta):
    try:
        existing = supabase.table('discussion_counts').select('count').eq('question_id', question_id).execute()
        if existing.data:
            new_val = max(0, existing.data[0]['count'] + delta)
            supabase.table('discussion_counts').update({'count': new_val}).eq('question_id', question_id).execute()
        else:
            supabase.table('discussion_counts').insert({'question_id': question_id, 'count': max(0, delta)}).execute()
    except Exception as e:
        print(f"[Disc] count sync error: {e}")

def _sync_count(question_id, delta):
    with _count_lock:
        _count_cache[question_id] = max(0, _count_cache.get(question_id, 0) + delta)

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
    text = text.strip()
    text = re.sub(r'[<>]', '', text)
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
    now_iso = datetime.utcnow().isoformat()
    temp_id = str(uuid.uuid4())
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
        'created_at': now_iso,
        'updated_at': now_iso
    }

    with _buffer_lock:
        _msg_buffer.append(record)
        if len(_msg_buffer) >= BUFFER_MAX_SIZE:
            batch = list(_msg_buffer)
            _msg_buffer.clear()
            threading.Thread(target=_flush_now, args=(batch,), daemon=True).start()

    _sync_count(question_id, +1)

    broadcast_msg = {
        'temp_id': temp_id,
        'question_id': question_id,
        'username': username,
        'message': msg,
        'parent_id': data.get('parent_id'),
        'created_at': now_iso,
        'is_own': False,
        'is_pinned': False,
        'is_best_answer': False,
        'is_edited': False,
        'replies': [],
        'count': _get_count(question_id)
    }

    if socketio:
        socketio.emit('new_message', broadcast_msg, room=f'q_{question_id}')

    own_msg = {**broadcast_msg, 'is_own': True}
    return jsonify({'success': True, 'message': own_msg})


def _flush_now(batch):
    try:
        supabase.table('question_discussions').insert(batch).execute()
        for rec in batch:
            _sync_count_db(rec['question_id'], +1)
    except Exception as e:
        print(f"[Disc] force flush error: {e}")


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
        row = supabase.table('question_discussions').select('user_id,question_id').eq('id', comment_id).execute()
        if not row.data or (row.data[0]['user_id'] != uid and not _is_admin()):
            return jsonify({'success': False, 'message': 'Forbidden'}), 403
        supabase.table('question_discussions').update({
            'message': msg, 'is_edited': True, 'updated_at': datetime.utcnow().isoformat()
        }).eq('id', comment_id).execute()
        qid = row.data[0]['question_id']
        if socketio:
            socketio.emit('edit_message', {'comment_id': comment_id, 'message': msg}, room=f'q_{qid}')
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
        qid = row.data[0]['question_id']
        _sync_count(qid, -1)
        _sync_count_db(qid, -1)
        if socketio:
            socketio.emit('delete_message', {'comment_id': comment_id}, room=f'q_{qid}')
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False}), 500


@discussion_bp.route('/api/discussion/admin/pin/<int:comment_id>', methods=['PUT'])
def admin_pin(comment_id):
    if not _is_admin():
        return jsonify({'success': False}), 403
    try:
        row = supabase.table('question_discussions').select('is_pinned,question_id').eq('id', comment_id).execute()
        if not row.data:
            return jsonify({'success': False}), 404
        new_val = not row.data[0]['is_pinned']
        qid = row.data[0]['question_id']
        supabase.table('question_discussions').update({'is_pinned': new_val}).eq('id', comment_id).execute()
        if socketio:
            socketio.emit('pin_message', {'comment_id': comment_id, 'is_pinned': new_val}, room=f'q_{qid}')
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
        if socketio:
            socketio.emit('best_message', {'comment_id': comment_id, 'is_best_answer': new_val}, room=f'q_{qid}')
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


def register_socketio_events(sio):
    @sio.on('join_discussion')
    def on_join(data):
        if 'user_id' not in session:
            return
        qid = data.get('question_id')
        if qid:
            join_room(f'q_{qid}')

    @sio.on('leave_discussion')
    def on_leave(data):
        qid = data.get('question_id')
        if qid:
            leave_room(f'q_{qid}')