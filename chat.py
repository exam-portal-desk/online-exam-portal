from flask import Blueprint, request, jsonify, session, render_template, redirect, url_for
from flask_socketio import join_room, leave_room
from supabase_db import supabase
import threading, time, re
from datetime import datetime

chat_bp = Blueprint('chat', __name__)
socketio = None

CHAT_RATE_LIMIT = 2
MAX_CHAT_MSG_LEN = 1000
_chat_rate = {}
_chat_rate_lock = threading.Lock()
_online_users = {}
_online_lock = threading.Lock()

_unread_buffer = {}
_unread_lock = threading.Lock()

_member_cache = {}
_member_cache_lock = threading.Lock()
MEMBER_CACHE_TTL = 60

def init_chat_socketio(sio):
    global socketio
    socketio = sio

def _sanitize(text):
    text = text.strip()
    text = re.sub(r'[<>]', '', text)
    return re.sub(r'\s+', ' ', text)

def _rate_ok(uid):
    now = time.time()
    with _chat_rate_lock:
        if now - _chat_rate.get(uid, 0) < CHAT_RATE_LIMIT:
            return False
        _chat_rate[uid] = now
        return True

def _uid():
    return session.get('user_id')

def _uname():
    return session.get('full_name') or session.get('username', 'User')

def _get_members_cached(conv_id):
    now = time.time()
    with _member_cache_lock:
        entry = _member_cache.get(conv_id)
        if entry and now - entry['ts'] < MEMBER_CACHE_TTL:
            return entry['ids']
    res = supabase.table('chat_members').select('user_id').eq('conversation_id', conv_id).execute()
    ids = [m['user_id'] for m in (res.data or [])]
    with _member_cache_lock:
        _member_cache[conv_id] = {'ids': ids, 'ts': now}
    return ids

def _invalidate_member_cache(conv_id):
    with _member_cache_lock:
        _member_cache.pop(conv_id, None)

def _get_or_create_dm_conv(uid1, uid2):
    res = supabase.rpc('get_dm_conversation', {'uid1': uid1, 'uid2': uid2}).execute()
    if res.data:
        return res.data
    conv = supabase.table('chat_conversations').insert({'is_group': False, 'created_by': uid1}).execute()
    cid = conv.data[0]['id']
    supabase.table('chat_members').insert([
        {'conversation_id': cid, 'user_id': uid1, 'role': 'member'},
        {'conversation_id': cid, 'user_id': uid2, 'role': 'member'}
    ]).execute()
    return cid

def _buffer_unread(conv_id, exclude_uid):
    member_ids = _get_members_cached(conv_id)
    with _unread_lock:
        for uid in member_ids:
            if uid != exclude_uid:
                key = (uid, conv_id)
                _unread_buffer[key] = _unread_buffer.get(key, 0) + 1

def _flush_unread():
    while True:
        time.sleep(5)
        with _unread_lock:
            if not _unread_buffer:
                continue
            snapshot = dict(_unread_buffer)
            _unread_buffer.clear()
        for (uid, conv_id), delta in snapshot.items():
            try:
                existing = supabase.table('chat_unread').select('id,count').eq('user_id', uid).eq('conversation_id', conv_id).execute()
                if existing.data:
                    supabase.table('chat_unread').update({'count': existing.data[0]['count'] + delta}).eq('id', existing.data[0]['id']).execute()
                else:
                    supabase.table('chat_unread').insert({'user_id': uid, 'conversation_id': conv_id, 'count': delta}).execute()
            except:
                pass

threading.Thread(target=_flush_unread, daemon=True).start()

def _set_online(uid, sid):
    with _online_lock:
        _online_users[uid] = {'sid': sid, 'ts': time.time()}

def _set_offline(uid):
    with _online_lock:
        _online_users.pop(uid, None)

def _is_online(uid):
    with _online_lock:
        entry = _online_users.get(uid)
        if not entry:
            return False
        return (time.time() - entry['ts']) < 120

def _emit(event, data, room, skip_uid=None):
    if not socketio:
        return
    skip_sid = None
    if skip_uid:
        with _online_lock:
            entry = _online_users.get(skip_uid)
            skip_sid = entry['sid'] if entry else None
    try:
        socketio.emit(event, data, room=room, skip_sid=skip_sid)
    except:
        socketio.emit(event, data, room=room)


@chat_bp.route('/chat')
def chat_page():
    if not _uid():
        return redirect(url_for('login'))
    return render_template('chat.html')


@chat_bp.route('/api/chat/search')
def search_users():
    if not _uid():
        return jsonify({'success': False}), 401
    q = request.args.get('q', '').strip()
    if len(q) < 2:
        return jsonify({'success': True, 'users': []})
    try:
        res = supabase.table('users').select('id,username,full_name').ilike('username', f'%{q}%').neq('id', _uid()).limit(10).execute()
        if not res.data:
            return jsonify({'success': True, 'users': []})
        user_ids = [u['id'] for u in res.data]
        conns = supabase.table('chat_connections').select('requester_id,recipient_id,status').or_(
            ','.join([f'and(requester_id.eq.{_uid()},recipient_id.eq.{uid}),and(requester_id.eq.{uid},recipient_id.eq.{_uid()})' for uid in user_ids])
        ).execute()
        conn_map = {}
        for c in (conns.data or []):
            other = c['recipient_id'] if c['requester_id'] == _uid() else c['requester_id']
            conn_map[other] = c['status']
        users = [{'id': u['id'], 'username': u['username'], 'full_name': u['full_name'],
                  'online': _is_online(u['id']), 'connection_status': conn_map.get(u['id'])} for u in res.data]
        return jsonify({'success': True, 'users': users})
    except:
        return jsonify({'success': False}), 500


@chat_bp.route('/api/chat/request', methods=['POST'])
def send_request():
    if not _uid():
        return jsonify({'success': False}), 401
    data = request.get_json() or {}
    rid = data.get('recipient_id')
    if not rid or rid == _uid():
        return jsonify({'success': False}), 400
    try:
        existing = supabase.table('chat_connections').select('id,status').or_(
            f'and(requester_id.eq.{_uid()},recipient_id.eq.{rid}),and(requester_id.eq.{rid},recipient_id.eq.{_uid()})'
        ).execute()
        if existing.data:
            row = existing.data[0]
            if row['status'] == 'pending':
                return jsonify({'success': False, 'message': 'Request already sent'}), 409
            elif row['status'] == 'accepted':
                return jsonify({'success': False, 'message': 'Already connected'}), 409
            elif row['status'] == 'rejected':
                supabase.table('chat_connections').update({'status': 'pending', 'requester_id': _uid(), 'recipient_id': rid, 'updated_at': datetime.utcnow().isoformat()}).eq('id', row['id']).execute()
                if socketio:
                    socketio.emit('chat_request', {'from_id': _uid(), 'from_name': _uname()}, room=f'user_{rid}')
                return jsonify({'success': True})
        supabase.table('chat_connections').insert({'requester_id': _uid(), 'recipient_id': rid, 'status': 'pending'}).execute()
        if socketio:
            socketio.emit('chat_request', {'from_id': _uid(), 'from_name': _uname()}, room=f'user_{rid}')
        return jsonify({'success': True})
    except:
        return jsonify({'success': False}), 500


@chat_bp.route('/api/chat/request/<int:conn_id>', methods=['PUT'])
def respond_request(conn_id):
    if not _uid():
        return jsonify({'success': False}), 401
    data = request.get_json() or {}
    action = data.get('action')
    if action not in ('accept', 'reject'):
        return jsonify({'success': False}), 400
    try:
        row = supabase.table('chat_connections').select('*').eq('id', conn_id).execute()
        if not row.data or row.data[0]['recipient_id'] != _uid():
            return jsonify({'success': False}), 403
        status = 'accepted' if action == 'accept' else 'rejected'
        supabase.table('chat_connections').update({'status': status, 'updated_at': datetime.utcnow().isoformat()}).eq('id', conn_id).execute()
        req_id = row.data[0]['requester_id']
        if action == 'accept':
            conv_id = _get_or_create_dm_conv(_uid(), req_id)
            if socketio:
                socketio.emit('request_accepted', {'by_name': _uname(), 'conv_id': conv_id}, room=f'user_{req_id}')
            return jsonify({'success': True, 'conv_id': conv_id})
        return jsonify({'success': True})
    except:
        return jsonify({'success': False}), 500


@chat_bp.route('/api/chat/requests/inbox')
def inbox():
    if not _uid():
        return jsonify({'success': False}), 401
    try:
        res = supabase.table('chat_connections').select('id,requester_id,status,created_at').eq('recipient_id', _uid()).eq('status', 'pending').execute()
        if not res.data:
            return jsonify({'success': True, 'requests': []})
        req_ids = [r['requester_id'] for r in res.data]
        users_res = supabase.table('users').select('id,username,full_name').in_('id', req_ids).execute()
        user_map = {u['id']: u for u in (users_res.data or [])}
        requests = [{'conn_id': r['id'], 'from_id': r['requester_id'],
                     'from_name': user_map.get(r['requester_id'], {}).get('full_name') or user_map.get(r['requester_id'], {}).get('username') or 'User',
                     'created_at': r['created_at']} for r in res.data]
        return jsonify({'success': True, 'requests': requests})
    except:
        return jsonify({'success': False}), 500


@chat_bp.route('/api/chat/conversations')
def get_conversations():
    if not _uid():
        return jsonify({'success': False}), 401
    try:
        members = supabase.table('chat_members').select('conversation_id').eq('user_id', _uid()).execute()
        conv_ids = [m['conversation_id'] for m in (members.data or [])]
        if not conv_ids:
            return jsonify({'success': True, 'conversations': []})

        convs = supabase.table('chat_conversations').select('*').in_('id', conv_ids).execute()
        unread_res = supabase.table('chat_unread').select('conversation_id,count').eq('user_id', _uid()).execute()
        unread_map = {u['conversation_id']: u['count'] for u in (unread_res.data or [])}

        last_msgs = {}
        for cid in conv_ids:
            lm = supabase.table('chat_messages').select('message,sender_name,created_at').eq('conversation_id', cid).eq('is_deleted', False).order('created_at', desc=True).limit(1).execute()
            if lm.data:
                last_msgs[cid] = lm.data[0]

        all_members_res = supabase.table('chat_members').select('conversation_id,user_id').in_('conversation_id', conv_ids).execute()
        conv_member_map = {}
        all_other_ids = []
        for m in (all_members_res.data or []):
            conv_member_map.setdefault(m['conversation_id'], []).append(m['user_id'])
            if m['user_id'] != _uid():
                all_other_ids.append(m['user_id'])

        user_cache = {}
        if all_other_ids:
            ur = supabase.table('users').select('id,full_name,username').in_('id', list(set(all_other_ids))).execute()
            user_cache = {u['id']: u for u in (ur.data or [])}

        result = []
        for c in (convs.data or []):
            cid = c['id']
            member_ids = conv_member_map.get(cid, [])
            other_id = None
            members_list = []
            if c['is_group']:
                name = c['group_name'] or 'Group'
                members_list = [
                    {'id': uid, 'name': 'You' if uid == _uid() else (user_cache.get(uid, {}).get('full_name') or user_cache.get(uid, {}).get('username') or '?')}
                    for uid in member_ids
                ]
            else:
                other_ids = [uid for uid in member_ids if uid != _uid()]
                other_id = other_ids[0] if other_ids else None
                u = user_cache.get(other_id, {})
                name = u.get('full_name') or u.get('username') or 'Chat'
            result.append({
                'id': cid, 'name': name, 'is_group': c['is_group'], 'created_by': c.get('created_by'),
                'unread': unread_map.get(cid, 0), 'last_message': last_msgs.get(cid),
                'online': _is_online(other_id) if not c['is_group'] else False,
                'other_id': other_id, 'members': members_list
            })
        result.sort(key=lambda x: x['last_message']['created_at'] if x['last_message'] else '0', reverse=True)
        return jsonify({'success': True, 'conversations': result})
    except Exception as e:
        print(f'[Chat] convs error: {e}')
        return jsonify({'success': False}), 500


@chat_bp.route('/api/chat/messages/<int:conv_id>')
def get_messages(conv_id):
    if not _uid():
        return jsonify({'success': False}), 401
    member = supabase.table('chat_members').select('id').eq('conversation_id', conv_id).eq('user_id', _uid()).execute()
    if not member.data:
        return jsonify({'success': False}), 403
    try:
        vis = supabase.table('chat_visibility').select('cleared_at').eq('user_id', _uid()).eq('conversation_id', conv_id).execute()
        cleared_at = vis.data[0]['cleared_at'] if vis.data else None

        before = request.args.get('before')
        q = supabase.table('chat_messages').select('id,sender_id,sender_name,message,created_at,is_edited,reply_to_id,reply_to_text,reply_to_name').eq('conversation_id', conv_id).eq('is_deleted', False).order('created_at', desc=True).limit(40)
        if before:
            q = q.lt('created_at', before)
        if cleared_at:
            q = q.gt('created_at', cleared_at)
        res = q.execute()
        msgs = list(reversed(res.data or []))
        uid = _uid()
        for m in msgs:
            m['is_own'] = (m['sender_id'] == uid)
            m.pop('sender_id', None)
        supabase.table('chat_unread').update({'count': 0}).eq('user_id', uid).eq('conversation_id', conv_id).execute()
        return jsonify({'success': True, 'messages': msgs})
    except:
        return jsonify({'success': False}), 500


@chat_bp.route('/api/chat/messages/<int:conv_id>', methods=['POST'])
def send_message(conv_id):
    if not _uid():
        return jsonify({'success': False}), 401
    uid = _uid()
    if not _rate_ok(uid):
        return jsonify({'success': False, 'message': 'Slow down'}), 429
    member = supabase.table('chat_members').select('id').eq('conversation_id', conv_id).eq('user_id', uid).execute()
    if not member.data:
        return jsonify({'success': False}), 403
    data = request.get_json() or {}
    msg = data.get('message', '').strip()
    if not msg or len(msg) > MAX_CHAT_MSG_LEN:
        return jsonify({'success': False}), 400
    msg = _sanitize(msg)
    name = _uname()
    now = datetime.utcnow().isoformat()
    reply_to_id = data.get('reply_to_id')
    reply_to_text = data.get('reply_to_text', '')[:100] if data.get('reply_to_text') else None
    reply_to_name = data.get('reply_to_name') or None
    record = {
        'conversation_id': conv_id, 'sender_id': uid, 'sender_name': name,
        'message': msg, 'created_at': now,
        'reply_to_id': reply_to_id, 'reply_to_text': reply_to_text, 'reply_to_name': reply_to_name
    }
    try:
        res = supabase.table('chat_messages').insert(record).execute()
        msg_id = res.data[0]['id']
        _buffer_unread(conv_id, uid)
        broadcast = {
            'id': msg_id, 'sender_name': name, 'message': msg, 'created_at': now,
            'is_own': False, 'conv_id': conv_id,
            'reply_to_id': reply_to_id, 'reply_to_text': reply_to_text, 'reply_to_name': reply_to_name
        }
        _emit('chat_message', broadcast, room=f'conv_{conv_id}', skip_uid=uid)
        return jsonify({'success': True, 'message': {**broadcast, 'is_own': True}})
    except:
        return jsonify({'success': False}), 500


@chat_bp.route('/api/chat/messages/<int:msg_id>/edit', methods=['PUT'])
def edit_message(msg_id):
    if not _uid():
        return jsonify({'success': False}), 401
    data = request.get_json() or {}
    new_text = data.get('message', '').strip()
    if not new_text or len(new_text) > MAX_CHAT_MSG_LEN:
        return jsonify({'success': False, 'message': 'Invalid message'}), 400
    new_text = _sanitize(new_text)
    try:
        row = supabase.table('chat_messages').select('sender_id,conversation_id').eq('id', msg_id).execute()
        if not row.data or row.data[0]['sender_id'] != _uid():
            return jsonify({'success': False}), 403
        conv_id = row.data[0]['conversation_id']
        supabase.table('chat_messages').update({'message': new_text, 'is_edited': True}).eq('id', msg_id).execute()
        _emit('msg_edited', {'msg_id': msg_id, 'message': new_text, 'conv_id': conv_id}, room=f'conv_{conv_id}')
        return jsonify({'success': True, 'message': new_text})
    except:
        return jsonify({'success': False}), 500


@chat_bp.route('/api/chat/messages/<int:msg_id>', methods=['DELETE'])
def delete_message(msg_id):
    if not _uid():
        return jsonify({'success': False}), 401
    try:
        row = supabase.table('chat_messages').select('sender_id,conversation_id').eq('id', msg_id).execute()
        if not row.data or row.data[0]['sender_id'] != _uid():
            return jsonify({'success': False}), 403
        conv_id = row.data[0]['conversation_id']
        supabase.table('chat_messages').update({'is_deleted': True}).eq('id', msg_id).execute()
        _emit('msg_deleted', {'msg_id': msg_id, 'conv_id': conv_id}, room=f'conv_{conv_id}')
        return jsonify({'success': True})
    except:
        return jsonify({'success': False}), 500


@chat_bp.route('/api/chat/conversations/<int:conv_id>/clear', methods=['DELETE'])
def clear_chat(conv_id):
    if not _uid():
        return jsonify({'success': False}), 401
    member = supabase.table('chat_members').select('id').eq('conversation_id', conv_id).eq('user_id', _uid()).execute()
    if not member.data:
        return jsonify({'success': False}), 403
    try:
        now = datetime.utcnow().isoformat()
        existing = supabase.table('chat_visibility').select('id').eq('user_id', _uid()).eq('conversation_id', conv_id).execute()
        if existing.data:
            supabase.table('chat_visibility').update({'cleared_at': now}).eq('id', existing.data[0]['id']).execute()
        else:
            supabase.table('chat_visibility').insert({'user_id': _uid(), 'conversation_id': conv_id, 'cleared_at': now}).execute()
        supabase.table('chat_unread').update({'count': 0}).eq('user_id', _uid()).eq('conversation_id', conv_id).execute()
        return jsonify({'success': True})
    except:
        return jsonify({'success': False}), 500


@chat_bp.route('/api/chat/conversations/<int:conv_id>/read', methods=['POST'])
def mark_read(conv_id):
    if not _uid():
        return jsonify({'success': False}), 401
    member = supabase.table('chat_members').select('id').eq('conversation_id', conv_id).eq('user_id', _uid()).execute()
    if not member.data:
        return jsonify({'success': False}), 403
    try:
        supabase.table('chat_unread').update({'count': 0}).eq('user_id', _uid()).eq('conversation_id', conv_id).execute()
        return jsonify({'success': True})
    except:
        return jsonify({'success': False}), 500


@chat_bp.route('/api/chat/friend/<int:other_id>', methods=['DELETE'])
def remove_friend(other_id):
    if not _uid():
        return jsonify({'success': False}), 401
    try:
        conn = supabase.table('chat_connections').select('id').or_(
            f'and(requester_id.eq.{_uid()},recipient_id.eq.{other_id}),and(requester_id.eq.{other_id},recipient_id.eq.{_uid()})'
        ).execute()
        if conn.data:
            supabase.table('chat_connections').delete().eq('id', conn.data[0]['id']).execute()
        dm_res = supabase.rpc('get_dm_conversation', {'uid1': _uid(), 'uid2': other_id}).execute()
        if dm_res.data:
            conv_id = dm_res.data
            _invalidate_member_cache(conv_id)
            supabase.table('chat_messages').update({'is_deleted': True}).eq('conversation_id', conv_id).execute()
            supabase.table('chat_members').delete().eq('conversation_id', conv_id).execute()
            supabase.table('chat_unread').delete().eq('conversation_id', conv_id).execute()
            supabase.table('chat_visibility').delete().eq('conversation_id', conv_id).execute()
            supabase.table('chat_conversations').delete().eq('id', conv_id).execute()
            if socketio:
                socketio.emit('conversation_removed', {'conv_id': conv_id}, room=f'user_{other_id}')
        return jsonify({'success': True})
    except Exception as e:
        print(f'[Chat] remove friend error: {e}')
        return jsonify({'success': False}), 500


@chat_bp.route('/api/chat/group/<int:conv_id>/exit', methods=['DELETE'])
def exit_group(conv_id):
    if not _uid():
        return jsonify({'success': False}), 401
    try:
        conv = supabase.table('chat_conversations').select('created_by,group_name').eq('id', conv_id).execute()
        if not conv.data:
            return jsonify({'success': False}), 404
        is_creator = conv.data[0]['created_by'] == _uid()
        remaining = supabase.table('chat_members').select('user_id').eq('conversation_id', conv_id).neq('user_id', _uid()).execute()
        supabase.table('chat_members').delete().eq('conversation_id', conv_id).eq('user_id', _uid()).execute()
        supabase.table('chat_unread').delete().eq('conversation_id', conv_id).eq('user_id', _uid()).execute()
        _invalidate_member_cache(conv_id)
        if is_creator and remaining.data:
            supabase.table('chat_conversations').update({'created_by': remaining.data[0]['user_id']}).eq('id', conv_id).execute()
        if socketio:
            socketio.emit('member_left', {'conv_id': conv_id, 'user_name': _uname()}, room=f'conv_{conv_id}')
        if not remaining.data:
            supabase.table('chat_messages').update({'is_deleted': True}).eq('conversation_id', conv_id).execute()
            supabase.table('chat_conversations').delete().eq('id', conv_id).execute()
        if socketio:
            socketio.emit('conversation_removed', {'conv_id': conv_id}, room=f'user_{_uid()}')
        return jsonify({'success': True})
    except Exception as e:
        print(f'[Chat] exit group error: {e}')
        return jsonify({'success': False}), 500


@chat_bp.route('/api/chat/group/<int:conv_id>', methods=['DELETE'])
def delete_group(conv_id):
    if not _uid():
        return jsonify({'success': False}), 401
    try:
        conv = supabase.table('chat_conversations').select('created_by').eq('id', conv_id).execute()
        if not conv.data or conv.data[0]['created_by'] != _uid():
            return jsonify({'success': False, 'message': 'Only group creator can delete the group'}), 403
        members = supabase.table('chat_members').select('user_id').eq('conversation_id', conv_id).execute()
        _invalidate_member_cache(conv_id)
        supabase.table('chat_messages').update({'is_deleted': True}).eq('conversation_id', conv_id).execute()
        supabase.table('chat_members').delete().eq('conversation_id', conv_id).execute()
        supabase.table('chat_unread').delete().eq('conversation_id', conv_id).execute()
        supabase.table('chat_conversations').delete().eq('id', conv_id).execute()
        if socketio:
            for m in (members.data or []):
                socketio.emit('conversation_removed', {'conv_id': conv_id}, room=f'user_{m["user_id"]}')
        return jsonify({'success': True})
    except Exception as e:
        print(f'[Chat] delete group error: {e}')
        return jsonify({'success': False}), 500


@chat_bp.route('/api/chat/group', methods=['POST'])
def create_group():
    if not _uid():
        return jsonify({'success': False}), 401
    data = request.get_json() or {}
    name = data.get('name', '').strip()
    member_ids = data.get('member_ids', [])
    if not name or not member_ids:
        return jsonify({'success': False}), 400
    name = _sanitize(name)[:50]
    try:
        conv = supabase.table('chat_conversations').insert({'is_group': True, 'group_name': name, 'created_by': _uid()}).execute()
        cid = conv.data[0]['id']
        all_members = list(set([_uid()] + member_ids))
        supabase.table('chat_members').insert([
            {'conversation_id': cid, 'user_id': m, 'role': 'admin' if m == _uid() else 'member'}
            for m in all_members
        ]).execute()
        for m in all_members:
            if m != _uid() and socketio:
                socketio.emit('added_to_group', {'conv_id': cid, 'group_name': name}, room=f'user_{m}')
        return jsonify({'success': True, 'conv_id': cid})
    except:
        return jsonify({'success': False}), 500


@chat_bp.route('/api/chat/group/<int:conv_id>/members', methods=['POST'])
def add_group_member(conv_id):
    if not _uid():
        return jsonify({'success': False}), 401
    data = request.get_json() or {}
    new_uid = data.get('user_id')
    if not new_uid:
        return jsonify({'success': False}), 400
    try:
        conv = supabase.table('chat_conversations').select('created_by,group_name').eq('id', conv_id).eq('is_group', True).execute()
        if not conv.data:
            return jsonify({'success': False, 'message': 'Group not found'}), 404
        if conv.data[0]['created_by'] != _uid():
            admin_check = supabase.table('chat_members').select('role').eq('conversation_id', conv_id).eq('user_id', _uid()).execute()
            if not admin_check.data or admin_check.data[0].get('role') != 'admin':
                return jsonify({'success': False, 'message': 'Only admins can add members'}), 403
        already = supabase.table('chat_members').select('id').eq('conversation_id', conv_id).eq('user_id', new_uid).execute()
        if already.data:
            return jsonify({'success': False, 'message': 'User already in group'}), 409
        supabase.table('chat_members').insert({'conversation_id': conv_id, 'user_id': new_uid, 'role': 'member'}).execute()
        _invalidate_member_cache(conv_id)
        group_name = conv.data[0]['group_name'] or 'Group'
        if socketio:
            socketio.emit('added_to_group', {'conv_id': conv_id, 'group_name': group_name}, room=f'user_{new_uid}')
            socketio.emit('member_joined', {'conv_id': conv_id, 'user_id': new_uid}, room=f'conv_{conv_id}')
        return jsonify({'success': True})
    except Exception as e:
        print(f'[Chat] add member error: {e}')
        return jsonify({'success': False}), 500


@chat_bp.route('/api/chat/group/<int:conv_id>/members/<int:target_uid>', methods=['DELETE'])
def remove_group_member(conv_id, target_uid):
    if not _uid():
        return jsonify({'success': False}), 401
    try:
        conv = supabase.table('chat_conversations').select('created_by').eq('id', conv_id).execute()
        if not conv.data:
            return jsonify({'success': False}), 404
        is_admin = conv.data[0]['created_by'] == _uid()
        if not is_admin:
            admin_check = supabase.table('chat_members').select('role').eq('conversation_id', conv_id).eq('user_id', _uid()).execute()
            is_admin = bool(admin_check.data and admin_check.data[0].get('role') == 'admin')
        if not is_admin and target_uid != _uid():
            return jsonify({'success': False}), 403
        supabase.table('chat_members').delete().eq('conversation_id', conv_id).eq('user_id', target_uid).execute()
        supabase.table('chat_unread').delete().eq('conversation_id', conv_id).eq('user_id', target_uid).execute()
        _invalidate_member_cache(conv_id)
        if socketio:
            socketio.emit('removed_from_group', {'conv_id': conv_id}, room=f'user_{target_uid}')
            socketio.emit('member_left', {'conv_id': conv_id, 'user_id': target_uid}, room=f'conv_{conv_id}')
        return jsonify({'success': True})
    except:
        return jsonify({'success': False}), 500


@chat_bp.route('/api/chat/unread_count')
def unread_count():
    if not _uid():
        return jsonify({'success': False}), 401
    try:
        unread_res = supabase.table('chat_unread').select('count').eq('user_id', _uid()).execute()
        total = sum(r['count'] for r in (unread_res.data or []))
        pending_res = supabase.table('chat_connections').select('id', count='exact').eq('recipient_id', _uid()).eq('status', 'pending').execute()
        pending_count = pending_res.count if pending_res.count is not None else len(pending_res.data or [])
        return jsonify({'success': True, 'unread': total, 'requests': pending_count})
    except:
        return jsonify({'success': True, 'unread': 0, 'requests': 0})


@chat_bp.route('/api/chat/online_status')
def online_status():
    if not _uid():
        return jsonify({'success': False}), 401
    data = request.args.get('ids', '')
    try:
        ids = [int(x) for x in data.split(',') if x.strip()]
        result = {uid: _is_online(uid) for uid in ids}
        return jsonify({'success': True, 'status': result})
    except:
        return jsonify({'success': False}), 400


def register_chat_socketio_events(sio):
    @sio.on('connect')
    def on_connect(auth=None):
        uid = session.get('user_id')
        if uid:
            _set_online(uid, request.sid)
            join_room(f'user_{uid}')
            sio.emit('user_online', {'user_id': uid}, skip_sid=request.sid)

    @sio.on('disconnect')
    def on_disconnect(reason=None):
        uid = session.get('user_id')
        if uid:
            _set_offline(uid)
            try:
                sio.emit('user_offline', {'user_id': uid})
            except:
                pass

    @sio.on('join_conv')
    def on_join_conv(data):
        uid = session.get('user_id')
        if not uid:
            return
        cid = data.get('conv_id')
        if not cid:
            return
        member_ids = _get_members_cached(cid)
        if uid in member_ids:
            join_room(f'conv_{cid}')

    @sio.on('leave_conv')
    def on_leave_conv(data):
        cid = data.get('conv_id')
        if cid:
            leave_room(f'conv_{cid}')

    @sio.on('typing')
    def on_typing(data):
        cid = data.get('conv_id')
        uid = session.get('user_id')
        name = session.get('full_name') or session.get('username', '')
        if cid and uid:
            sio.emit('user_typing', {'user_id': uid, 'name': name, 'conv_id': cid}, room=f'conv_{cid}', skip_sid=request.sid)

    @sio.on('heartbeat')
    def on_heartbeat():
        uid = session.get('user_id')
        if uid:
            _set_online(uid, request.sid)