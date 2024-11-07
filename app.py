from flask import Flask, render_template, request, jsonify, session, redirect
from datetime import datetime
import logging

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

logging.basicConfig(filename='chat_access.log', level=logging.INFO)

messages = []
active_users = {}  # Store active users and their IPs
banned_users = set()  # Store banned usernames
muted_users = set()  # Store muted usernames
admin_users = {'admin'}  # Default admin user, you can remove if not needed

# Admin functions
def is_admin():
    return request.remote_addr == '127.0.0.1' or session.get('username') in admin_users

@app.route('/admin')
def admin_panel():
    if not is_admin():
        return redirect('/')
    return render_template('admin.html', 
                         active_users=active_users,
                         banned_users=banned_users,
                         muted_users=muted_users,
                         admin_users=admin_users,
                         request=request)

@app.route('/admin/ban/<username>')
def ban_user(username):
    if not is_admin():
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    banned_users.add(username)
    if username in active_users:
        del active_users[username]
    return jsonify({'status': 'success', 'message': f'Banned {username}'})

@app.route('/admin/unban/<username>')
def unban_user(username):
    if not is_admin():
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    banned_users.discard(username)
    return jsonify({'status': 'success', 'message': f'Unbanned {username}'})

@app.route('/admin/mute/<username>')
def mute_user(username):
    if not is_admin():
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    muted_users.add(username)
    return jsonify({'status': 'success', 'message': f'Muted {username}'})

@app.route('/admin/unmute/<username>')
def unmute_user(username):
    if not is_admin():
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    muted_users.discard(username)
    return jsonify({'status': 'success', 'message': f'Unmuted {username}'})

@app.route('/admin/grant/<username>')
def grant_admin(username):
    if request.remote_addr != '127.0.0.1':  # Only localhost can grant admin
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    admin_users.add(username)
    return jsonify({'status': 'success', 'message': f'Granted admin to {username}'})

@app.route('/admin/revoke/<username>')
def revoke_admin(username):
    if request.remote_addr != '127.0.0.1':  # Only localhost can revoke admin
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    admin_users.discard(username)
    return jsonify({'status': 'success', 'message': f'Revoked admin from {username}'})

@app.route('/')
def index():
    if 'username' not in session:
        return redirect('/login')
    return render_template('index.html', admin_users=admin_users)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        if username:
            if username in banned_users:
                return "You have been banned from the chat.", 403
            session['username'] = username
            ip = request.remote_addr
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            logging.info(f'New user joined - Username: {username}, IP: {ip}, Time: {timestamp}')
            active_users[username] = ip
            return redirect('/')
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'username' in session:
        username = session['username']
        session.pop('username', None)
        if username in active_users:
            del active_users[username]
    return redirect('/login')

@app.route('/send', methods=['POST'])
def send():
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Not logged in'})
    
    username = session['username']
    if username in banned_users:
        session.clear()
        return jsonify({'status': 'error', 'message': 'You are banned'})
    
    if username in muted_users:
        return jsonify({'status': 'error', 'message': 'You are muted'})
        
    data = request.get_json()
    message = data.get('message')
    timestamp = datetime.now().strftime('%H:%M:%S')
    
    new_message = {
        'username': username,
        'message': message,
        'timestamp': timestamp,
        'is_admin': username in admin_users  # Add admin status to message
    }
    messages.append(new_message)
    return jsonify({'status': 'success'})

@app.route('/get_messages')
def get_messages():
    return jsonify(messages)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
