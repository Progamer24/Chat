import os
from flask import Flask, render_template, request, jsonify, session, redirect
from datetime import datetime
import logging
from collections import deque
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-default-secret-key')

# Initialize storage
messages = deque(maxlen=100)  # Store last 100 messages
active_users = {}
banned_users = set()
muted_users = set()
admin_users = {'admin'}  # Default admin user

# Initialize rate limiter
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Update admin check to use environment variable for allowed IPs
ADMIN_IPS = os.environ.get('ADMIN_IPS', '127.0.0.1').split(',')

def is_admin():
    return request.remote_addr in ADMIN_IPS or session.get('username') in admin_users

@app.route('/')
def index():
    if 'username' not in session:
        return redirect('/login')
    return render_template('index.html', admin_users=admin_users)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        if username in banned_users:
            return "You are banned from the chat."
        if username and username not in active_users:
            session['username'] = username
            active_users[username] = datetime.now()
            return redirect('/')
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'username' in session:
        username = session['username']
        if username in active_users:
            del active_users[username]
        session.clear()
    return redirect('/login')

@app.route('/send', methods=['POST'])
@limiter.limit("2 per second")
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
        'is_admin': username in admin_users
    }
    messages.append(new_message)
    return jsonify({'status': 'success'})

@app.route('/get_messages')
def get_messages():
    return jsonify(list(messages))

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
    return jsonify({'status': 'success'})

@app.route('/admin/unban/<username>')
def unban_user(username):
    if not is_admin():
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    banned_users.discard(username)
    return jsonify({'status': 'success'})

@app.route('/admin/mute/<username>')
def mute_user(username):
    if not is_admin():
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    muted_users.add(username)
    return jsonify({'status': 'success'})

@app.route('/admin/unmute/<username>')
def unmute_user(username):
    if not is_admin():
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    muted_users.discard(username)
    return jsonify({'status': 'success'})

@app.route('/admin/grant/<username>')
def grant_admin(username):
    if request.remote_addr not in ADMIN_IPS:
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    admin_users.add(username)
    return jsonify({'status': 'success', 'message': f'Granted admin to {username}'})

@app.route('/admin/revoke/<username>')
def revoke_admin(username):
    if request.remote_addr not in ADMIN_IPS:
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    admin_users.discard(username)
    return jsonify({'status': 'success', 'message': f'Revoked admin from {username}'})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port)
