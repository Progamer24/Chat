from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from collections import deque
import os
from datetime import datetime
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Store messages in memory (replace with database for production)
messages = deque(maxlen=100)  # Stores last 100 messages

# Admin IPs (set this in Railway environment variables)
ADMIN_IPS = os.environ.get('ADMIN_IPS', '').split(',')

# Add these lists to store banned and muted users
banned_users = set()
muted_users = set()
active_users = set()

# Add this near the top with other global variables
user_ips = {}  # Dictionary to store username -> IP mapping

@app.route('/')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', messages=list(messages))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        if username:
            session['username'] = username
            return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/send_message', methods=['POST'])
@limiter.limit("1 per second")  # Rate limit message sending
def send_message():
    if 'username' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    username = session['username']
    if username in banned_users:
        return jsonify({'error': 'You are banned'}), 403
    if username in muted_users:
        return jsonify({'error': 'You are muted'}), 403
    
    content = request.form.get('message')
    if not content:
        return jsonify({'error': 'Empty message'}), 400

    # Update user_ips when message is sent
    user_ips[username] = request.remote_addr

    message = {
        'username': username,
        'content': content,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'ip': request.remote_addr,
        'is_admin': request.remote_addr in ADMIN_IPS
    }
    
    messages.append(message)
    return jsonify({'status': 'success'})

@app.route('/get_messages')
def get_messages():
    if 'username' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    # Convert deque to list and add admin status
    message_list = []
    for msg in messages:
        msg_copy = msg.copy()  # Create a copy to avoid modifying original
        msg_copy['is_admin'] = msg.get('ip') in ADMIN_IPS
        message_list.append(msg_copy)
    
    return jsonify(message_list)

@app.route('/clear', methods=['POST'])
def clear_messages():
    if request.remote_addr not in ADMIN_IPS:
        return jsonify({'error': 'Unauthorized'}), 403
    messages.clear()
    return jsonify({'status': 'success'})

# Health check endpoint for Railway
@app.route('/health')
def health_check():
    return jsonify({'status': 'healthy'}), 200

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded'}), 429

# Add these new routes for admin panel
@app.route('/admin')
def admin_panel():
    try:
        if request.remote_addr not in ADMIN_IPS:
            return redirect(url_for('home'))
        
        # Update user_ips when messages are received
        for msg in messages:
            if 'username' in msg and 'ip' in msg:
                user_ips[msg['username']] = msg['ip']
        
        # Get active users with their IPs
        active_users = {}
        for msg in messages:
            if 'username' in msg:
                username = msg['username']
                active_users[username] = user_ips.get(username, 'Unknown')
        
        return render_template('admin.html', 
                             active_users=active_users,
                             banned_users=banned_users,
                             muted_users=muted_users,
                             admin_users=ADMIN_IPS,
                             request=request)  # Pass request object to template
    except Exception as e:
        app.logger.error(f"Admin panel error: {str(e)}")
        return render_template('500.html'), 500

# Add these routes for admin toggle functionality
@app.route('/admin/grant/<username>')
def grant_admin(username):
    if request.remote_addr not in ADMIN_IPS:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403
    if username in user_ips:
        ADMIN_IPS.append(user_ips[username])
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': 'User not found'})

@app.route('/admin/revoke/<username>')
def revoke_admin(username):
    if request.remote_addr not in ADMIN_IPS:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403
    if username in user_ips and user_ips[username] in ADMIN_IPS:
        ADMIN_IPS.remove(user_ips[username])
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': 'User not found or not admin'})

# Add these new admin routes
@app.route('/admin/ban/<username>', methods=['POST'])
def ban_user(username):
    if request.remote_addr not in ADMIN_IPS:
        return jsonify({'error': 'Unauthorized'}), 403
    banned_users.add(username)
    return jsonify({'status': 'success'})

@app.route('/admin/unban/<username>', methods=['POST'])
def unban_user(username):
    if request.remote_addr not in ADMIN_IPS:
        return jsonify({'error': 'Unauthorized'}), 403
    banned_users.discard(username)
    return jsonify({'status': 'success'})

@app.route('/admin/mute/<username>', methods=['POST'])
def mute_user(username):
    if request.remote_addr not in ADMIN_IPS:
        return jsonify({'error': 'Unauthorized'}), 403
    muted_users.add(username)
    return jsonify({'status': 'success'})

@app.route('/admin/unmute/<username>', methods=['POST'])
def unmute_user(username):
    if request.remote_addr not in ADMIN_IPS:
        return jsonify({'error': 'Unauthorized'}), 403
    muted_users.discard(username)
    return jsonify({'status': 'success'})

# Add a link to admin panel in index.html for admin users

if __name__ == '__main__':
    port = os.environ.get('PORT', 5000)
    app.run(host='0.0.0.0', port=port, debug=False)
