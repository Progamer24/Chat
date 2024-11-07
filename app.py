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
    
    content = request.form.get('message')
    if not content:
        return jsonify({'error': 'Empty message'}), 400

    message = {
        'username': session['username'],
        'content': content,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'ip': request.remote_addr
    }
    
    messages.append(message)
    return jsonify({'status': 'success'})

@app.route('/get_messages')
def get_messages():
    if 'username' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    return jsonify(list(messages))

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
    if request.remote_addr not in ADMIN_IPS:
        return redirect(url_for('home'))
    
    return render_template('admin.html', 
                         active_users=dict(messages),  # This is simplified, you might want to track active users differently
                         banned_users=[],  # Implement banned users list
                         muted_users=[],   # Implement muted users list
                         admin_users=ADMIN_IPS)

# Add a link to admin panel in index.html for admin users

if __name__ == '__main__':
    port = os.environ.get('PORT', 5000)
    app.run(host='0.0.0.0', port=port, debug=False)
