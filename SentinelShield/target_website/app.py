from flask import Flask, render_template, redirect, url_for, request, session
import json
import os
from datetime import datetime, timezone
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secure key in production

# Shared events file path (will be mounted from SentinelShield)
EVENTS_FILE = '/shared/events.json'

def load_events():
    """Load events from JSON file"""
    try:
        with open(EVENTS_FILE, 'r') as f:
            content = f.read().strip()
            return json.loads(content) if content else []
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_events(events):
    """Save events to JSON file"""
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(EVENTS_FILE), exist_ok=True)
        with open(EVENTS_FILE, 'w') as f:
            json.dump(events, f, indent=4)
    except Exception as e:
        print(f"Error saving events: {e}")

def log_event(event_type, details, severity='MEDIUM', ip=None):
    """Log an event to the shared events.json file"""
    if not ip:
        ip = request.remote_addr
    
    event = {
        'type': event_type,
        'ip': ip,
        'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
        'details': details,
        'severity': severity,
        'source': 'target_website',
        'request_path': request.path,
        'user_agent': request.headers.get('User-Agent', '')[:100]
    }
    
    events = load_events()
    events.append(event)
    save_events(events)
    print(f"Logged event: {event_type} from {ip}")

def detect_suspicious_activity():
    """Detect suspicious activity in the current request"""
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '').lower()
    path = request.path
    
    # 1. Check for suspicious user agents
    suspicious_agents = ['sqlmap', 'nmap', 'nikto', 'curl', 'wget', 'python-requests', 'hydra', 'burp', 'w3af', 'zap', 'scanner', 'bot']
    for agent in suspicious_agents:
        if agent in user_agent:
            log_event('Suspicious User-Agent', f"Detected suspicious user-agent: {agent}", 'HIGH', ip)
            return True
    
    # 2. Check for suspicious paths (potential attacks)
    suspicious_paths = ['/admin', '/wp-admin', '/phpmyadmin', '/config', '/.env', '/backup', '/shell', '/cmd']
    for suspicious_path in suspicious_paths:
        if suspicious_path in path:
            log_event('Suspicious Path Access', f"Attempted access to suspicious path: {path}", 'HIGH', ip)
            return True
    
    # 3. Check for SQL injection patterns in query parameters
    sql_patterns = ["'", "1=1", "OR 1", "UNION SELECT", "DROP TABLE", "INSERT INTO"]
    for param, value in request.args.items():
        for pattern in sql_patterns:
            if pattern.lower() in value.lower():
                log_event('SQL Injection Attempt', f"Potential SQL injection in parameter {param}: {value}", 'CRITICAL', ip)
                return True
    
    # 4. Check for XSS patterns
    xss_patterns = ["<script>", "javascript:", "onerror=", "onload="]
    for param, value in request.args.items():
        for pattern in xss_patterns:
            if pattern.lower() in value.lower():
                log_event('XSS Attempt', f"Potential XSS in parameter {param}: {value}", 'CRITICAL', ip)
                return True
    
    return False

@app.before_request
def require_login():
    # Log all requests for monitoring
    if request.endpoint not in ('login', 'logout', 'signup', 'static'):
        if not session.get('logged_in'):
            log_event('Unauthorized Access', f"Attempted access to {request.path} without login", 'MEDIUM')
            return redirect(url_for('login'))
        else:
            # Check for suspicious activity
            detect_suspicious_activity()

@app.route('/')
def index():
    log_event('Page Access', 'User accessed homepage', 'LOW')
    return render_template('index.html')

@app.route('/how-it-works')
def how_it_works():
    log_event('Page Access', 'User accessed how-it-works page', 'LOW')
    return render_template('how-it-works.html')

@app.route('/use-cases')
def use_cases():
    log_event('Page Access', 'User accessed use-cases page', 'LOW')
    return render_template('use-cases.html')

@app.route('/team')
def team():
    log_event('Page Access', 'User accessed team page', 'LOW')
    return render_template('team.html')

@app.route('/contact')
def contact():
    log_event('Page Access', 'User accessed contact page', 'LOW')
    return render_template('contact.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Log login attempts
        log_event('Login Attempt', 'User attempted login', 'MEDIUM')
        # Accept any login for demo
        session['logged_in'] = True
        log_event('Login Success', 'User successfully logged in', 'LOW')
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Log signup attempts
        log_event('Signup Attempt', 'User attempted to create account', 'MEDIUM')
        # Simulate account creation for demo
        # In a real app, you would save user data to database
        log_event('Signup Success', 'User successfully created account', 'LOW')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout')
def logout():
    if session.get('logged_in'):
        log_event('Logout', 'User logged out', 'LOW')
    session.clear()
    return render_template('logout.html')

# Add a test endpoint to simulate suspicious activity
@app.route('/test-suspicious')
def test_suspicious():
    """Test endpoint to simulate suspicious activity"""
    log_event('Test Event', 'This is a test suspicious event from target website', 'MEDIUM')
    return "Test event logged!"

if __name__ == '__main__':
    # Running on port 8080 to avoid conflict with SentinelShield
    app.run(host='0.0.0.0', port=8080, debug=True) 