from flask import Flask, render_template, redirect, url_for, request, session

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secure key in production

@app.before_request
def require_login():
    if request.endpoint not in ('login', 'logout', 'static') and not session.get('logged_in'):
        return redirect(url_for('login'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/how-it-works')
def how_it_works():
    return render_template('how-it-works.html')

@app.route('/use-cases')
def use_cases():
    return render_template('use-cases.html')

@app.route('/team')
def team():
    return render_template('team.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Accept any login for demo
        session['logged_in'] = True
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return render_template('logout.html')

if __name__ == '__main__':
    # Running on port 8080 to avoid conflict with SentinelShield
    app.run(host='0.0.0.0', port=8080, debug=True) 