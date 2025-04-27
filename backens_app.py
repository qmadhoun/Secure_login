from flask import Flask, render_template, request, redirect, url_for
import json
import bcrypt
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Crucial voor sessiebeveiliging

USER_FILE = 'users.json'

# Helper-functies
def load_users():
    try:
        with open(USER_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_user(username, password):
    users = load_users()
    
    # Controleer of gebruiker al bestaat
    if any(user['username'] == username for user in users):
        return False
    
    # Hash wachtwoord met bcrypt
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    users.append({
        'username': username,
        'password': hashed_pw.decode('utf-8')  # Bewaar als string
    })
    
    with open(USER_FILE, 'w') as f:
        json.dump(users, f, indent=4)
    
    return True

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    message = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        users = load_users()
        user = next((u for u in users if u['username'] == username), None)
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            message = "Succesvol ingelogd! 🎉"
        else:
            message = "Foutieve inloggegevens! ❌"
    
    return render_template('login.html', message=message)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if save_user(username, password):
            return redirect(url_for('login', message="Registratie succesvol! ✅"))
        else:
            return render_template('register.html', message="Gebruikersnaam bestaat al! ⚠️")
    
    return render_template('register.html')

if __name__ == '__main__':
    app.run(
        ssl_context=('certs/cert.pem', 'certs/key.pem'),
        host='0.0.0.0',
        port=443,
        debug=True  # Uitzetten in productie!
    )
