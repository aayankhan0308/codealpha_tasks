# Fixed secure version
import sqlite3
import bcrypt
from flask import Flask, request

app = Flask(__name__)

def secure_hash(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())  # SECURE!

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # SAFE: No SQL injection!
    query = "SELECT * FROM users WHERE username=? AND password=?"
    
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(query, (username, secure_hash(password)))
    user = cursor.fetchone()
    
    if user:
        return "Login success!"
    return "Login failed!"

if __name__ == '__main__':
    app.run(debug=False)  # SECURE: debug mode off