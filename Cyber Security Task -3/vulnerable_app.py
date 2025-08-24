# Simple login with security problems
import sqlite3
import hashlib
from flask import Flask, request

app = Flask(__name__)

def weak_hash(password):
    return hashlib.md5(password.encode()).hexdigest()  # UNSAFE!

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # UNSAFE: SQL Injection risk!
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{weak_hash(password)}'"
    
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(query)
    user = cursor.fetchone()
    
    if user:
        return "Login success!"
    return "Login failed!"

if __name__ == '__main__':
    app.run(debug=True)  # UNSAFE: debug mode on