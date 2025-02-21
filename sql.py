#how to detect and fix sql injection

#snippet which introduces sql injection vulneribility 
import sqlite3
from flask import Flask, request

app = Flask(__name__)

def create_database(): #example databasez
    conn = sqlite3.connect('example.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''') #created a table
    c.execute("INSERT INTO users (username, password) VALUES ('admin', 'adminpass')") #added one row inside it -> required/correct username and password
    conn.commit()
    conn.close()

@app.route('/login', methods=['GET', 'POST']) #created a /login endpoint  webpage bound to the login page given below
def login():
    #getting values from the user and storing it in respective variables
    username = request.args.get('username')
    password = request.args.get('password')
    conn = sqlite3.connect('example.db')
    c = conn.cursor()
    
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'" #directly feeding the values to the query 
    #if login successfull -> get a login message
    print("Executing query:", query)
    c.execute(query)
    result = c.fetchone()
    conn.close()
    if result:
        return "Login successful"
    else:
        return "Login failed"

if __name__ == '__main__':
    create_database()
    app.run(debug=True)



"""
SQL Injection Exploit:
Now, try injecting SQL in the username field:

browser: 
http://127.0.0.1:5000/login?username=admin'--&password=anything
This works because:

The query becomes:
SELECT * FROM users WHERE username = 'admin'--' AND password = 'anything'
The -- comment out the rest, effectively making the password check irrelevant.

Use OR '1'='1' to log in as anyone:
browser:
http://127.0.0.1:5000/login?username=' OR '1'='1&password=

Now, the query becomes:
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = ''

Since '1'='1' is always TRUE, login is bypassed!

"""