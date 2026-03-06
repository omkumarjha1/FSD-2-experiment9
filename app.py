from flask import Flask, request, jsonify
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_super_secret_key'

# Mock User Database
users = {
    "admin": "password123"
}

# --- Helper: Token Required Decorator ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Checking Bearer Header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['user']
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
            
        return f(current_user, *args, **kwargs)
    return decorated

# --- 1. Basic Auth (Authorization Header) ---
@app.route('/login/basic', methods=['POST'])
def login_basic():
    auth = request.authorization
    if auth and auth.username in users and users[auth.username] == auth.password:
        return jsonify({"message": f"Welcome {auth.username}! Authenticated via Basic Auth."})
    return jsonify({"message": "Invalid Credentials"}), 401

# --- 2. Custom Header Auth ---
@app.route('/login/custom', methods=['POST'])
def login_custom():
    username = request.headers.get('X-Custom-User')
    password = request.headers.get('X-Custom-Pass')
    
    if username in users and users[username] == password:
        return jsonify({"message": "Authenticated via Custom Headers."})
    return jsonify({"message": "Invalid Credentials"}), 401

# --- 3. JWT Generation (Bearer Header) ---
@app.route('/login/jwt', methods=['POST'])
def login_jwt():
    auth = request.json
    if not auth or not auth.get('username') or not auth.get('password'):
        return jsonify({"message": "Missing credentials"}), 400

    if auth['username'] in users and users[auth['username']] == auth['password']:
        token = jwt.encode({
            'user': auth['username'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({'token': token})

    return jsonify({"message": "Invalid Credentials"}), 401

# --- Protected Route (Testing the JWT) ---
@app.route('/protected', methods=['GET'])
@token_required
def protected(current_user):
    return jsonify({"message": f"Hello {current_user}, you have access to this protected route!"})

if __name__ == '__main__':
    app.run(debug=True)