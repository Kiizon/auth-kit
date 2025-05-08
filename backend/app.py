from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import datetime
import os
from models import db, User

app = Flask(__name__)
CORS(app)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')

# Initialize database
db.init_app(app)

# Create database tables
with app.app_context():
    db.create_all()

def generate_token(user_id):
    """Generate a JWT token for a user"""
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
    }

    #HS256 for speed and security
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

# Sign up a user
@app.route('/signup', methods=['POST'])
def signup():
    """Create a new user and return JWT token expiring in 1 day"""
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Missing required fields'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'User already exists'}), 400
    
    user = User(email=data['email'], password=data['password'])
    db.session.add(user)
    db.session.commit()
    
    token = generate_token(user.id)
    return jsonify({'token': token}), 201

# Login a user
@app.route('/login', methods=['POST'])
def login():
    """Login a user and return JWT token expiring in 1 day"""

    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Missing required fields'}), 400
    
    user = User.query.filter_by(email=data['email']).first()
    if not user or not user.check_password(data['password']):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    user.last_login = datetime.datetime.utcnow()
    db.session.commit()
    
    token = generate_token(user.id)
    return jsonify({'token': token}), 200

if __name__ == '__main__':
    app.run(debug=True)