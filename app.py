import boto3
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import os
from dotenv import load_dotenv
from flask_cors import CORS

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Set up Flask configuration using environment variables
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')  # Default is 'your-secret-key' if not set in .env

# Updated URI for PostgreSQL (from environment variable)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', 'postgresql://postgres:postgres@db45230603.c7a06co0a7wo.ap-southeast-2.rds.amazonaws.com:5432/db45230603')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS', False)
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', './uploads')  # Default is './uploads' if not set in .env

# Make sure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize the database
db = SQLAlchemy(app)

# User Model
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Item Model
class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

# Helper: JWT token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = Users.query.get(data['user_id'])
            if not current_user:
                raise Exception('User not found')
        except Exception as e:
            return jsonify({'error': 'Invalid or expired token'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# Signup route
@app.route('/auth/signup', methods=['POST'])
def signup():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password required'}), 400

    if Users.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 409

    user = Users(username=data['username'])
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User created'}), 201

# Login route
@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    user = Users.query.filter_by(username=data.get('username')).first()
    if user and user.check_password(data.get('password')):
        token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token})
    return jsonify({'error': 'Invalid credentials'}), 401

# CRUD Routes for items (protected)
@app.route('/items', methods=['POST'])
@token_required
def create_item(current_user):
    data = request.get_json()
    if not data or not data.get('content'):
        return jsonify({'error': 'Content required'}), 400
    item = Item(content=data['content'], user_id=current_user.id)
    db.session.add(item)
    db.session.commit()
    return jsonify({'message': 'Item created', 'item': {'id': item.id, 'content': item.content}}), 201

@app.route('/items', methods=['GET'])
@token_required
def get_items(current_user):
    items = Item.query.filter_by(user_id=current_user.id).all()
    return jsonify([{'id': item.id, 'content': item.content} for item in items])

@app.route('/items/<int:item_id>', methods=['PUT'])
@token_required
def update_item(current_user, item_id):
    item = Item.query.filter_by(id=item_id, user_id=current_user.id).first()
    if not item:
        return jsonify({'error': 'Item not found'}), 404
    data = request.get_json()
    item.content = data.get('content', item.content)
    db.session.commit()
    return jsonify({'message': 'Item updated', 'item': {'id': item.id, 'content': item.content}})

@app.route('/items/<int:item_id>', methods=['DELETE'])
@token_required
def delete_item(current_user, item_id):
    item = Item.query.filter_by(id=item_id, user_id=current_user.id).first()
    if not item:
        return jsonify({'error': 'Item not found'}), 404
    db.session.delete(item)
    db.session.commit()
    return jsonify({'message': 'Item deleted'})

# Route to upload a file to S3
@app.route('/upload', methods=['POST'])
@token_required
def upload_file(current_user):
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    # Connect to LocalStack S3 using environment variables
    s3_client = boto3.client(
        's3',
        endpoint_url=os.getenv('S3_ENDPOINT_URL', 'http://localhost:4566'),  # Default to LocalStack for testing
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID', 'test'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY', 'test'),
        region_name=os.getenv('AWS_REGION', 'us-east-1')
    )

    try:
        # Upload file to S3 bucket
        s3_client.upload_fileobj(file, os.getenv('S3_BUCKET_NAME', 'my-bucket'), file.filename)
        return jsonify({'message': f'File {file.filename} uploaded successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

