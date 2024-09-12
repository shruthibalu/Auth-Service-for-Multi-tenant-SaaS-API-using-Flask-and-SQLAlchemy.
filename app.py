from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import jwt
import os
from functools import wraps
from models import db, User, Organization, Member, Role

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth_service.db'  # You can change to Postgres/MySQL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# Token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
        except:
            return jsonify({'message': 'Token is invalid!'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(email=data['email'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    new_organization = Organization(name=data['organization_name'])
    db.session.add(new_organization)
    db.session.commit()

    owner_role = Role(name='Owner', org_id=new_organization.id)
    db.session.add(owner_role)
    db.session.commit()

    new_member = Member(user_id=new_user.id, org_id=new_organization.id, role_id=owner_role.id)
    db.session.add(new_member)
    db.session.commit()

    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()

    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401

    token = jwt.encode({'user_id': user.id, 'exp': datetime.utcnow() + timedelta(minutes=30)},
                       app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({'token': token})

@app.route('/reset-password', methods=['POST'])
@token_required
def reset_password(current_user):
    data = request.get_json()
    new_password = generate_password_hash(data['new_password'], method='sha256')
    current_user.password = new_password
    db.session.commit()

    return jsonify({'message': 'Password updated successfully'})

@app.route('/invite-member', methods=['POST'])
@token_required
def invite_member(current_user):
    data = request.get_json()

    invited_user = User.query.filter_by(email=data['email']).first()
    if invited_user:
        return jsonify({'message': 'User already exists'})

    new_user = User(email=data['email'], password=generate_password_hash('temporary_password', method='sha256'))
    db.session.add(new_user)
    db.session.commit()

    role = Role.query.filter_by(name=data['role'], org_id=data['org_id']).first()
    if not role:
        return jsonify({'message': 'Role not found'}), 404

    new_member = Member(user_id=new_user.id, org_id=data['org_id'], role_id=role.id)
    db.session.add(new_member)
    db.session.commit()

    # Add email sending logic here
    return jsonify({'message': 'User invited successfully'})

# Other API endpoints for deleting members, updating roles, etc. can follow a similar pattern

if __name__ == '__main__':
    app.run(debug=True)
