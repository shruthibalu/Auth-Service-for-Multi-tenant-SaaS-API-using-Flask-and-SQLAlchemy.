from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    status = db.Column(db.Integer, default=0, nullable=False)
    personal = db.Column(db.Boolean, default=False)
    settings = db.Column(db.JSON, default={})
    created_at = db.Column(db.BigInteger, default=int(datetime.utcnow().timestamp()))
    updated_at = db.Column(db.BigInteger, nullable=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)  # Encrypted password
    profile = db.Column(db.JSON, default={})
    status = db.Column(db.Integer, default=0, nullable=False)
    settings = db.Column(db.JSON, default={})
    created_at = db.Column(db.BigInteger, default=int(datetime.utcnow().timestamp()))
    updated_at = db.Column(db.BigInteger, nullable=True)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)

class Member(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    status = db.Column(db.Integer, default=0, nullable=False)
    settings = db.Column(db.JSON, default={})
    created_at = db.Column(db.BigInteger, default=int(datetime.utcnow().timestamp()))
    updated_at = db.Column(db.BigInteger, nullable=True)
