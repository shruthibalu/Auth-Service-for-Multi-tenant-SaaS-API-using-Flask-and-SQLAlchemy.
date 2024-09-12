import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key')
    SQLALCHEMY_DATABASE_URI = 'sqlite:///auth_service.db'  # Use PostgreSQL/MySQL if needed
    SQLALCHEMY_TRACK_MODIFICATIONS = False
