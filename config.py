import os

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "mysecret")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URI", "sqlite:///shareon.db")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "supersecretkey")
