from flask import Blueprint, request
from werkzeug.security import check_password_hash, generate_password_hash

auth = Blueprint("auth", __name__, url_prefix="/api/v1/auth")

@auth.post("/register")
def register():
    username = request.json['username']
    email = request.json['email']
    password = request.json['password']
    
    return {"user": "created"}

@auth.get("/me")
def me():
    return {"user": "created"}