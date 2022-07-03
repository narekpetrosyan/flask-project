import datetime
from flask import Blueprint, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash
from src.constants import http_status_codes
import validators
from src.database import User, db
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity


auth = Blueprint("auth", __name__, url_prefix="/api/v1/auth")

@auth.post("/register")
def register():
    username = request.json['username']
    email = request.json['email']
    password = request.json['password']

    if len(password) < 6:
        return jsonify({"error": "Password too short"}),http_status_codes.HTTP_400_BAD_REQUEST

    if len(username) < 6:
        return jsonify({"error": "Username too short"}),http_status_codes.HTTP_400_BAD_REQUEST

    if not username.isalnum() or " " in username:
        return jsonify({"error": "Username holds an alphanumeric"}),http_status_codes.HTTP_400_BAD_REQUEST

    if not validators.email(email):
        return jsonify({"error": "Email is not valid"}),http_status_codes.HTTP_400_BAD_REQUEST

    if User.query.filter_by(email=email).first() is not None:
        return jsonify({"error": "Email already registered"}),http_status_codes.HTTP_409_CONFLICT

    if User.query.filter_by(username=username).first() is not None:
        return jsonify({"error": "Username already registered"}),http_status_codes.HTTP_409_CONFLICT

    pwd_hash = generate_password_hash(password)

    user = User(username=username, password=pwd_hash, email=email)
    db.session.add(user)
    db.session.commit()
    
    return jsonify(
        {"message": "User created", "user": {
            "username":username, 
            "email": email
        }}
    ), http_status_codes.HTTP_201_CREATED

@auth.post("/login")
def login():
    email = request.json.get('email','')
    password = request.json.get('password','')

    user = User.query.filter_by(email=email).first()

    if user:
        is_pass_correct = check_password_hash(user.password, password)

        if is_pass_correct:
            refresh = create_refresh_token(user.id,expires_delta=datetime.timedelta(minutes=15))
            access = create_access_token(user.id,expires_delta=datetime.timedelta(days=30))

            return jsonify({
                "username": user.username,
                'access_token': access,
                "refresh_token": refresh
            }), http_status_codes.HTTP_200_OK


    return jsonify({
        'message': "Wrong credentials"
    }), http_status_codes.HTTP_401_UNAUTHORIZED

@auth.get("/me")
@jwt_required()
def me():
    user_id = get_jwt_identity()
    user = User.query.filter_by(id=user_id).first()
    return jsonify({
        "username": user.username,
        "email": user.email,
    }), http_status_codes.HTTP_200_OK


@auth.post("/token/refresh")
@jwt_required(refresh=True)
def refresh_user_token():
    user_id = get_jwt_identity()
    access = create_access_token(identity=user_id)

    return jsonify({
        "access_token": access
    })