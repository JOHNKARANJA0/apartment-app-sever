#!/usr/bin/env python3
import os
import random
from datetime import timedelta
from flask import Flask, request, jsonify
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required, get_jwt
from flask_restful import Api, Resource
from flask_cors import CORS
from models import db, Apartment as ApartmentModel, User, bcrypt

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI')  # e.g., 'sqlite:///app.db'
app.config["JWT_SECRET_KEY"] = "your_jwt_secret_key"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)
app.config["SECRET_KEY"] = "your_secret_key"

app.json.compact = False
jwt = JWTManager(app)

migrate = Migrate(app, db)
db.init_app(app)
bcrypt.init_app(app)
api = Api(app)

@app.route("/")
def index():
    return "<h1>Apartment App Server</h1>"

class Login(Resource):
    def post(self):
        request_json = request.get_json()
        email = request_json.get('email', None)
        password = request_json.get('password', None)

        user = User.query.filter_by(email=email).first()

        if user and user.authenticate(password):
            access_token = create_access_token(identity=user.id)
            return {"access_token": access_token}
        else:
            return {"message": "Invalid email or password"}, 401

class CheckSession(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)
        if current_user:
            apartments = [apt.to_dict() for apt in current_user.apartments]
            return {
                "id": current_user.id,
                "name": current_user.name,
                "email": current_user.email,
                "apartments": apartments
            }, 200
        else:
            return {"error": "User not found"}, 404

BLACKLIST = set()
@jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(jwt_header, decrypted_token):
    return decrypted_token['jti'] in BLACKLIST

class Logout(Resource):
    @jwt_required()
    def post(self):
        jti = get_jwt()["jti"]
        BLACKLIST.add(jti)
        return {"success": "Successfully logged out"}, 200

class Users(Resource):
    def get(self):
        users = User.query.all()
        return [user.to_dict(only=('id', 'name', 'email', 'user_type')) for user in users], 200

    def post(self):
        data = request.get_json()
        password = data['password']
        try:
            password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(
                name=data['name'],
                email=data['email'],
                user_type=data['user_type']
            )
            new_user._password_hash = password_hash
            db.session.add(new_user)
            db.session.commit()
            return {"success": "User created successfully!"}, 201
        except Exception as e:
            db.session.rollback()
            return {"errors": [str(e)]}, 400

class ApartmentResource(Resource):
    def get(self):
        apartments = ApartmentModel.query.all()
        return [apartment.to_dict() for apartment in apartments], 200

api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(Users, '/users')
api.add_resource(ApartmentResource, '/apartments')

if __name__ == "__main__":
    app.run(debug=False)