#!/usr/bin/env python3
import os
from sqlite3 import IntegrityError
from models import db, Apartment as ApartmentModel, User, bcrypt
from flask_migrate import Migrate
from flask import Flask, request, jsonify, session
from flask_restful import Api, Resource
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = b'Y\xf1Xz\x00\xad|eQ\x80t \xca\x1a\x10K'
app.config['SQLALCHEMY_DATABASE_URI'] =os.environ.get('DATABASE_URI') #'sqlite:///app.db' 
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.json.compact = False

migrate = Migrate(app, db)
db.init_app(app)

CORS(app, supports_credentials=True)
bcrypt.init_app(app)

api = Api(app)

@app.route("/")
def index():
    return "<h1>Apartment App Server</h1>"

class Login(Resource):
    def post(self):
        request_json = request.get_json()
        email = request_json.get('email')
        password = request_json.get('password')

        user = User.query.filter_by(email=email).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(only=('id', 'name', 'email')), 200
        elif user:
            return {"error": "Wrong password"}, 401
        return {'error': '401 Unauthorized'}, 401

class Logout(Resource):
    def delete(self):
        if session.get('user_id'):
            session.pop('user_id', None)
            return {}, 204
        return {'error': 'Unauthorized'}, 401

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.filter_by(id=user_id).first()
            if user:
                return user.to_dict(), 200
        return {}, 401

class Users(Resource):
    def get(self):
        users = User.query.all()
        return [user.to_dict(only=('id', 'name', 'email', 'user_type')) for user in users], 200

    def post(self):
        data = request.get_json()
        password = "password"
        try:
            password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(
                name=data['name'],
                email=data['email'],
                user_type=data['user_type']
            )
            new_user.password_hash = password_hash
            db.session.add(new_user)
            db.session.commit()
            return new_user.to_dict(only=('id', 'name', 'email')), 201
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
    app.run(debug=True)