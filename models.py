#!/usr/bin/env python3

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import MetaData
from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()

metadata = MetaData(
    naming_convention={
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    }
)

db = SQLAlchemy(metadata=metadata)

# Creating the users
class User(db.Model, SerializerMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    user_type = db.Column(db.String, nullable=False)
    _password_hash = db.Column('password_hash', db.String(128), nullable=False)
    
    apartments = db.relationship('Apartment', backref='user', lazy=True, cascade='all, delete-orphan')
    
    serialize_rules = ('-apartments.user', '-_password_hash')
    
    @validates('email')
    def validate_email(self, key, value):
        assert '@' in value, "Invalid Email provided"
        return value
    
    @hybrid_property
    def password_hash(self):
        raise AttributeError('Password hashes may not be viewed.')
    
    @password_hash.setter
    def password_hash(self, password):
        self._password_hash = bcrypt.generate_password_hash(password.encode('utf-8')).decode('utf-8')
    
    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password.encode('utf-8'))


class Apartment(db.Model, SerializerMixin):
    __tablename__ = 'apartments'
    
    id = db.Column(db.Integer, primary_key=True)
    hse_no = db.Column(db.String(100), nullable=False)
    meter_no = db.Column(db.Integer, nullable=False)
    current_bill = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    serialize_rules = ('-user.apartments',)

    def __repr__(self):
        return f"<Apartment {self.hse_no}>"