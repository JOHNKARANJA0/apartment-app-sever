from random import randint, choice as rc
from faker import Faker

from flask_bcrypt import Bcrypt

from app import app
from models import db, Apartment, User

bcrypt = Bcrypt()

fake = Faker()

with app.app_context():

    print("Deleting all records...")
    Apartment.query.delete()
    User.query.delete()

    print("Creating users...")

    users = []
    emails = []

    for i in range(20):
        
        email = fake.email()
        while email in emails:
            email = fake.email()
        emails.append(email)
        password ='password'
        
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        user_types = ['Admin', 'Tentant']
        user_type = rc(user_types)
        user = User(
            name=fake.name(),
            email=email,
            user_type=user_type
        )
        user._password_hash = password_hash 

        users.append(user)

    db.session.add_all(users)
    db.session.commit()  # Commit users to the database

    print("Creating tasks...")
    apartments = []
    random_numbers = [fake.random_number() for _ in range(8)]
    for i in range(50):
        user = rc(users)
        house_numbers = fake.building_number()
        apartment_status = ['Unoccupied', 'Occupied', 'Renovation']
        status = rc(apartment_status)
        meter_no = fake.random_number(digits=8)
        current_bill = fake.random_number(digits=4)
        apartment = Apartment(
            hse_no = house_numbers,
            meter_no= meter_no,
            current_bill = current_bill, 
            status=status,
            user_id=user.id  # Assign a user_id to each task
        )

        apartments.append(apartment)

    db.session.add_all(apartments)
    db.session.commit()  # Commit tasks to the database


    print("Complete.")