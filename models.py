from flask_sqlalchemy import SQLAlchemy
from datetime import datetime,time
from werkzeug.security import generate_password_hash 

# Initialize the database object
db = SQLAlchemy()

# Admin model
class Admin(db.Model):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Storing hashed passwords
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)

# Parent model
class Parent(db.Model):
    __tablename__ = 'parents'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Storing hashed passwords
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    phone_number = db.Column(db.String(50), nullable=False)
    children = db.relationship('Student', backref='parent', lazy=True)  # Link to students
    alerts = db.relationship('Alert', backref='alert_parent', lazy=True)

# Student model
class Student(db.Model):
    __tablename__ = 'students'
    id = db.Column(db.Integer, primary_key=True)
    student_num = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(80), nullable=False)
    surname = db.Column(db.String(80), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    year_of_study = db.Column(db.Integer, nullable=False)
    course = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('parents.id'), nullable=False)# Foreign key to Parent table
    attendance = db.relationship('Attendance', backref='student', lazy=True)

class SchoolAuthority(db.Model):
    __tablename__ = 'school_authorities'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Storing hashed passwords
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=False)  # Foreign key linking to Admin

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    bus_in_time = db.Column(db.Time, nullable=True)
    bus_out_time = db.Column(db.Time, nullable=True)
    campus_in_time = db.Column(db.Time, nullable=True)
    campus_out_time = db.Column(db.Time, nullable=True)
    status = db.Column(db.String(20), nullable=False)
    bus_check_in_status = db.Column(db.String(20), nullable=True)  # Late, Early, On time
    campus_check_in_status = db.Column(db.String(20), nullable=True)  # Late, Early, On time

from datetime import datetime

class Alert(db.Model):
    __tablename__ = 'alerts'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id'), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('parents.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    date_sent = db.Column(db.DateTime, default=datetime.utcnow)  # Date and time the alert was sent

    student = db.relationship('Student', backref='alerts', lazy=True)
    parent = db.relationship('Parent', backref='alert_parent', lazy=True)


class SystemLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    event_type = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    user_role = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text, nullable=True)


# Initialize the database connection in your app file
def init_db(app):
    db.init_app(app)
    with app.app_context():
        db.create_all()
        






