from flask import Flask, render_template
from flask import Flask, render_template, redirect, url_for, flash, session, request
from werkzeug.security import generate_password_hash , check_password_hash
from flask_sqlalchemy import SQLAlchemy
#from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from datetime import datetime, time,timedelta
from flask import Flask
from models import db, Admin, Parent, Student,SchoolAuthority, SystemLog, Attendance, Alert
from flask import request
from forms import LoginForm,RegistrationForm
#from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = 'MlondiMlaba04'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///school_database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)


with app.app_context():
    db.create_all()
    admin=Admin(username="admin",
                    email="admin@admin.com",
                    password=generate_password_hash("password"),
                    first_name="administrator",
                    last_name="phungula")
        
    SchoolAuthority= SchoolAuthority(username="SchoolAuthority",
                                         email="SchoolAuthority@SchoolAuthority.com",
                                         password=generate_password_hash("password"),
                                         first_name="SchoolAuthority",
                                         last_name="phungula",
                                         admin_id=1)
    db.session.add(admin)
    db.session.add(SchoolAuthority)
    try:
        db.session.commit()
    except:
        db.session.rollback()

"""@app.route('/')
def home():
    form = LoginForm()
    return render_template('login.html',form=form)"""
@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        role =form.role.data
        username = form.username.data
        password =form.password.data

        # Check if the user is a parent
        parent = Parent.query.filter_by(username=username).first()
        if parent and check_password_hash(parent.password, password):
            session['user_id'] = parent.id
            session['username'] = parent.username
            session['role'] = 'parent'
            flash('Login successful! Welcome, Parent!', 'success')
            return redirect(url_for('parent_dashboard'))
        
        # Check if the user is an admin
        admin = Admin.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password, password):
            session['user_id'] = admin.id
            session['username'] = admin.username
            session['role'] = 'admin'
            flash('Login successful! Welcome, Admin!', 'success')
            return redirect(url_for('admin_dashboard'))
        
        school_authority = SchoolAuthority.query.filter_by(username=username).first()
        if school_authority and check_password_hash(school_authority.password, password):
            session['username'] = school_authority.username
            session['role'] = 'school_authority'
            return redirect(url_for('school_authority_dashboard'))
        
        if role == 'student':
            name = request.form['name']
            student = Student.query.filter_by(name=name).first()
            if student and check_password_hash(student.password, password):
                session['student_id'] = student.id
                session['role'] = 'student'
                flash('Login successful!', 'success')
                return redirect(url_for('student_dashboard'))
        

        # If neither, show error
        flash('Invalid username or password!', 'danger')
    
    return render_template('login.html',form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        role =form.role.data
        username =form.username.data
        email =form.email.data
        password =form.password.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        phone_number = request.form['phone_number'] if role == 'parent' else None  # Only for parents

        # Hash the password before storing
        hashed_password = generate_password_hash(password)

        if role == 'parent':
            new_user = Parent(username=username, email=email, password=hashed_password,
                              first_name=first_name, last_name=last_name, phone_number=phone_number)
            db.session.add(new_user)
        elif role == 'admin':
            new_user = Admin(username=username, email=email, password=hashed_password,
                             first_name=first_name, last_name=last_name)
            db.session.add(new_user)

        db.session.commit()
        flash('Registration successful!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html',form=form)



@app.route('/register_student', methods=['GET', 'POST'])
def register_student():
    if 'username' in session and session['role'] == 'parent':
        if request.method == 'POST':
            student_number = request.form['student_num']
            student_name = request.form['name']
            student_surname = request.form['surname']  # Capture surname
            student_age = request.form['age']
            student_year = request.form['year_of_study']# Capture grade
            student_course = request.form['course']
            student_password = request.form['password']
            parent_id = session['user_id']  # Get the logged-in parent ID
            
            
            #hashed_password = generate_password_hash(password)

            # Create a new student instance
            new_student = Student(
                student_num=student_number,
                name=student_name,
                surname=student_surname,  # Store surname
                age=student_age,
                year_of_study=student_year,  # Store grade
                course=student_course,
                password=generate_password_hash(student_password),
                parent_id=parent_id
            )
            db.session.add(new_student)
            db.session.commit()

            flash('Student registered successfully!', 'success')
            return redirect(url_for('view_children'))  # Redirect to view children after registration

        return render_template('register_student.html')  # Render the registration form if GET request
    else:
        flash("You must be logged in as a Parent to register a student.", 'danger')
        return redirect(url_for('login'))
    
@app.route('/register_school_authority', methods=['GET', 'POST'])
def register_school_authority():
    if 'username' in session and session['role'] == 'admin':
        if request.method == 'POST':
            # Get the school authority data from the form
            authority_username = request.form['username']
            authority_email = request.form['email']
            authority_password = request.form['password']# You should hash this password
            authority_first_name = request.form['first_name']
            authority_last_name = request.form['last_name']
            
            # Ensure the authority is linked with the current logged-in admin
            admin_id = session['user_id']  # Retrieve admin_id from session
            
            # Create the school authority entry in the database
            new_authority = SchoolAuthority(
                username=authority_username,
                email=authority_email,
                password=generate_password_hash(authority_password),# Hashing the password
                first_name=authority_first_name,
                last_name=authority_last_name,
                admin_id=admin_id
            )
            db.session.add(new_authority)
            db.session.commit()

            flash('School Authority registered successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        
        # Render the school authority registration form if it's a GET request
        return render_template('register_school_authority.html')
    
    else:
        flash("You must be logged in as an Admin to register a School Authority.", 'danger')
        return redirect(url_for('login'))

@app.route('/manage_users', methods=['GET', 'POST'])
def manage_users():
    if 'username' in session and session['role'] == 'admin':
        parents = Parent.query.all()  # Fetch all parents
        admins = Admin.query.all()  # Fetch all admins
        school_authorities = SchoolAuthority.query.all()  # Fetch all school authorities

        return render_template('manage_users.html', parents=parents, admins=admins, school_authorities=school_authorities)
    else:
        flash("You must be logged in as an Admin to manage users.", 'danger')
        return redirect(url_for('admin_login'))
    
@app.route('/manage_students', methods=['GET', 'POST'])
def manage_students():
    if 'username' in session and session['role'] == 'admin':
        students = Student.query.all()  # Fetch all students
        return render_template('manage_students.html', students=students)
    else:
        flash("You must be logged in as an Admin to manage students.", 'danger')
        return redirect(url_for('admin_login'))
 
    

@app.route('/add_user', methods=['POST'])
def add_user():
    if 'username' in session and session['role'] == 'admin':
        role = request.form['role']
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])# Hash the password
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        
        
        if role == 'parent':
            new_parent = Parent(username=username, email=email, password=password, first_name=first_name, last_name=last_name)
            db.session.add(new_parent)
        elif role == 'admin':
            new_admin = Admin(username=username, email=email, password=password, first_name=first_name, last_name=last_name)
            db.session.add(new_admin)
        elif role == 'school_authority':
            new_authority = SchoolAuthority(username=username, email=email, password=password, first_name=first_name, last_name=last_name)
            db.session.add(new_authority)

        db.session.commit()
        flash(f'{role.capitalize()} added successfully!', 'success')
        return redirect(url_for('manage_users'))
    else:
        flash("You must be logged in as an Admin to add users.", 'danger')
        return redirect(url_for('admin_login'))
    
@app.route('/add_student', methods=['POST'])
def add_student():
    if 'username' in session and session['role'] == 'admin':
        first_name = request.form['first_name']
        surname = request.form['surname']
        grade = request.form['grade']
        parent_id = request.form['parent_id']  # Link to the parent

        new_student = Student(first_name=first_name, surname=surname, grade=grade, parent_id=parent_id)
        db.session.add(new_student)
        db.session.commit()
        flash('Student added successfully!', 'success')
        return redirect(url_for('manage_students'))
    else:
        flash("You must be logged in as an Admin to add students.", 'danger')
        return redirect(url_for('admin_login'))
    

@app.route('/edit_school_authority/<int:authority_id>', methods=['GET', 'POST'])
def edit_school_authority(authority_id):
    authority = SchoolAuthority.query.get_or_404(authority_id)
    if request.method == 'POST':
        authority.username = request.form['username']
        authority.email = request.form['email']
        if request.form['password']:
            authority.password = generate_password_hash(request.form['password'])
        
        db.session.commit()
        flash('School Authority updated successfully!', 'success')
        return redirect(url_for('manage_users'))
    
    return render_template('edit_user.html', user=authority)

@app.route('/edit_student/<int:student_id>', methods=['GET', 'POST'])
def edit_student(student_id):
    student = Student.query.get_or_404(student_id)
    if request.method == 'POST':
        # Update student details with data from the form
        student.student_num = request.form['student_num']
        student.name = request.form['name']
        student.surname = request.form['surname']
        student.age = request.form['age']
        student.year_of_study = request.form['year_of_study']
        student.course = request.form['course']  # If parent ID can change

        db.session.commit()
        flash('Student details updated successfully!', 'success')
        return redirect(url_for('view_children'))  # Redirect to the children view

    return render_template('edit_student.html', student=student)

@app.route('/delete_student/<int:student_id>')
def delete_student(student_id):
    student = Student.query.get_or_404(student_id)
    db.session.delete(student)
    db.session.commit()
    flash('Student deleted successfully!', 'success')
    return redirect(url_for('manage_students'))


@app.route('/delete_school_authority/<int:authority_id>')
def delete_school_authority(authority_id):
    authority = SchoolAuthority.query.get_or_404(authority_id)
    db.session.delete(authority)
    db.session.commit()
    flash('School Authority deleted successfully!', 'success')
    return redirect(url_for('manage_users'))

    
@app.route('/view_children')
def view_children():
    try:
        if 'username' in session and session['role'] == 'parent':
            parent_id = session['user_id']
            students = Student.query.filter_by(parent_id=parent_id).all()
            return render_template('view_children.html', students=students)
        else:
            flash("You must be logged in as a Parent to view your children.", 'danger')
            return redirect(url_for('login'))
    except Exception as e:
        print(f"Error: {e}")  # Prints error to the console/log
        return "An error occurred", 500
    
@app.route('/student_details/<int:student_id>')
def student_details(student_id):
    student = Student.query.get_or_404(student_id)  # Fetch student by ID
    if student.parent_id != session['user_id']:
        flash("You do not have permission to view this student's details.", 'danger')
        return redirect(url_for('view_children'))

    return render_template('student_details.html', student=student)

BUS_CHECK_IN_TIME = time(9, 30)  # 09:30 AM
CAMPUS_CHECK_IN_TIME = time(10, 0)

def check_student_check_in(bus_in_time, campus_in_time):
    bus_status = "On time"
    campus_status = "On time"

    # Check Bus Check-In
    if bus_in_time > BUS_CHECK_IN_TIME:
        bus_status = "Late"
    elif bus_in_time < BUS_CHECK_IN_TIME - timedelta(minutes=10):
        bus_status = "Early"

    # Check Campus Check-In
    if campus_in_time > CAMPUS_CHECK_IN_TIME:
        campus_status = "Late"
    elif campus_in_time < CAMPUS_CHECK_IN_TIME - timedelta(minutes=10):
        campus_status = "Early"

    return bus_status, campus_status


@app.route('/check_in_bus', methods=['POST'])
def check_in_bus():
    student_id = session['student_id']  # Assuming student ID is stored in session
    date = datetime.now().date()  # Get the current date

    # Fetch or create an attendance record for today
    attendance = Attendance.query.filter_by(student_id=student_id, date=date).first()
    if not attendance:
        attendance = Attendance(student_id=student_id, date=date, status='Present')
        db.session.add(attendance)
    
    bus_in_time = datetime.now().time()
    attendance.bus_in = bus_in_time  # Update the bus check-in time

    # Determine bus check-in status
    if bus_in_time > BUS_CHECK_IN_TIME:
        attendance.bus_check_in_status = "Late"
    elif bus_in_time < (datetime.combine(date, BUS_CHECK_IN_TIME) - timedelta(minutes=10)).time():
        attendance.bus_check_in_status = "Early"
    else:
        attendance.bus_check_in_status = "On time"
    
    # Update the bus check-in time
    attendance.bus_in_time = datetime.now().time()
    db.session.commit()
    flash('Bus Check-In Successful!', 'success')
    return redirect(url_for('student_dashboard'))

# Route for bus check-out
@app.route('/check_out_bus', methods=['POST'])
def check_out_bus():
    student_id = session['student_id']
    date = datetime.now().date()

    attendance = Attendance.query.filter_by(student_id=student_id, date=date).first()
    if attendance:
        attendance.bus_out_time = datetime.now().time()
        db.session.commit()
        flash('Bus Check-Out Successful!', 'success')
    else:
        flash('Error: No bus check-in found for today.', 'danger')

    return redirect(url_for('student_dashboard'))

# Route for campus check-in
@app.route('/check_in_campus', methods=['POST'])
def check_in_campus():
    student_id = session['student_id']
    date = datetime.now().date()

    attendance = Attendance.query.filter_by(student_id=student_id, date=date).first()
    if not attendance:
        attendance = Attendance(student_id=student_id, date=date, status='Present')
        db.session.add(attendance)
    
    campus_in_time = datetime.now().time()
    attendance.campus_in = campus_in_time  # Update the campus check-in time

    # Determine campus check-in status
    if campus_in_time > CAMPUS_CHECK_IN_TIME:
        attendance.campus_check_in_status = "Late"
    elif campus_in_time < (datetime.combine(date, CAMPUS_CHECK_IN_TIME) - timedelta(minutes=10)).time():
        attendance.campus_check_in_status = "Early"
    else:
        attendance.campus_check_in_status = "On time"
    
    
    attendance.campus_in_time = datetime.now().time()
    db.session.commit()
    flash('Campus Check-In Successful!', 'success')
    return redirect(url_for('student_dashboard'))

# Route for campus check-out
@app.route('/check_out_campus', methods=['POST'])
def check_out_campus():
    student_id = session['student_id']
    date = datetime.now().date()

    attendance = Attendance.query.filter_by(student_id=student_id, date=date).first()
    if attendance:
        attendance.campus_out_time = datetime.now().time()
        db.session.commit()
        flash('Campus Check-Out Successful!', 'success')
    else:
        flash('Error: No campus check-in found for today.', 'danger')

    return redirect(url_for('student_dashboard'))

def get_attendance_records():
    return Attendance.query.all()
# Route to view attendance history
@app.route('/view_attendance', methods=['GET', 'POST'])
def view_attendance():
    if 'student_id' in session and session['role'] == 'student':
        student_id = session['student_id']  # Get the student ID from the session
        attendance_records = Attendance.query.filter_by(student_id=student_id).all()  # Fetch records for the student
        attendance_records = []
    
        if request.method == 'POST':
            selected_date = request.form.get('date')
            if selected_date:
            # Convert the string date to a date object
                selected_date = datetime.strptime(selected_date, "%Y-%m-%d").date()
                attendance_records = Attendance.query.filter_by(date=selected_date).all()
            else:
            # Default to show all attendance records or handle accordingly
                 attendance_records = Attendance.query.all()
        else:
        # Default case for GET requests
            attendance_records = Attendance.query.all()
        # Print the records for debugging (optional)
        for record in attendance_records:
            print(record)
        
        return render_template('view_attendance.html', attendance_records=attendance_records)
    else:
        flash("You must be logged in as a student to view this page.", 'danger')
        return redirect(url_for('login'))


@app.route('/admin_dashboard')
def admin_dashboard():
    if 'username' in session and session['role'] == 'admin':
        return render_template('admin_dashboard.html')
    else:
        flash("You must be logged in as an Admin to view this page.", 'danger')
        return redirect(url_for('login'))

@app.route('/parent_dashboard')
def parent_dashboard():
    if 'user_id' in session and session['role'] == 'parent':
        parent_id = session['user_id']  # Get the parent ID from session (user_id is used)
        
        # Fetch all students linked to this parent
        students = Student.query.filter_by(parent_id=parent_id).all()  
        
        # Render the parent dashboard with the list of students
        return render_template('parent_dashboard.html', students=students)
    else:
        flash("You must be logged in as a Parent to view this page.", 'danger')
        return redirect(url_for('login'))
    
@app.route('/view_student_attendance', methods=['GET', 'POST'])
def view_student_attendance():
    attendance_records = []
    
    if request.method == 'POST':
        selected_date = request.form.get('date')
        if selected_date:
            # Convert the string date to a date object
            selected_date = datetime.strptime(selected_date, "%Y-%m-%d").date()
            attendance_records = Attendance.query.filter_by(date=selected_date).all()
        else:
            # Default to show all attendance records or handle accordingly
            attendance_records = Attendance.query.all()
    else:
        # Default case for GET requests
        attendance_records = Attendance.query.all()
        
    student_id = request.form.get('student_id')  # Get the selected student ID from the form
    student = Student.query.get(student_id)  # Fetch the student using the ID
    if student:
        attendance_records = Attendance.query.filter_by(student_id=student_id).all()  # Fetch attendance records for the selected student
        return render_template('view_attendance.html', attendance_records=attendance_records, student=student)
    else:
        flash('Student not found!', 'error')
        return redirect(url_for('parent_dashboard')) 
    
@app.route('/view_attendance_reports')
def view_attendance_reports():
    attendance_records = []
    
    if request.method == 'POST':
        selected_date = request.form.get('date')
        if selected_date:
            # Convert the string date to a date object
            selected_date = datetime.strptime(selected_date, "%Y-%m-%d").date()
            attendance_records = Attendance.query.filter_by(date=selected_date).all()
        else:
            # Default to show all attendance records or handle accordingly
            attendance_records = Attendance.query.all()
    else:
        # Default case for GET requests
        attendance_records = Attendance.query.all()
    return render_template('attendance_reports.html', attendance_records=attendance_records)

@app.route('/view_sent_alerts')
def view_sent_alerts():
    if 'user_id' in session and session['role'] == 'parent':
        parent_id = session['user_id']
        sent_alerts = Alert.query.filter_by(parent_id=parent_id).all()  # Fetch alerts sent to this parent
        return render_template('view_sent_alerts.html',  sent_alerts=sent_alerts)
    else:
        flash('You need to log in as a Parent to view alerts.', 'danger')
        return redirect(url_for('login'))
        
    
@app.route('/school_authority_dashboard')
def school_authority_dashboard():
    if 'username' in session and session['role'] == 'school_authority':
        # Example of School Authority viewing all students
        students = Student.query.all()
        return render_template('school_authority_dashboard.html', students=students)
    else:
        flash("Unauthorized access. Please log in.", 'danger')
        return redirect(url_for('login'))

@app.route('/student_dashboard')
def student_dashboard():
    if 'student_id' in session and session['role'] == 'student':
        student_id = session['student_id']
        student = Student.query.get(student_id)  # Fetch the student from the database
        return render_template('student_dashboard.html', student=student)
    else:
        flash("You must be logged in as a Student to view this page.", 'danger')
        return redirect(url_for('login'))

@app.route('/attendance_reports', methods=['GET', 'POST'])
def attendance_reports():
    attendance_records = []
    
    if request.method == 'POST':
        selected_date = request.form.get('date')
        if selected_date:
            # Convert the string date to a date object
            selected_date = datetime.strptime(selected_date, "%Y-%m-%d").date()
            attendance_records = Attendance.query.filter_by(date=selected_date).all()
        else:
            # Default to show all attendance records or handle accordingly
            attendance_records = Attendance.query.all()
    else:
        # Default case for GET requests
        attendance_records = Attendance.query.all()
        
    
    return render_template('attendance_reports.html', attendance_records=attendance_records)



@app.route('/send_alert', methods=['POST'])
def send_alert():
    student_id = request.form['student_id']
    parent_id = request.form['parent_id']

    # Fetch the student and determine the attendance record
    student = Student.query.get(student_id)
    attendance = Attendance.query.filter_by(student_id=student_id).first()

    # Ensure that attendance record exists
    if attendance:
        status_message = f"Alert: {student.name} {student.surname} is marked as {attendance.status}."
        
        # Create an alert in the database
        alert = Alert(parent_id=parent_id, message=status_message)

        try:
            db.session.add(alert)
            db.session.commit()
            print("Alert saved successfully:", alert)
            flash('Alert sent successfully!', 'success')
        except Exception as e:
            db.session.rollback()  # Roll back on error
            flash(f'Error sending alert: {str(e)}', 'danger')
    else:
        flash('No attendance record found for this student.', 'danger')

    return redirect(url_for('view_attendance_reports'))


@app.route('/mark_attendance', methods=['POST'])
def mark_attendance():
    student_id = session['student_id']
    status = request.form.get('status')
    date = datetime.now().date()

    # Fetch or create an attendance record for today
    attendance = Attendance.query.filter_by(student_id=student_id, date=date).first()
    if not attendance:
        attendance = Attendance(student_id=student_id, date=date, status=status)
        db.session.add(attendance)
    else:
        # Update status if record already exists
        attendance.status = status
    
    db.session.commit()
    flash('Attendance marked successfully!', 'success')
    return redirect(url_for('student_dashboard'))

# Route to delete a student
@app.route('/remove_student/<int:student_id>', methods=['POST'])
def remove_student(student_id):
    if 'user_id' not in session or session['role'] != 'parent':
        flash('You need to log in as a Parent to delete a student.', 'danger')
        return redirect(url_for('login'))

    parent_id = session['user_id']
    
    # Fetch the student and check if the parent owns the student
    student = Student.query.filter_by(id=student_id, parent_id=parent_id).first()
    
    if not student:
        flash('Error: Student not found or you are not authorized to delete this student.', 'danger')
        return redirect(url_for('parent_dashboard'))

    try:
        # Delete the student
        db.session.delete(student)
        db.session.commit()
        flash(f'Student {student.name} {student.surname} deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting student: {str(e)}', 'danger')

    return redirect(url_for('parent_dashboard'))


@app.route('/logout')
def logout():
    # Clear the session data
    session.clear()  # This will log out the user
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))



if __name__ == '__main__':
    app.run(debug=True)
