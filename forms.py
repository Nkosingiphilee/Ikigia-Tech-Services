from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, PasswordField, SubmitField,TelField
from wtforms.validators import DataRequired,Email,Length

class LoginForm(FlaskForm):
    role = SelectField('Select Role', choices=[
        ('student', 'Student'),
        ('parent', 'Parent'),
        ('admin', 'Admin'),
        ('school_authority', 'School Authority')
    ], validators=[DataRequired()])
    
    name = StringField('Name')  # Only shown if role is 'student'
    username = StringField('Username', validators=[DataRequired(),Length(min=2,max=20)])  # Shown for other roles
    password = PasswordField('Password', validators=[DataRequired(),Length(min=2,max=60)])
    submit = SubmitField('Login')


class RegistrationForm(FlaskForm):
    role = SelectField('Select Role', choices=[
        ('parent', 'Parent'),
        ('admin', 'Admin'),
        # Add more roles if needed
    ], validators=[DataRequired()])
    
    username = StringField('Username', validators=[DataRequired(),Length(min=2,max=20)])
    email = StringField('Email', validators=[DataRequired(), Email(),Length(min=2,max=20)])
    password = PasswordField('Password', validators=[DataRequired(),Length(min=2,max=60)])
    first_name = StringField('First Name', validators=[DataRequired(),Length(min=2,max=20)])
    last_name = StringField('Last Name', validators=[DataRequired(),Length(min=2,max=20)])
    phone_number = TelField('Phone Number', validators=[DataRequired(),Length(min=10,max=13)])
    submit = SubmitField('Register')

class RegisterSchoolAuthorityForm(FlaskForm):
    username = StringField('Authority Username', validators=[DataRequired(),Length(min=2,max=20)], render_kw={"placeholder": "Enter Authority Username"})
    email = StringField('Authority Email', validators=[DataRequired(), Email(),Length(min=2,max=60)], render_kw={"placeholder": "Enter Authority Email"})
    password = PasswordField('Password', validators=[DataRequired(),Length(min=2,max=60)], render_kw={"placeholder": "Enter Password"})
    first_name = StringField('Authority First Name', validators=[DataRequired(),Length(min=2,max=30)], render_kw={"placeholder": "Enter Authority First Name"})
    last_name = StringField('Authority Last Name', validators=[DataRequired(),Length(min=2,max=30)], render_kw={"placeholder": "Enter Authority Last Name"})
    submit = SubmitField('Register Authority')
