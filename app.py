from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, FloatField
from wtforms.validators import InputRequired, Length, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisisasecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=60)])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username is already taken.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=60)])
    submit = SubmitField('Login')

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            session['user_id'] = user.id
            flash('Login successful', 'success')
            return redirect(url_for('form'))
        else:
            flash('Login unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', form=form)
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))
@app.route('/form', methods=['GET', 'POST'])
def form():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        entry = {
            "clinic_name": request.form.get("clinic_name"),
            "practitioner_id": request.form.get("practitioner_id"),
            "doctor_name": request.form.get("doctor_name"),
            "degree": request.form.get("degree"),
            "contract_type": request.form.get("contract_type"),
            "first_visit": request.form.get("first_visit"),
            "follow_up": request.form.get("follow_up"),
            "work_hours": request.form.get("work_hours"),
            "utilization": request.form.get("utilization"),
            "total_visits": request.form.get("total_visits"),
            "total_fee": request.form.get("total_fee"),
            "lab_referrals": request.form.get("lab_referrals"),
            "lab_procedures": request.form.get("lab_procedures"),
            "lab_cost": request.form.get("lab_cost"),
            "radiology_referrals": request.form.get("radiology_referrals"),
            "radiology_procedures": request.form.get("radiology_procedures"),
            "radiology_cost": request.form.get("radiology_cost"),
            "pharmacy_referrals": request.form.get("pharmacy_referrals"),
            "pharmacy_cost": request.form.get("pharmacy_cost"),
            "approval_pharmacy_referrals": request.form.get("approval_pharmacy_referrals"),
            "approval_pharmacy_cost": request.form.get("approval_pharmacy_cost"),
            "services": request.form.get("services"),
            "total_achieved": request.form.get("total_achieved")
        }
        # Save the entry to a file or a database here
        # For demonstration, we will just flash a success message
        flash('Entry added successfully', 'success')
        return redirect(url_for('form'))
    return render_template('form.html')

@app.route('/entries')
def display_entries():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Here you would load the entries from a database or a file
    # For demonstration, we will use a static list
    entries = [
        {
            "clinic_name": "Clinic 1",
            "practitioner_id": "123",
            "doctor_name": "Dr. A",
            "degree": "MBBS",
            "contract_type": "Full-Time",
            "first_visit": "Yes",
            "follow_up": "No",
            "work_hours": 40,
            "utilization": 75.0,
            "total_visits": 100,
            "total_fee": 5000.0,
            "lab_referrals": 10,
            "lab_procedures": 5,
            "lab_cost": 1000.0,
            "radiology_referrals": 7,
            "radiology_procedures": 3,
            "radiology_cost": 1500.0,
            "pharmacy_referrals": 20,
            "pharmacy_cost": 2000.0,
            "approval_pharmacy_referrals": 15,
            "approval_pharmacy_cost": 3000.0,
            "services": "Service 1",
            "total_achieved": 8000.0
        }
    ]
    return render_template('display.html', entries=entries)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
