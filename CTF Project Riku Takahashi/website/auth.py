from flask import Blueprint, render_template, request, flash, redirect, url_for, make_response
from .models import User, Note
from .models import User, Note
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
import hashlib
import base64

auth = Blueprint('auth', __name__)
admin = Blueprint('admin', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')

    return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


#Sing-up page is hidden on the website but you can access through "/sing-up"
@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Passwords must be at least 7 characters.', category='error')
        else:
            #Hash password with MD5
            hashed_password = hashlib.md5(password1.encode()).hexdigest()
            encoded_password = base64.b64encode(password1.encode()).decode()
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(password1, method='pbkdf2:sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))


    return render_template("sign_up.html", user=current_user)



#robots.txt files--------------------------------------------------------------------------------------------------------------------------

@auth.route('/robots.txt')
def robots_txt(): 
    return render_template('robots.txt.html')

@auth.route('/8028f') #Fake page
def trap():
    return render_template('/8028f.html')


@auth.route('user-bin') #Base64 page
def user_bin():
    return render_template('user-bin.html')

@auth.route('/top-secretfile') #Cat picture
def top_secretfile():
    return render_template('cat.html')

@auth.route('/mydog') #Dog picture
def hi():
    return render_template('dog.html')

@auth.route('/wp-email/') #Target email adress
def user_answer(): 
    return render_template('target-email.html')

@auth.route('/db_connect/secret_db_access.log') #Fake database 
def show_data():
    return render_template('database.html')



@auth.route('/db_connect', methods=['GET', 'POST'])
def enter_keyword():
    if request.method == 'POST':
        keyword = request.form.get('keyword')

        if keyword == 'admin9rt':
            return redirect(url_for('auth.command_line'))  # Redirect to /secretfile.txt
        else:
            flash('Incorrect keyword. Try again.', category='error')
    
    return render_template('enter_keyword.html')  # Create a template with a form to enter the keyword

@auth.route('/command-line')
def command_line():
    return render_template('command_line.html')



#Tutorials--------------------------------------------------------------------------------------------------------------------------------------

@auth.route('/tutorial')
def tutorial():
     return render_template("tutorial.html")

@auth.route('/tutorial/step1')
def step1():
    return render_template('step1.html')

@auth.route('/tutorial/step2')
def step2():
    return render_template('step2.html')

@auth.route('/tutorial/step3')
def step3():
    return render_template('step3.html')

@auth.route('tutorial/step4')
def step4():
    return render_template('step4.html')

@auth.route('tutorial/step5')
def step5():
    return render_template('step5.html')
#Database-------------------------------------------------------------------------------------------------------------------------------------------
@auth.route('/adminonly') #Actual database
def view_data():
    users = User.query.all()

    notes = Note.query.all()

    data = {
        "users": [{"id": user.id, "email": user.email, "first_name": user.first_name, "password": user.password} for user in users]}
        # "notes": [{"id": note.id, "data": note.data, "date": note.date, "user_id": note.user_id} for note in notes],
    return render_template("view_data.html", data=data)

    