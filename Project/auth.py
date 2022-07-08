from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash


auth = Blueprint('auth', __name__)
 
@auth.route('/login', methods=['GET', 'POST'])
def login():
    data = request.form
    print(data)
    return render_template('login.html', text='Testing', user='Udoy', bul=True)


@auth.route('/logout')
def logout():
    return render_template('logout.html')


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        FirstName = request.form.get('FirstName')
        Email = request.form.get('Email')
        Password1 = request.form.get('Password1')
        Password2 = request.form.get('Password2')

        if len(Email) < 4:
            flash('Email must be greater than 4 characters.', category='error')
        elif len(FirstName) < 4:
            flash('First Name must be greater than 4 characters.', category='error')
        elif Password1 != Password2:
            flash('Password Don\'t match', category='error')
        elif len(Password1) < 8:
            flash('Password must be at least 8 characters', category='error')
        else:
            new_user = User(email=Email, FirstName=FirstName, password=generate_password_hash(Password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            flash('Account Created!', category='success')
            return redirect(url_for('views.home'))

    return render_template('sign_up.html')