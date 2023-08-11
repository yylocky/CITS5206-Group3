from flask import render_template, request, redirect, url_for, flash, jsonify, current_app, session
from flask_login import current_user, login_user, logout_user, login_required
from app import app, db, forms
from app.models import User
from app.forms import LoginForm, SignupForm
from datetime import datetime
from werkzeug.urls import url_parse
import re
import pytz
import random

timezone = pytz.timezone("Australia/Perth")
now = datetime.now(timezone)

# decorator for homepage


@app.route('/')
@app.route('/homepage')
def homepage():
    return render_template('homepage.html', title='Home')

# decorator for login page


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid Username or Password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('homepage')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)

# decorator for logout page


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('homepage'))

# decorator for signup page


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        flash('You are already logged in!')
        return redirect(url_for('homepage'))
    form = SignupForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations! You are now a registered user. Log in to start chatting!', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', title='Sign Up', form=form)

# decorator for assign page


@app.route('/assign')
def assign():
    return render_template('assign.html', title='Assign Workload')


if __name__ == '__main__':
    app.run(debug=True)
