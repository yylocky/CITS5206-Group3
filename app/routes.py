from flask import render_template, request, redirect, url_for, flash, jsonify, current_app, session
from flask_login import current_user, login_user, logout_user, login_required
from app import app, db, forms, spreadsheets
from app.models import Login, User, Role, WorkloadAllocation
from app.forms import LoginForm, SignupForm
from werkzeug.urls import url_parse
import re
import os
import random
from flask import session
import pandas as pd


# decorator for login page


@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = Login.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid Username or Password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('login')
        set_session(user)
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)

# decorator for logout page
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

# decorator for view_workload page
@app.route('/view_workload')
@login_required
def view_workload():
    # users=User.query.all() # Just using user table for mockup
    return render_template('view_workload.html', title='View Workload')#, users=users)

# decorator for assign_workload page
@app.route('/assign_workload', methods=['GET', 'POST'])
@login_required
def assign():
    return render_template('assign_workload.html', title='Assign Workload')

# for spreadsheet upload form
@app.route('/handleForm2', methods=['POST'])
def handle_form2():
    # Logic to handle form 2 data (file upload)
    file = request.files['spreadsheet']
    
    if file:
        print('file is ok')
        #data = pd.read_excel(file)
        # data.to_sql(name='table_name', con=engine, if_exists='append', index=False)
    return "File uploaded and data inserted to database"

# def upload_file():
#     if request.method == 'POST':
#         if 'file' not in request.files:
#             flash('No file part')
#             return redirect(request.url)
#         file = request.files['file']
#         if file.filename == '':
#             flash('No selected file')
#             return redirect(request.url)
#         if file and allowed_file(file.filename):
#             filename = secure_filename(file.filename)
#             file.save(os.path.join('uploads', filename))
#             flash('File uploaded successfully')
#             return redirect(url_for('uploads.upload_file'))
#         else:
#             flash('Invalid file type. Allowed file types are: .xlsx')
#     return render_template('upload.html')

def set_session(user):
    user_info = User.query.filter_by(username=user.username).first()
    if user_info is None:
        flash('Invalid Username or Password')
        return redirect(url_for('login'))
    role = Role.query.filter_by(role_id=user_info.role_id).first()
    session['role_id'] = role.role_id
    session['role_name'] = role.role_name


def get_session():
    role_name = session.get('role_name', '')
    return role_name


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', title='Dashboard')



if __name__ == '__main__':
    app.run(debug=True)
