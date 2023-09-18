from flask import render_template, request, redirect, url_for, flash, jsonify, current_app, session
from flask_login import current_user, login_user, logout_user, login_required
from app import app, db, forms
from app.models import Login, User, Role, WorkloadAllocation
from app.forms import LoginForm, SignupForm
from werkzeug.urls import url_parse
from werkzeug.utils import secure_filename
import re
import os
import random
from flask import session



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

# Definitions for file type validation - MW
ALLOWED_EXTENSIONS = {'xlsx', 'xls', 'csv', 'tsv'}
# Check if filename has "." and whether the extension is in the allow extensions list. - MW
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# decorator for assign_workload page
@app.route('/assign_workload', methods=['POST'])
@login_required
def assign():
    return render_template('assign_workload.html', title='Assign Workload')
# validation for upload file type at the backend - MW
def upload():
    file = request.files['file']

    if file.filename == '':
        # return render_template('assign_workload.html', message='No selected file')
        flash('No file selected.')
        return redirect(url_for('upload'))
    
    if not allowed_file(file.filename):
        flash('Invalid file type. Only Excel, CSV or TSV files allowed.') # cant remove csv or tsv or even xls if it is too hard. Or we can just limit this to xlsx. but the save function will convert his to xlsx
        return redirect(url_for('upload'))

    if file:
        # Save the uploaded file temporarily for further processing
        temp_filepath = '/tmp/uploaded_spreadsheet.xlsx'
        file.save(temp_filepath)

    # Changwu, for your consideration, i have imported WorkloadAllocation from models.py
        # Read and process the spreadsheet (e.g., using pandas)
        #import pandas as pd
        #df = pd.read_excel(temp_filepath)

        # Database update logic (e.g., using SQLAlchemy)
        #from sqlalchemy import create_engine
        #engine = create_engine('sqlite:///your_database.db')
        #df.to_sql('your_table_name', engine, if_exists='replace', index=False)

        #return render_template('assign_workload.html', message='Upload and database update successful')



# 20230918 MW: Remove as no longer required
# @app.route('/edit_allocation_detail')
#def edit_allocation_detail():
#    role_name = get_session()
#    return render_template('edit_allocation_detail.html', title='Edit Allocation Detail', role_name=role_name)




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
