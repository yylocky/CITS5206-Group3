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

# decorator for login page


@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid Username or Password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('login')
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


@app.route('/assign_workload')
@login_required
def assign():
    return render_template('assign_workload.html', title='Assign Workload')



@app.route('/edit_allocation_detail')
@login_required
def edit_allocation_detail():

    # Connect to the database
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()

    # Query to fetch data from the database
    cursor.execute("SELECT dept_id FROM Departmentss")
    DEPTS = [row[0] for row in cursor.fetchall()]

    cursor.execute("SELECT work_type FROM WorkloadAllocations")
    TASK_TYPES = [row[0] for row in cursor.fetchall()]

    cursor.execute("SELECT work_type FROM WorkloadAllocations")
    TASK_TYPES = [row[0] for row in cursor.fetchall()]

    cursor.execute("SELECT user_id FROM Users")
    USERIDS = [row[0] for row in cursor.fetchall()]

    # Close the database connection
    conn.close()   



    # validate submission
    alloc_id = request.form.get("alloc_id")
    dept_id = request.form.get("dept_id")
    task_type = request.form.get("task_type")
    task_name = request.form.het("task_name")
    user_id = request.form.get("user_id")
    assgn_hour = request.form.get("assgn_hour")

    if user_id not in USERIDS or dept_id not in DEPTS or task_type not in TASK_TYPES:
            return render_template ("assgn_fail.html") # need to add a failure page

    #insert assignment info
    db.execute("INSERT INFO WorkloadAllocations (alloc_id, dept_id, task_type, task_name, user_id, hours_allocated) VALUES (?, ?, ?, ?, ?, ?)", alloc_id, dept_id, task_type, task_name, user_id, assgn_hour )


    return render_template('edit_allocation_detail.html', title='Edit Allocation Detail')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', title='Dashboard')



if __name__ == '__main__':
    app.run(debug=True)
