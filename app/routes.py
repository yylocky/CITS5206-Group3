from flask import render_template, request, redirect, url_for, flash, jsonify, current_app, session
from flask_login import current_user, login_user, logout_user, login_required
from app import app, db, forms
from app.models import Login
from app.models import WorkloadAllocation
from app.models import User,Department,Role,Work
from app.forms import LoginForm, SignupForm
from werkzeug.urls import url_parse
import pandas as pd
import re
import random

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
    return render_template('edit_allocation_detail.html', title='Edit Allocation Detail')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', title='Dashboard')



@app.route("/upload", methods=["POST"])
def upload_file():
    file = request.files["file"]

    if file.filename != "":
        try:
            df = pd.read_excel(file)
            print("Uploaded Data:")
            print(df)

            for index, row in df.iterrows():
                print(f"Row {index + 1}:")
                print("Code:", row["Code"])
                print("Title:", row["Title"])
                print("Dept:", row["Dept"])
                print("Task Type:", row["Task Type"])
                print("Commments:", row["Commments"])
                print("Staff:", row["Staff"])
                print("WkldHours:", row["WkldHours"])
                print("-" * 20)

                k_work_id = row["Staff"]
                k_username = k_work_id
                k_hours_allocated = row["WkldHours"]
                k_workload_point = 0.5
                k_comment = row["Commments"]
                k_comment_status = 'Unread'
                k_taskType = row["Task Type"]
                k_unit_code = row["Code"]

                k_department = row["Dept"]
                k_depart = Department.query.filter_by(dept_name=k_department).first()
                k_dept_id = k_depart.dept_id
                print(k_dept_id)

                role_name = "Staff"
                k_role = Role.query.filter_by(role_name=role_name).first()
                k_role_id = k_role.role_id
                print(k_role_id)

                # #workload
                k_workload_allocation = WorkloadAllocation(
                    work_id=str(k_work_id),
                    hours_allocated=float(k_hours_allocated),
                    username=str(k_username),
                    comment=k_comment,
                    comment_status=k_comment_status,
                    workload_point=float(k_workload_point)
                )

                db.session.add(k_workload_allocation)
                db.session.commit()

                # #work
                k_work_explanation = "Some explanation for " + k_taskType
                k_work = Work(
                    work_id=k_work_id,
                    work_explanation=k_work_explanation,
                    work_type=k_taskType,
                    dept_id=int(k_dept_id),
                    unit_code=k_unit_code
                )
                #
                db.session.add(k_work)
                db.session.commit()

                # user
                k_contract_hour = float(k_workload_point) / float(k_hours_allocated)

                k_user = User(
                    username=k_username,
                    role_id=int(k_role_id),
                    leave_hours=float(0),
                    contract_hour=float(k_contract_hour),
                    available_hours=float(k_contract_hour),
                    dept_id=int(k_dept_id)
                )

                db.session.add(k_user)
                db.session.commit()

            return "File uploaded and data stored as TaskData objects successfully."
        except Exception as e:
            return f"Error: {str(e)}"

    return "No file selected for upload."
if __name__ == '__main__':
    app.run(debug=True)
