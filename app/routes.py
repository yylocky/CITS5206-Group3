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
from openpyxl import load_workbook

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


# Upload function, including validate file type - MW
ALLOWED_EXTENSIONS = {'xlsx', 'xls', 'csv', 'tsv'} # MW
@app.route("/upload", methods=["POST"])
def upload_file():
    file = request.files["file"]
    print(file)

    file_extension = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else '' # MW
    
    if file_extension not in ALLOWED_EXTENSIONS: #MW
        return "Invalid file type. Please upload a valid Excel file." #MW

    if file.filename != "":

        #validate the spreadsheet
        workbook = load_workbook(file)
        sheet = workbook.active
        data = sheet.values
        data = list(data)
        headings = data[0] # Assuming the headings are in the first row
        print (headings) # test
        print (type(headings))
        expected_headings = ('Staff ID', 'Task Type', 'UnitCode', 'Department', 'Comment', 'Role', 'WorkloadHours', 'Explanation')
        print (type(expected_headings))
        missing_headings = [heading for heading in expected_headings if heading not in headings]
        print (missing_headings)

        if missing_headings:
            return "This may not be the right spreadsheet as it does not pass the content validation."
        else:
            # insert DB
            try:
                df = pd.read_excel(file)
                print("Uploaded Data:")
                print(df)

                for index, row in df.iterrows():
                    print(f"Row {index + 1}:")
                    print("Code:", row["Staff ID"])
                    print("Task Type:", row["Task Type"])
                    print("Title:", row["UnitCode"])
                    print("Dept:", row["Department"])

                    print("Comment:", row["Comment"])
                    print("Staff:", row["Role"])
                    print("WkldHours:", row["WorkloadHours"])

                    print("-" * 20)

                    k_work_id = row["Staff ID"]
                    k_username = k_work_id
                    k_hours_allocated = row["WorkloadHours"]
                    k_workload_point = 0.5
                    k_comment = row["Comment"]
                    k_comment_status = 'Unread'
                    k_taskType = row["Task Type"]
                    k_unit_code = row["UnitCode"]

                    explanation = ""

                    department_name = row["Department"]
                    k_depart = Department.query.filter_by(dept_name=department_name).first()
                    if k_depart:
                        k_dept_id = k_depart.dept_id+1
                    else:
                        k_dept_id = random.randint(1,10000)
                    
                    role_name = row["Role"]
                    k_role = Role.query.filter_by(role_name=role_name).first()
                
                    if k_role:
                        k_role_id = k_role.role_id+1
                    else:
                        k_role_id = random.randint(1,10000)


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
                    # k_work_explanation = "Some explanation for " + k_taskType
                    if k_taskType == 'ADMIN':
                        explanation = role_name + "in" + k_unit_code
                    if k_taskType == 'CWS':
                        explanation = "cwk proj sup of" + k_work_id + "in" + k_unit_code
                    if k_taskType == "GA":
                        explanation = role_name + "in" + k_unit_code
                    if k_taskType == 'HDR':
                        explanation = "HDR sup of" + k_work_id
                    if k_taskType == 'NEMP':
                        explanation = role_name + "in" + k_unit_code
                    if k_taskType == 'CWS':
                        explanation = "cwk proj sup of" + k_work_id + "in" + k_unit_code
                    if k_taskType == 'RESERV':
                        explanation = "cwk proj sup of" + k_work_id + "in" + k_unit_code
                    if k_taskType == 'RES - MGMT':
                        explanation = "cwk proj sup of" + k_work_id + "in" + k_unit_code
                    if k_taskType == 'SDS':
                        explanation = role_name + "in" + k_unit_code
                    if k_taskType == 'TEACH':
                        explanation = role_name + "in" + k_unit_code
                    if k_taskType == 'UDEV':
                        explanation = role_name + "in" + k_unit_code
                    if k_taskType == 'LSL':
                        explanation = role_name + "in" + k_unit_code
                    if k_taskType == 'PL':
                        explanation = role_name + "in" + k_unit_code
                    if k_taskType == 'SBL':
                        explanation = role_name + "in" + k_unit_code

                    k_work = Work(
                        # work_id=k_work_id,
                        work_explanation=explanation,
                        work_type=k_taskType,
                        dept_id=k_dept_id,
                        unit_code=k_unit_code
                    )
                    #
                    db.session.add(k_work)
                    db.session.commit()

                    # user


                    k_user = User(
                        # username=random.randint(0, 100000),
                        username = k_username,
                        role_id=k_role_id,
                        # alloc_id=random.randint(0, 120),
                        leave_hours=float(0),
                        contract_hour=0,
                        available_hours=0,
                        dept_id=k_dept_id
                    )

                    db.session.add(k_user)
                    db.session.commit()

                return "File uploaded and data stored as TaskData objects successfully."
            except Exception as e:
                return f"Error: {str(e)}"
    return "No file selected for upload."

if __name__ == '__main__':
    app.run(debug=True)
