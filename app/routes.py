from flask import render_template, request, redirect, url_for, flash, jsonify, current_app, session
from flask_login import current_user, login_user, logout_user, login_required
from app import app, db, forms
from app.models import Login
from app.models import WorkloadAllocation
from app.models import User,Department,Role,Work
from app.models import Login, User, WorkloadAllocation, Role, Work
from app.forms import LoginForm, SignupForm
from werkzeug.urls import url_parse
import pandas as pd
import re
import random
from openpyxl import load_workbook
from flask import g


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

# decorator for filtered view_workload page from notification
@app.route('/view_workload')
@login_required
def view_workload():
    # Check if the alloc_id is present in the request's query parameters
    alloc_id = request.args.get('alloc_id')

    if alloc_id:
        # Fetch workload entries with the specified alloc_id
        workloads = WorkloadAllocation.query.filter_by(
            alloc_id=alloc_id).all()
    else:
        # If no alloc_id is specified (i.e. accessed from nav bar), fetch all workload entries
        workloads = WorkloadAllocation.query.all()

    return render_template('view_workload.html', title='View Workload', workloads=workloads)

# decorator for view all workload page
@app.route('/view_all_workload')
@login_required
def view_all_workload():
    role_id = current_user.user.role_id
    # if current user is admin(4) or hod(1), show all workload
    if role_id == 4 or role_id == 1:
        workloads = WorkloadAllocation.query.all()

    # if current user is HoD(2), show only their department workload
    elif role_id == 2:
        workloads = WorkloadAllocation.query.join(Work, Work.work_id == WorkloadAllocation.work_id).filter(Work.dept_id == current_user.user.dept_id).all()

    # if current user is staff(3), show only their workload
    elif role_id == 3:
        workloads = WorkloadAllocation.query.filter_by(username=current_user.username).all()

    return render_template('view_all_workload.html', title='View All Workload', workloads=workloads)

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
@login_required
def upload_file():
    file = request.files["file"]
    file_extension = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else '' # MW
    
    if file_extension not in ALLOWED_EXTENSIONS: #MW
        # return "Invalid file type. Please upload a valid Excel file." #MW
        flash('Invalid file type, please upload again') #MW
        return redirect(url_for('assign')) #mw
    
    if file.filename != "":
        #validate the spreadsheet
        workbook = load_workbook(file)
        sheet = workbook.active
        sheet_title = sheet.title
        print(sheet_title) #testing
        #data = sheet.values
        #data = list(data)
        #headings = data[0] # Assuming the headings are in the first row
        #expected_headings = ('Staff ID', 'Task Type', 'UnitCode', 'Department', 'Comment', 'Role', 'WorkloadHours', 'leave_hours')

        if sheet_title != "UWA_WLAM":
            # return "This may not be the right spreadsheet as it does not pass the content validation."
            flash('Invalid spreedsheet, please upload again')
            return redirect(url_for('assign'))
        
        else:
            # insert DB

            try:
                df = pd.read_excel(file)
                print("Uploaded Data:")
                print(df)

                for index, row in df.iterrows():
                    print(f"Row {index + 1}:")
                    print("Code:", row["Staff ID"])
                    print("Teach Type:", row["Teach type"])
                    print("Title:", row["UnitCode"])
                    print("Dept:", row["Department"])
                    #print("Comment:", row["Comment"])
                    print("Staff:", row["Role"])
                    print("Wkldhours:", row["Wkldhours"])
                    print("Admin Type of Role:", row["Admin Type of Role"])
                    print("Admin Hours:", row["Admin Hours"])
                    print("Leave Type:", row["Leave Type"])
                    print("Leave days", row["Leave days"])
                    print("RM Hours", row["RM Hours"])
                    print("CWS Hours", row["CWS Hours"])
                    print("RM Justification", row["RM Justification"])

                    print("-" * 20)

                    
                    #Work allocation
                    k_work_id = row["Staff ID"]
                    k_username = k_work_id
                    k_hours_allocated = row["Wkldhours"]
                    k_workload_point = 0.5
                    #k_comment = row["Comment"]
                    #k_comment_status = 'Unread'
                    k_taskType = row["Teach type"]
                    k_unit_code = row["UnitCode"]
                    #k_leave_hours = row['leave_hours']

                    explanation = ""

                    department_name = row["Department"]
                    k_dept_id = Department.query.filter_by(dept_name=department_name).first().dept_id
                    
                    
                    role_name = row["Role"]
                    k_role_id = Role.query.filter_by(role_name=role_name).first().role_id

                    uu = User.query.filter_by(username=k_username).first()
                    k_workload_point = 1
                    if not uu or uu.contract_hour==0:
                        k_workload_point = 1.0
                    else:
                        k_contract_hour = uu.contract_hour
                        k_workload_point = float(k_hours_allocated/k_contract_hour)

                    k_work_id = Work.query.count() + 1
                    # workload
                    k_workload_allocation = WorkloadAllocation(
                        work_id=str(k_work_id),
                        hours_allocated=float(k_hours_allocated),
                        username=str(k_username),
                        # comment=k_comment,
                        # comment_status=k_comment_status,
                        workload_point= k_workload_point
                    )

                    db.session.add(k_workload_allocation)
                    db.session.commit()

                    # #work
                    # k_work_explanation = "Some explanation for " + k_taskType
                    if k_taskType == 'ADMIN':
                        explanation = role_name + " in " + k_unit_code
                    if k_taskType == 'CWS':
                        explanation = "cwk proj sup of " + k_work_id + " in " + k_unit_code
                    if k_taskType == "GA":
                        explanation = role_name + " in " + k_unit_code
                    if k_taskType == 'HDR':
                        explanation = "HDR sup of " + k_work_id
                    if k_taskType == 'NEMP':
                        explanation = role_name + " in " + k_unit_code
                    #if k_taskType == 'CWS':
                        #explanation = "cwk proj sup of " + k_work_id + " in " + k_unit_code
                    if k_taskType == 'RESERV':
                        explanation = "cwk proj sup of " + k_work_id + " in " + k_unit_code
                    # if k_taskType == 'RES - MGMT':
                        #explanation = "cwk proj sup of " + k_work_id + " in " + k_unit_code
                    if k_taskType == 'SDS':
                        explanation = role_name + " in " + k_unit_code
                    if k_taskType == 'TEACH':
                        explanation = role_name + " in " + k_unit_code
                    if k_taskType == 'UDEV':
                        explanation = role_name + " in " + k_unit_code

                    k_work = Work(
                        work_id=k_work_id,
                        work_explanation=explanation,
                        work_type=k_taskType,
                        dept_id=k_dept_id,
                        unit_code=k_unit_code
                    )
                    db.session.add(k_work)
                    db.session.commit()


                    # user
                    uu = User.query.filter_by(username=k_username).first()
                    if not uu:
                        k_user = User(
                            # username=random.randint(0, 100000),
                            username = k_username,
                            role_id=k_role_id,
                            # alloc_id=random.randint(0, 120),
                            #leave_hours=k_leave_hours,
                            dept_id=k_dept_id
                        )

                        db.session.add(k_user)
                        db.session.commit()
                    else:
                        user = User.query.filter_by(username=k_username).first()
                        user.role_id = k_role_id
                        #user.leave_hours=k_leave_hours
                        user.dept_id = k_dept_id

                        db.session.commit()

                    # # Admin
                    # k_work_id = Work.query.count() + 1
                    # k_username = row["Staff ID"]
                    # k_hours_allocated = row["Admin Hours"]
                    # k_taskType = 'ADMIN'
                    # explanation = row["Admin Type of Role"]

                    # # Insert allocation record
                    # k_workload_allocation = WorkloadAllocation(
                    #     work_id=str(k_work_id),
                    #     hours_allocated=float(k_hours_allocated),
                    #     username=str(k_username),
                    # )
                    # db.session.add(k_workload_allocation)
                    # db.session.commit()

                    # # Insert work record
                    # k_work = Work(
                    #     work_id=k_work_id,
                    #     work_explanation=explanation,
                    #     work_type=k_taskType,
                    #     #dept_id=k_dept_id,
                    #     #unit_code=k_unit_code
                    # )
                    # db.session.add(k_work)
                    # db.session.commit()                  

                    # # Leave
                    # k_work_id = Work.query.count() + 1
                    # k_username = row["Staff ID"]
                    # k_hours_allocated = row["Leave days"]
                    # k_taskType = row["Leave Type"]
                    # k_leave_hours = float(k_hours_allocated)*7.5
                    # if k_taskType == 'LSL':
                    #     explanation = k_username + 'on LSL'
                    # if k_taskType == 'PL':
                    #     explanation = k_username + 'on PL'
                    # if k_taskType == 'SBL':
                    #     explanation = k_username + 'on SBL'

                    # #Admin-insert work allocation record
                    # k_workload_allocation = WorkloadAllocation(
                    #     work_id=str(k_work_id),
                    #     hours_allocated=float(k_hours_allocated)*7.5,
                    #     username=str(k_username),
                    #     # comment=k_comment,
                    #     # comment_status=k_comment_status,
                    #     #workload_point= k_workload_point
                    # )
                    # db.session.add(k_workload_allocation)
                    # db.session.commit()

                    # # Admin - Insert work record
                    # k_work = Work(
                    #     work_id=k_work_id,
                    #     work_explanation=explanation,
                    #     work_type=k_taskType,
                    #     #dept_id=k_dept_id,
                    #     #unit_code=k_unit_code
                    # )
                    # db.session.add(k_work)
                    # db.session.commit()      

                    # # RM
                    # k_work_id = Work.query.count() + 1
                    # k_username = row["Staff ID"]
                    # k_hours_allocated = row["RM Hours"]
                    # k_taskType = 'RES - MGMT'
                    # explanation = row["RM Justification"]

                    # #RM - insert allocation record
                    # k_workload_allocation = WorkloadAllocation(
                    #     work_id=str(k_work_id),
                    #     hours_allocated=float(k_hours_allocated),
                    #     username=str(k_username),
                    # )
                    # db.session.add(k_workload_allocation)
                    # db.session.commit()
                    
                    # # RM - Insert work record
                    # k_work = Work(
                    #     work_id=k_work_id,
                    #     work_explanation=explanation,
                    #     work_type=k_taskType,
                    # )
                    # db.session.add(k_work)
                    # db.session.commit()  

                    # # CWS - definition
                    # k_work_id = Work.query.count() + 1
                    # k_username = row["Staff ID"]
                    # k_hours_allocated = row["CWS Hours"]
                    # k_taskType = "CWS"
                    # explanation = "cwk proj sup of " + k_work_id

                    # #CWS - add workallocation record
                    # k_workload_allocation = WorkloadAllocation(
                    #     work_id=str(k_work_id),
                    #     hours_allocated=float(k_hours_allocated),
                    #     username=str(k_username),
                    # )
                    # db.session.add(k_workload_allocation)
                    # db.session.commit()

                    # # RM - Insert work record
                    # k_work = Work(
                    #     work_id=k_work_id,
                    #     work_explanation=explanation,
                    #     work_type=k_taskType,
                    # )
                    # db.session.add(k_work)
                    # db.session.commit() 

                flash("File uploaded and data stored as TaskData objects successfully.")
                return redirect(url_for('assign'))
            except Exception as e:
                return f"Error: {str(e)}"

    flash("No file selected for upload.")
    return redirect(url_for('assign'))

@app.route('/comment_history')
@login_required
def comment_history():
    # Check if the current user is an HoD
    if g.is_hod:
        # Fetch the department ID of the current HoD user
        hod_dept_id = User.query.filter_by(
            username=current_user.username).first().dept_id

        # Fetch the comments made by staff members with the same dept_id as that of the HoD user and save them in the comments variable
        comments = WorkloadAllocation.query.join(User, WorkloadAllocation.username == User.username).filter(
            User.dept_id == hod_dept_id
        ).all()

        # Render the comment history page
        return render_template('comment_history.html', title='Comment History', comments=comments)

    # If the current user is not an HoD, redirect them to some other page or display an error message (depends on your application's requirements)
    else:
        flash('You do not have permission to view the Comment History page.')
        return redirect(url_for('dashboard'))


@app.route('/mark_comments_as_read', methods=['POST'])
@login_required
def mark_comments_as_read():
    # Check if the user is an HoD
    if g.is_hod:
        # Fetch the department ID of the current HoD user
        hod_dept_id = User.query.filter_by(
            username=current_user.username).first().dept_id

        # Fetch the comments made by staff members with the same dept_id as that of the HoD user
        comments = WorkloadAllocation.query.join(User, WorkloadAllocation.username == User.username).filter(
            User.dept_id == hod_dept_id
        ).all()

        # Update the comment_status to "Read" for each fetched comment
        for comment in comments:
            if comment.comment_status == "Unread":
                comment.comment_status = "Read"
                db.session.commit()

        # Return success status as JSON response
        return jsonify(status="success"), 200

    # If the user is not an HoD, return an error message
    else:
        return jsonify(status="error", message="Unauthorised access"), 403

# The below function runs before processing a request


@app.before_request
def before_request():
    # Initialise the global notification flag to False
    g.show_notification = False
    # Check if the current user is authenticated
    if current_user.is_authenticated:
        # Fetch the user data from the User table based on the current user's username
        user = User.query.filter_by(username=current_user.username).first()

        # If the user is found
        if user:
            # Check if the user's role is "HoD"
            is_hod = user.role_id == Role.query.filter_by(
                role_name='HoD').first().role_id

            # Set a global variable to identify if the current user is an HoD
            g.is_hod = is_hod

            # If the user is an HoD
            if is_hod:
                # Query for unread comments from users in the same department as the HoD
                unread_comments = WorkloadAllocation.query.join(User, WorkloadAllocation.username == User.username).filter(
                    WorkloadAllocation.comment_status == "Unread",
                    User.dept_id == user.dept_id
                ).count()

                # If there are any unread comments, set the global notification flag to True
                g.show_notification = unread_comments > 0
            else:
                # If user is not an HoD, set the global notification flag to False
                g.show_notification = False
        else:
            # If user data is not found in the User table, set the global notification flag to False
            g.show_notification = False

# Check for unread comments


@app.route('/check_unread_comments')
@login_required  # Ensure that the user is logged in to access this route
def check_unread_comments():
    # Fetch the user data from the User table based on the current user's username
    user = User.query.filter_by(username=current_user.username).first()

    # If the user is found
    if user:
        # Query for unread comments from users in the same department as the current user
        unread_comments = WorkloadAllocation.query.join(User, WorkloadAllocation.username == User.username).filter(
            WorkloadAllocation.comment_status == "Unread",
            User.dept_id == user.dept_id
        ).count()
    else:
        # If user data is not found, set unread comments to 0
        unread_comments = 0

    # Return the number of unread comments as a JSON response
    return jsonify(unread_comments=unread_comments)

if __name__ == '__main__':
    app.run(debug=True)
