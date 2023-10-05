from flask import render_template, request, redirect, url_for, flash, jsonify, current_app, session
from flask_login import current_user, login_user, logout_user, login_required
from app import app, db, forms
from app.models import Login, User, Role

from app.models import WorkloadAllocation
from app.models import Department,Work
from app.forms import LoginForm, SignupForm
from werkzeug.urls import url_parse
import re
import random
from flask import session
import uuid

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


@app.route('/assign_workload')
@login_required
def assign():
    return render_template('assign_workload.html', title='Assign Workload')

@app.route('/edit_allocation_detail')
@login_required
def edit_allocation_detail():
    role_name = get_session()
    return render_template('edit_allocation_detail.html', title='Edit Allocation Detail', role_name=role_name)


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


@app.route("/getpoint", methods=["POST"])
def get_point():
    staff_id = request.form.get("staffId")  

    
    user = User.query.filter_by(username=staff_id).first() 

    if user:
        contract_hour = user.contract_hour

        return jsonify({"contract_hour": contract_hour})
    else:
        return jsonify({"message": "User not found"})


@app.route('/assign', methods=['POST'])
def assign_task():
    try:
        k_category = request.form.get("category")
        k_taskType = request.form.get("taskType")
        k_department = request.form.get("department")
        k_work_id = request.form.get("staffId")
        k_username = k_work_id
        k_comment = request.form.get("explanation")
        k_comment_status = "Unread"
        k_unit_code = request.form.get("unitCode")
        k_hours_allocated = request.form.get("assignedHours")
        k_workload_point = request.form.get("workPoint")

        print("k_category: ")
        print(k_category)
        print("k_taskType: ")
        print(k_taskType)
        print("k_department: ")
        print(k_department)
        print("k_work_id: ")
        print(k_work_id)
        print("k_username: ")
        print(k_username)
        print("k_comment: ")
        print(k_comment)
        print("k_comment_status: ")
        print(k_comment_status)
        print("k_unit_code: ")
        print(k_unit_code)
        print("k_hours_allocated: ")
        print(k_hours_allocated)
        print("k_workload_point: ")
        print(k_workload_point)

        k_depart = Department.query.filter_by(dept_name=k_department).first()
        print(k_depart)
        k_dept_id = k_depart.dept_id
        print(k_dept_id)

        role_name = "HoS"
        k_role = Role.query.filter_by(role_name=role_name).first()
        k_role_id = k_role.role_id
        print(k_role_id)

        # #work
        k_work_explanation="Some explanation for " + k_taskType
        k_work = Work(
            work_explanation=k_comment,
            work_type=k_taskType,
            dept_id=int(k_dept_id),
            unit_code=k_unit_code
        )
        #
        db.session.add(k_work)
        db.session.commit()

        # #workload
        k_workload_allocation = WorkloadAllocation(
            work_id=k_work.work_id,
            hours_allocated=float(k_hours_allocated),
            username=int(k_username),
            comment=k_comment,
            comment_status=k_comment_status,
            workload_point=float(k_workload_point)
        )

        db.session.add(k_workload_allocation)
        db.session.commit()
        #

        #user
        k_contract_hour = float(k_workload_point) / float(k_hours_allocated)
        k_user = User.query.filter_by(username=k_username).first()
        k_user.leave_hours = k_hours_allocated
        db.session.add(k_user)
        db.session.commit()

        return "assigned and data stored successfully."
    except Exception as e:
        return f"Error: {str(e)}"

def generate_int_id():
    # Generate a UUID4 and convert it to an integer
    uuid_str = str(uuid.uuid4()).replace('-', '')
    int_id = int(uuid_str, 16)
    int_id = int(str(int_id)[0:12])
    return int_id
@app.route("/get_department", methods=["POST"])
def get_department():
    staff_id = request.form.get("staffId")
    user_info = User.query.filter_by(username=staff_id).first()
    dept_info = Department.query.filter_by(dept_id=user_info.dept_id).first()
    # Assuming you have retrieved the department as "department_name"
    department_name = dept_info.dept_name # Replace with your actual department retrieval logic
    return jsonify({"department": department_name})


@app.route('/check_duplicate_task', methods=['POST'])
def check_duplicate_task():
    try:
        task_type = request.form.get("taskType")
        department = request.form.get("department")
        staff_id = request.form.get("staffId")
        assigned_hours = request.form.get("assignedHours")
        k_workload_point = request.form.get("workPoint")

        is_duplicate = False

        workloads = WorkloadAllocation.query.filter_by(username= staff_id, hours_allocated=assigned_hours, workload_point= k_workload_point).all()
        for item in workloads:
            k_depart = Department.query.filter_by(dept_name=department).first()
            works = Work.query.filter_by(work_id=item.work_id, work_type=task_type, dept_id=k_depart.dept_id).all()
            if len(works) != 0:
                is_duplicate = True
                break
        print(is_duplicate)
        return jsonify({"is_duplicate": is_duplicate})
    except Exception as e:
        return jsonify({"error": str(e)})



if __name__ == '__main__':
    app.run(debug=True)
