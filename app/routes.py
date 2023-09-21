from flask import render_template, request, redirect, url_for, flash, jsonify, current_app, session
from flask_login import current_user, login_user, logout_user, login_required
from app import app, db, forms
from app.models import Login, User, Role, Work, WorkloadAllocation, Department
from app.forms import LoginForm, SignupForm
from werkzeug.urls import url_parse
import re
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


@app.route('/assign_workload')
@login_required
def assign():
    return render_template('assign_workload.html', title='Assign Workload')

@app.route('/edit_allocation_detail', methods=['GET', 'POST'])
@login_required
def edit_allocation_detail():
    role_name = get_session()
    if request.method == 'POST':
        comment = request.form.get('comment')
        if comment is None or comment == '':
            flash('Invalid Comment')
            return render_template('edit_allocation_detail.html', title='Edit Allocation Detail', role_name=role_name)

        user = User.query.filter_by(username=session.get('username', '')).first()
        work = Work.query.filter_by(dept_id=user.dept_id).first()
        work_id = 1
        if work is not None:
            work_id = work.work_id
        hours_allocated = 4
        workload_point = 10
        comment_status = 'Unread'

        info = WorkloadAllocation(
            work_id=work_id,
            hours_allocated=hours_allocated,
            workload_point=workload_point,
            username=user.username,
            comment=comment,
            comment_status=comment_status
        )
        db.session.add(info)
        db.session.commit()

        flash('Comment Success')
        return redirect("/edit_allocation_detail")

    workloads = None
    role_id = session.get('role_id', '')
    username = session.get('username', '')
    user = User.query.filter_by(username=username,role_id=role_id).first()
    # if current user is admin(4) or hod(1), show all workload
    if role_id == 4 or role_id == 1:
        workloads = WorkloadAllocation.query.all()

    # if current user is HoD(2), show only their department workload
    elif role_id == 2:
        workloads = WorkloadAllocation.query.join(Work, Work.work_id == WorkloadAllocation.work_id).filter(
            Work.dept_id == user.dept_id).all()

    # if current user is staff(3), show only their workload
    elif role_id == 3:
        workloads = WorkloadAllocation.query.filter_by(username=username).all()

    return render_template('edit_allocation_detail.html', title='Edit Allocation Detail', role_name=role_name,
                           workloads=workloads, user=user)


@app.route('/get_work_type', methods=['GET', 'POST'])
@login_required
def get_work_type():
    work_type = []
    work_category = request.form.get('work_category')
    if work_category == "Service":
        work_type = ["ADMIN", "GA", "SDS"]

    if work_category == "Teaching":
        work_type = ["CWS", "TEACH", "UDEV"]

    if work_category == "Research":
        work_type = ["HDR", "ORES", "RES-MGMT", "RESERV"]

    if work_category == "Leave":
        work_type = ["LSL", "PL", "SBL"]

    return work_type


@app.route('/get_work', methods=['GET', 'POST'])
@login_required
def get_work():
    work_id = request.form.get('work_id')
    work = Work.query.filter_by(work_id=work_id).first()
    rest = {
        'work_id': work_id,
        'dept_id': work.dept_id,
        'work_explanation': work.work_explanation,
        'work_type': work.work_type,
        'unit_code': work.unit_code
    }
    return rest


@app.route('/get_works', methods=['GET', 'POST'])
@login_required
def get_works():
    works = Work.query.all()
    rest = []
    for item in works:
        temp = {
            'work_id': item.work_id,
            'dept_id': item.dept_id,
            'work_explanation': item.work_explanation,
            'work_type': item.work_type,
            'unit_code': item.unit_code
        }
        rest.append(temp)

    return rest


@app.route('/get_department', methods=['GET', 'POST'])
@login_required
def get_department():
    departments = Department.query.all()
    rest = []
    for item in departments:
        temp = {
            'dept_id': item.dept_id,
            'dept_name': item.dept_name
        }
        rest.append(temp)
    return rest


@app.route('/get_user', methods=['GET', 'POST'])
@login_required
def get_user():
    users = User.query.all()
    rest = []
    for item in users:
        temp = {
            'username': item.username,
            'role_id': item.role_id,
            'leave_hours': item.leave_hours,
            'contract_hour': item.contract_hour,
            'available_hours': item.available_hours,
            'dept_id': item.dept_id,
        }
        rest.append(temp)
    return rest


@app.route('/set_workload_allocation', methods=['GET', 'POST'])
@login_required
def set_workload_allocation():
    alloc_id = request.form.get('alloc_id')
    work_id = request.form.get('work_id')
    work_type = request.form.get('work_type')
    department = request.form.get('department')
    work_explanation = request.form.get('work_explanation')
    unit_code = request.form.get('unit_code')
    hours_allocated = request.form.get('hours_allocated')
    username = request.form.get('username')
    workload_point = request.form.get('workload_point')

    workload = WorkloadAllocation.query.filter_by(alloc_id=alloc_id).first()

    workload.work_id = work_id
    workload.hours_allocated = hours_allocated
    workload.username = username
    workload.workload_point = workload_point

    work = Work.query.filter_by(work_id=work_id).first()
    work.work_type = work_type
    work.dept_id = department
    work.work_explanation = work_explanation
    work.unit_code = unit_code

    db.session.commit()

    rest = {'code': 1, 'msg': 'Modify Success'}
    return rest


def set_session(user):
    user_info = User.query.filter_by(username=user.username).first()
    if user_info is None:
        flash('Invalid Username or Password')
        return redirect(url_for('login'))
    role = Role.query.filter_by(role_id=user_info.role_id).first()
    session['role_id'] = role.role_id
    session['role_name'] = role.role_name
    session['username'] = user.username


def get_session():
    role_name = session.get('role_name', '')
    return role_name


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', title='Dashboard')



if __name__ == '__main__':
    app.run(debug=True)