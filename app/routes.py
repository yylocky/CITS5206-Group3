from flask import render_template, request, redirect, url_for, flash, jsonify, current_app, session
from flask_login import current_user, login_user, logout_user, login_required
from app import app, db, forms
from app.models import Login, User, WorkloadAllocation, Role, Work
from app.forms import LoginForm, SignupForm
from werkzeug.urls import url_parse
import re
import random
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
        set_session(user)
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
