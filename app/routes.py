from flask import render_template, request, redirect, url_for, flash, jsonify, current_app, session
from flask_login import current_user, login_user, logout_user, login_required
from app import app, db, forms
from app.models import Login, User, Role, Work, WorkloadAllocation
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
        hours_allocated = 4
        workload_point = 10
        comment_status = 'Unread'

        info = WorkloadAllocation(
            work_id=work.work_id,
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

    return render_template('edit_allocation_detail.html', title='Edit Allocation Detail', role_name=role_name)



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
