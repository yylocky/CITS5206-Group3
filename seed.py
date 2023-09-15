from app import app, db
from app.models import Role, Department, User, Work, WorkloadAllocation, Login

def seed_roles():
    roles = ['HoS', 'HoD', 'Staff', 'Admin']
    for role in roles:
        new_role = Role(role_name=role)
        db.session.add(new_role)

def seed_departments():
    departments = ['Physics', 'M&S', 'CSSE']
    for dept in departments:
        new_dept = Department(dept_name=dept)
        db.session.add(new_dept)

def seed_login():
    logins = [
        {'username': 11111111, 'password': 'hospassword'},
        {'username': 22222222, 'password': 'hodpassword'},
        {'username': 33333333, 'password': 'staffpassword'},
        {'username': 44444444, 'password': 'adminpassword'},
    ]

    for login in logins:
        new_login = Login(username=login['username'])
        new_login.set_password(login['password'])
        db.session.add(new_login)

def seed_users():
    users = [
        {'username': 11111111, 'role_id': 1, 'leave_hours': 0.0, 'contract_hour': 40.0, 'available_hours': 40.0, 'dept_id': 1},
        {'username': 22222222, 'role_id': 2, 'leave_hours': 0.0, 'contract_hour': 40.0, 'available_hours': 40.0, 'dept_id': 2},
        {'username': 33333333, 'role_id': 3, 'leave_hours': 0.0, 'contract_hour': 40.0, 'available_hours': 40.0, 'dept_id': 3},
        {'username': 44444444, 'role_id': 4, 'leave_hours': 0.0, 'contract_hour': 40.0, 'available_hours': 40.0, 'dept_id': 1},
    ]

    for user in users:
        new_user = User(username=user['username'], role_id=user['role_id'], leave_hours=user['leave_hours'], contract_hour=user['contract_hour'], available_hours=user['available_hours'], dept_id=user['dept_id'])
        db.session.add(new_user)

def seed_work():
    work_types = ['ADMIN', 'CWS', 'GA', 'HDR', 'ORES', 'RES-MGMT', 'RESERV', 'SDS', 'TEACH', 'UDEV']
    for work_type in work_types:
        work_example = Work(work_explanation=f"Some explanation for {work_type}", work_type=work_type, dept_id=1, unit_code="if there is a unit code")
        db.session.add(work_example)

def seed_workload_allocation():
    workload = WorkloadAllocation(work_id=1, hours_allocated=4.0, username=33333333, comment="Some comment", comment_status="Unread", workload_point=10)
    db.session.add(workload)

def run_seed():
    with app.app_context():
        seed_roles()
        seed_departments()
        seed_login()
        seed_users()
        seed_work()
        seed_workload_allocation()
        db.session.commit()
        print("Seeding completed!")

if __name__ == '__main__':
    run_seed()
