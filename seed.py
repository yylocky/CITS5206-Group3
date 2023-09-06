from app import app, db
from app.models import Role, Department, User, Work, WorkloadAllocation

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

def seed_users_with_roles():
    users_data = [
        {'staff_number': 11111111, 'password': 'hospassword', 'role_name': 'HoS'},
        {'staff_number': 22222222, 'password': 'hodpassword', 'role_name': 'HoD'},
        {'staff_number': 33333333, 'password': 'staffpassword', 'role_name': 'Staff'},
        {'staff_number': 44444444, 'password': 'adminpassword', 'role_name': 'Admin'},
    ]

    for user_data in users_data:
        role = Role.query.filter_by(role_name=user_data['role_name']).first()
        if role:
            user = User(staff_number=user_data['staff_number'], role_id=role.role_id)
            user.set_password(user_data['password'])
            db.session.add(user)

def seed_work():
    work_types = ['ADMIN', 'CWS', 'GA', 'HDR', 'ORES', 'RES-MGMT', 'RESERV', 'SDS', 'TEACH', 'UDEV']
    for work_type in work_types:
        work_example = Work(work_explanation=f"Some explanation for {work_type}", work_type=work_type, default_hours=5.0, dept_id=1)  # Assuming `dept_id=1` for simplicity.
        db.session.add(work_example)

def seed_workload_allocation():
    workload = WorkloadAllocation(work_id=1, hours_allocated=4.0, staff_number=33333333, approval_status="Pending")
    db.session.add(workload)

def run_seed():
    with app.app_context():
        seed_roles()
        seed_departments()
        seed_users_with_roles()
        seed_work()
        seed_workload_allocation()
        db.session.commit()
        print("Seeding completed!")

if __name__ == '__main__':
    run_seed()
