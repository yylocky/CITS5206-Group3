import pytest
from app import db
from app.models import User, Role, Department, Work
from flask import Flask

@pytest.fixture(scope='module')
def test_client():
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    with app.test_client() as testing_client:
        with app.app_context():
            db.init_app(app)
            db.create_all()
            yield testing_client
            db.session.remove()
            db.drop_all()

def test_role_creation(test_client):
    role = Role(role_name='Admin')
    db.session.add(role)
    db.session.commit()

    assert role.role_id is not None
    assert role.role_name == 'Admin'

def test_department_creation(test_client):
    department = Department(dept_name='Physics')
    db.session.add(department)
    db.session.commit()

    assert department.dept_id is not None
    assert department.dept_name == 'Physics'

def test_user_creation(test_client):
    user = User(username=12345, role_id=1, leave_hours=10, contract_hour=40, available_hours=30, dept_id=1)
    db.session.add(user)
    db.session.commit()

    assert user.username == 12345
    assert user.available_hours == 30

def test_work_creation(test_client):
    work = Work(work_explanation="Explanation", unit_code="UnitCode", work_type="ADMIN", dept_id=1)
    db.session.add(work)
    db.session.commit()

    assert work.work_id is not None
    assert work.work_category == 'Service'
