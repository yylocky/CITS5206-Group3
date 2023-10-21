import pytest
import json
from app import db, app
from app.models import User, Role, Login, WorkloadAllocation
from flask import Flask

@pytest.fixture(scope='module')
def test_client_and_user():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    with app.test_client() as testing_client:
        with app.app_context():
            db.create_all()

            role = Role.query.filter_by(role_name='HoD').first()
            if role is None:
                role = Role(role_name='HoD')
                db.session.add(role)
                db.session.commit()
            user = User.query.filter_by(username=88888888).first()
            if not user:
                user = User(username=88888888, role_id=role.role_id, leave_hours=10, contract_hour=40, available_hours=30, dept_id=1)
                db.session.add(user)
                db.session.commit()

            login = Login.query.filter_by(username=user.username).first()
            if not login:
                login = Login(username=user.username)
                login.set_password('password')
                db.session.add(login)
                db.session.commit()

            yield testing_client, user  # this is where the testing happens

            db.session.remove()
            db.drop_all()

def test_update_comment_status(test_client_and_user):
    test_client, user = test_client_and_user

    print(test_client.application.url_map)

    # Log the user in
    login_response = test_client.post('/login', data=dict(
        username=user.username,
password='password'
    ), follow_redirects=True)

    print(login_response.data)

    # Check if the response is successful
    assert login_response.status_code == 200

    # Add a test comment
    comment = WorkloadAllocation(work_id=1, hours_allocated=20, workload_point=0.5, username=user.username, comment="Test comment", comment_status="Unread")
    db.session.add(comment)
    db.session.commit()

    # Check the initial comment status
    assert comment.comment_status == 'Unread'

    # Make a POST request to the /update_comment_status/<int:alloc_id> route
    response = test_client.post(f'/update_comment_status/{comment.alloc_id}', follow_redirects=True)

    # Check if the response is successful
    assert response.status_code == 200