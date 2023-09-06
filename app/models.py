from app import db, login
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

class Role(db.Model):
    role_id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(64), nullable=False, unique=True)
    __table_args__ = (db.CheckConstraint(role_name.in_(['HoS', 'HoD', 'Staff', 'Admin'])), )

class Department(db.Model):
    dept_id = db.Column(db.Integer, primary_key=True)
    dept_name = db.Column(db.String(64), nullable=False, unique=True)
    __table_args__ = (db.CheckConstraint(dept_name.in_(['Physics', 'M&S', 'CSSE'])), )

class User(UserMixin, db.Model):
    username = db.Column(db.Integer, primary_key=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.role_id'))
    leave_hours = db.Column(db.Float)
    contract_hour = db.Column(db.Float)
    available_hours = db.Column(db.Float)

    def get_id(self):
        return (self.username)

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Work(db.Model):
    work_id = db.Column(db.Integer, primary_key=True)
    work_explanation = db.Column(db.String(128), nullable=False)
    work_type = db.Column(db.String(64), nullable=False)
    default_hours = db.Column(db.Float)
    dept_id = db.Column(db.Integer, db.ForeignKey('department.dept_id'))
    __table_args__ = (db.CheckConstraint(work_type.in_(['ADMIN', 'CWS', 'GA', 'HDR', 'ORES', 'RES-MGMT', 'RESERV', 'SDS', 'TEACH', 'UDEV'])), )

class WorkloadAllocation(db.Model):
    alloc_id = db.Column(db.Integer, primary_key=True)
    work_id = db.Column(db.Integer, db.ForeignKey('work.work_id'))
    hours_allocated = db.Column(db.Float)
    username = db.Column(db.Integer, db.ForeignKey('user.username'))
    approval_status = db.Column(db.String(64))
    __table_args__ = (db.CheckConstraint(approval_status.in_(['Approved', 'Pending'])), )

@login.user_loader
def load_user(username):
    return User.query.get(int(username))
