from app import db, login
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from sqlalchemy.ext.hybrid import hybrid_property


class Role(db.Model):
    role_id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(64), nullable=False, unique=True)
    __table_args__ = (db.CheckConstraint(role_name.in_(['HoS', 'HoD', 'Staff', 'Admin']), name='role_name_check'),)


class Department(db.Model):
    dept_id = db.Column(db.Integer, primary_key=True)
    dept_name = db.Column(db.String(64), nullable=False, unique=True)
    __table_args__ = (db.CheckConstraint(dept_name.in_(['Physics', 'M&S', 'CSSE']), name='dept_name_check'),)

class User(db.Model):
    username = db.Column(db.Integer, db.ForeignKey('login.username'), primary_key=True) # username is the unique staff number
    role_id = db.Column(db.Integer, db.ForeignKey('role.role_id'))
    leave_hours = db.Column(db.Float)
    contract_hour = db.Column(db.Float)
    available_hours = db.Column(db.Float)
    dept_id = db.Column(db.Integer, db.ForeignKey('department.dept_id'))#staff belongs to a department
    __table_args__ = (db.CheckConstraint('available_hours = contract_hour - leave_hours', name='available_hours_check'),)
    department = db.relationship('Department', backref='users') 
    
class Login(UserMixin, db.Model):
    username = db.Column(db.Integer, primary_key=True) # username is the unique staff number
    password_hash = db.Column(db.String(128), nullable=False)
    user = db.relationship('User', backref='login', uselist=False)

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
    work_explanation = db.Column(db.String(128))
    unit_code = db.Column(db.String(64)) # unit_code is optional only if the work is related to a unit
    work_type = db.Column(db.String(64), nullable=False)#work type is one of the following 10 types of work and 3 types of leave
    dept_id = db.Column(db.Integer, db.ForeignKey('department.dept_id'), nullable=False)#work belongs to a department
    __table_args__ = (db.CheckConstraint(work_type.in_(['ADMIN', 'CWS', 'GA', 'HDR', 'ORES', 'RES-MGMT', 'RESERV', 'SDS', 'TEACH', 'UDEV','LSL', 'PL', 'SBL']), name='work_type_check'),)
    department = db.relationship('Department', backref='works')
    #add index to the table
    db.Index('idx_work_id', 'work_id')


    @hybrid_property
    def work_category(self):
        if self.work_type in ["ADMIN", "GA", "SDS"]:
            return "Service"
        elif self.work_type in ["CWS", "TEACH", "UDEV"]:
            return "Teaching"
        elif self.work_type in ["HDR", "ORES", "RES-MGMT", "RESERV"]:
            return "Research"
        elif self.work_type in ["LSL", "PL", "SBL"]:
            return "Leave"
        else:
            return None
        

class WorkloadAllocation(db.Model):
    alloc_id = db.Column(db.Integer, primary_key=True)
    work_id = db.Column(db.Integer, db.ForeignKey('work.work_id'), nullable=False)
    hours_allocated = db.Column(db.Float, nullable=False)
    workload_point = db.Column(db.Float, nullable=False)
    username = db.Column(db.Integer, db.ForeignKey('user.username'), nullable=False)
    comment = db.Column(db.String(256))
    comment_status = db.Column(db.String(64))
    user = db.relationship('User', backref='workload_allocations')
    work = db.relationship('Work', backref='workload_allocations')
    __table_args__ = (
        db.CheckConstraint(comment_status.in_(['Read', 'Unread']), name='comment_status_check'), 
        # db.CheckConstraint('workload_point == hours_allocated / user.contract_hour', name='workload_point_check'),
    )
    #add index to the table
    db.Index('idx_alloc_id', 'alloc_id')

@login.user_loader
def load_user(username):
    return Login.query.get(int(username))
