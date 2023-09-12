import pytz
from datetime import datetime
from app import db, login
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from datetime import datetime

timezone = pytz.timezone("Australia/Perth")
now = datetime.now(timezone)

# user class to store user login information
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    last_login = db.Column(db.DateTime, default=now)


    # format how the object is printed for debugging
    def __repr__(self):
        return '<User {}>'.format(self.username)

    # set password hash
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # check password hash
    def check_password(self, password):
        return check_password_hash(self.password_hash,password)
    
# user loader function for flask-login
@login.user_loader
def load_user(id):
    return User.query.get(int(id))



	class TaskData1(db.Model):
	    id = db.Column(db.Integer, primary_key=True)
	    department = db.Column(db.String(64))
	    task_type = db.Column(db.String(64))
	    task_name = db.Column(db.String(64))
	    assigned_hours = db.Column(db.Float)
	    staff_name = db.Column(db.String(64))

    def __repr__(self):
        return f'<TaskData1 {self.id}>'



    
