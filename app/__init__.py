from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
import os
from flask_uploads import configure_uploads, UploadSet, DATA

app=Flask(__name__)

app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login = LoginManager(app)
login.login_view='login'
create_app = app

#for file type validation
app.config['SECRET_KEY'] = 'my_security_key'
app.config['UPLOADED_SPREADSHEETS_DEST'] = 'uploads'
spreadsheets = UploadSet('spreadsheets', DATA)
configure_uploads(app, spreadsheets)


from app import routes, models, forms