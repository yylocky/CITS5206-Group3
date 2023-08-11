import os
import secrets
basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    SECRET_KEY= os.environ.get('SECRET_KEY') or secrets.token_hex(16)
    # define database location, default to sqlite database in app.db
    SQLALCHEMY_DATABASE_URI= os.environ.get('DATABASE_URL') or 'sqlite:///'+os.path.join(basedir,'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS= False