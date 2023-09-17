from app import app, db
from app.models import User
from app.models import Department,Role,Work,WorkloadAllocation

@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User, 'Department': Department, 'Role': Role, 'Work': Work, 'WorkloadAllocation': WorkloadAllocation}