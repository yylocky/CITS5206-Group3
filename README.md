# Project name

## Table of Contents

- The purpose of web application
- The architecture of web application
- How to launch the web application
- Unit tests
- Commit logs
- License
- Contributors

## The purpose of web application

## The architecture of web application

- Client side:
- Server side:
- Database:

## How to launch the web application

1. Clone the repository

```bash
git clone https://github.com/Erin27100/WebProject2.git
```

2. Set the environment

```bash
xsource venv/bin/activate
export FLASK_APP=app.py
pip install -r requirements.txt

```

initialize the database

```bash
flask db init
flask db migrate
flask db upgrade
```

We have set a database test.db in the repository. If you want to use it, you can skip the above steps.

3. Run the flask

```bash
flask run
```

4. Enjoy

## Unit tests

## System tests

## Commit logs

We use commit_log.txt to record the commit created by running:

```bash
git log -–all -–decorate -–graph
```

## License

This project is licensed under the MIT license.

## Contributors
