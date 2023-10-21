# Academic Workload Planning Manager

## Table of Contents

- Purpose of the Web Application
- Architecture of the Web Application
- How to Launch the Web Application
- Unit Tests
- System Tests
- Commit Logs
- License
- Contributors

## Purpose of the Web Application

This IT Capstone Project is designed to provide a comprehensive platform for academic institutions to allocate, manage, and oversee academic workloads. The platform promotes a fair and open work allocation process and supports informed workload planning decisions.

## Architecture of the Web Application

- Client side: A combination of HTML, CSS, and JavaScript - create interactive user interfaces and implements responsive design to ensure compatibility across various devices.
- Server side: Flask framework in Python - implement various routes to handle different user requests, including data retrieval, processing, and storage.
- Database: SQLite, with the use of SQLAlchemy as an ORM (Object Relational Mapper) to interact with the underlying database. The database structure consists of multiple tables such as `user`, `work`, and `workload_allocation` to store and manage workload allocation data.

## How to Launch the Web Application

1. Clone the repository

```bash
git clone https://github.com/yylocky/CITS5206-Group3.git
```

2. Set the environment

```bash
source venv/bin/activate
export FLASK_APP=app.py
pip install -r requirements.txt

```

3. Initialise the database

```bash
flask db init
flask db migrate
flask db upgrade
```

Note: We have set a test database `app.db` in the repository. If you wish to use it, you can skip the above steps.

4. Run the Flask application

```bash
flask run
```

5. Enjoy!

Open your preferred web browser and navigate to the localhost address displayed in your terminal.

## Unit Tests

Unit tests ensure individual units of the source code (e.g., functions and methods) work as intended. We use [pytest](https://docs.pytest.org/en/stable/) as our primary tool for running unit tests.

Key Tests Included:

1. Test Model: Comprehensive tests for the models to ensure data integrity, consistency, and reliability.
2. Update Comment Status Test: This specific test ensures that the comment status is updated correctly, which is crucial to manage and moderate the comments effectively.

How to Run Tests:

1. Ensure that you have `pytest` installed. If not, you can install it using:

   ```
   pip install pytest
   ```
2. To execute the tests, simply run:

   ```
   pytest
   ```

   This will automatically discover and run all the test files in the project, providing a detailed report of the tests that passed or faild.

   To run a specific test, use:

   ```
   pytest <path/to/the/test/file> 
   ```

**Note:** As we use the test database, we strongly advise you to back up your actual database in production and to always separate your test environment.

## System Tests

System tests evaluate the system's compliance with specified requirements. They provide end-to-end testing solutions to ensure the entire application functions correctly. We utilise [Selenium](https://www.techbeamers.com/selenium-webdriver-python-tutorial/) as our primary tool for conduction system tests.

Key Users Included:

1. HoS and Admin(Same access): Tests are in place to ensure these users can perform functions such as Login, View workload, Export workload, Sort workload, Filter workload, and Assign workload. To run the test, use:kload, Sort workload, Filter workload, Assignworkload. To run the test, use:

   ```
   python3 <path/to/systemtest_hos.py>
   ```
2. HoD: Tests ensure that these users can perform operations like login, view comment history, send comments, read comments, and modify workload. To run the test, use:

   ```
   python3 <path/to/systemtest_hod.py>
   ```
3. Staff: A specific test is in place to ensure that staff members are denied access to assign workloads. To run the test, use:

   ```
   python3 <path/to/systemtest_staff.py>
   ```

How to Run Tests:

1. **Selenium Library** : Install the Selenium Python library. You can do this using pip:

   ```
   pip install selenium
   ```
2. **WebDriver** : Depending on the browser and system you intend to use for testing, you'll need the corresponding WebDriver. Here is an example for setup test on Chrome Browser for Mac:

   ```
   brew install chromedrive
   ```
3. Refer[Selenium Webdriver Python Tutorial](https://www.techbeamers.com/selenium-webdriver-python-tutorial/) for more details. Once downloaded, ensure that the WebDriver binary is in your system's PATH or specify its location directly in your test script.
4. Ensure that you've already started your app and it's running at "[http://127.0.0.1:5000/](http://127.0.0.1:5000/)". If not, please refer to the **How to Launch the Web Application** section.
5. Execute each test script as indicated in the earlier section.

## Commit Logs

We maintain a detailed log of all commits in the commit_log.txt file. This log can be generated by running:

```bash
git log --all --decorate --graph
```

## License

This project is licensed under the MIT license.  For detailed information, please refer to the LICENSE file in the repository.

## Contributors

- Changwu Wu (23160199)
- Michael Wang (21240894)
- Warren Wang (23680549)
- Wendy Wang (23454213)
- Yinyin Wu (23415578)
- Kyle Leung (23601964)
