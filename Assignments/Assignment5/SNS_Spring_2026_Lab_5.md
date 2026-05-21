

International Institute of Information Technology
## Hyderabad
System and Network Security (CS5.470)
## Lab Assignment 5:
SQL Injection Attack and Defense
Hard Deadline: 17-04-2026, 11:59 PM
## Total Marks: 100
Note:- It is strongly recommended that no group is allowed to copy programs from others. Hence, if there
is any duplicate in the assignment, both parties will be awarded zero marks without any compromise. No
assignment will be accepted after the deadline. Students must implement the web application, database
setup, attack demonstrations, and defense mechanisms on their own systems. Blind use of frameworks or
copying ready-made vulnerable/secure code from the internet without understanding will result in penalties.
All attacks demonstrated must be reproducible during evaluation. Screenshots without proper implementation
will not be considered for marks.
## 1. Objective
In this assignment, you will:
-  Build a login system connected to a database
-  Make it vulnerable to SQL Injection
-  Perform SQL Injection attacks
-  Modify database using attacks
-  Secure the system and prevent all attacks
- Step 1: Install and Setup Environment
-  Install XAMPP
-  Open XAMPP Control Panel
## 1

-  Start Apache and MySQL
Place your project inside:
## C:\xampp\htdocs\
Open browser:
http://localhost/
## 3. Step 2: Create Database
## Open:
http://localhost/phpmyadmin
## Run:
CREATE DATABASE lab5;
USE lab5;
CREATE TABLE users (
username VARCHAR(50),
password VARCHAR(50)
## );
INSERT INTO users VALUES (’user1’,’pass1’);
INSERT INTO users VALUES (’admin’,’admin123’);
- Step 3: Build the Applications
You must create two separate applications:
## Important:
These are directories (folders). Each directory contains a complete web application.
4.1 vulnerableapp (Insecure Application)
## Create:
## 2

vulnerable_app/
|-- index.php
|-- authentication.php
|-- connection.php
|-- style.css
style.css is optional.
Description of files:
-  index.php: Login page with username and password input
-  authentication.php: Contains SQL query (intentionally vulnerable)
-  connection.php: Connects to MySQL database
-  style.css: Optional styling
Important: Use this vulnerable query:
$sql = "SELECT
## *
FROM users WHERE username=’$username’
AND password=’$password’";
This query is intentionally insecure.
4.2 secure
app (Fixed Application)
## Create:
secure_app/
|-- index.php
|-- authentication.php
|-- connection.php
This must be a corrected version of the vulnerable application.
Required fixes:
-  Use prepared statements
-  Hash passwords
-  Validate input
-  Do not display SQL errors
## 3

- Step 4: Run the Application
## Access:
http://localhost/vulnerable_app/
Test normal login:
-  user1 / pass1
- Step 5: Perform SQL Injection Attacks
## 6.1 Authentication Bypass
Login without knowing password. Expected: Login succeeds.
6.2 Union-Based Injection
Extract data from database. Expected: Show multiple users.
6.3 Blind SQL Injection
Use logical conditions to infer information.
6.4 Database Modification Attack (MANDATORY)
Perform at least one:
-  Change admin password
-  Insert a new user
You MUST show:
-  Screenshot BEFORE modification
-  Screenshot AFTER modification
- Step 6: Secure the Application
## Run:
http://localhost/secure_app/
Verify: All previous attacks FAIL
## 4

## 8. Submission Guidelines
## Submit:
## <group_number>_lab5.zip
## Containing:
-  vulnerable
app/
-  secureapp/
## •  Screenshots/
-  README.md
-  SECURITY.md
- SECURITY.md Must Explain
-  How SQL Injection works
-  Types of attacks performed
-  How attacks modified the database
-  How fixes prevent attacks
## 10. Evaluation Criteria
-  Vulnerable system implementation
-  Successful attacks
-  Database modification proof
-  Secure implementation
-  Code clarity
— End of Assignment —
## 5