# SECURITY.md — SQL Injection Attack and Defense Analysis

## System and Network Security (CS5.470) — Lab 5, Spring 2026

---

## 1. How SQL Injection Works

**SQL Injection (SQLi)** is a code injection technique that exploits vulnerabilities in web applications that construct SQL queries using unsanitized user input. When user-supplied data is directly concatenated into a SQL query string without proper validation, escaping, or parameterization, an attacker can inject malicious SQL code that the database engine executes as part of the query.

### The Vulnerable Pattern

In our vulnerable application, the authentication query is:

```php
$sql = "SELECT * FROM users WHERE username='$username' AND password='$password'";
```

Here, `$username` and `$password` come directly from user input (`$_POST`). If a user enters normal values like `user1` and `pass1`, the resulting query is:

```sql
SELECT * FROM users WHERE username='user1' AND password='pass1'
```

This works correctly. However, if an attacker enters a crafted string containing SQL metacharacters (such as single quotes `'`, comments `--`, or operators like `OR`, `UNION`), they can alter the query's logic entirely.

### Why It's Dangerous

SQL Injection can lead to:
- **Authentication Bypass**: Logging in without valid credentials.
- **Data Exfiltration**: Reading sensitive data (usernames, passwords, credit cards).
- **Data Modification**: Altering or deleting records (changing passwords, adding accounts).
- **Privilege Escalation**: Gaining administrative access.
- **Remote Code Execution**: In extreme cases, executing system commands via the database.

---

## 2. Types of Attacks Performed

### 2.1 Authentication Bypass

**Payload used**:
- Username: `' OR '1'='1' -- `
- Password: `anything`

**Resulting query**:
```sql
SELECT * FROM users WHERE username='' OR '1'='1' -- ' AND password='anything'
```

**Explanation**: The single quote `'` after `username=` closes the string literal. `OR '1'='1'` adds a condition that is always TRUE, so the WHERE clause matches ALL rows in the table. The `--` (double dash followed by a space) is a SQL comment that causes MySQL to ignore the rest of the query (the password check). The attacker is now logged in as the first user returned by the database.

**Impact**: Complete authentication bypass — no username or password knowledge required.

---

### 2.2 Union-Based Injection

**Payload used**:
- Username: `' UNION SELECT username, password FROM users -- `
- Password: `anything`

**Resulting query**:
```sql
SELECT * FROM users WHERE username='' UNION SELECT username, password FROM users -- ' AND password='anything'
```

**Explanation**: The first `SELECT` returns zero rows (no user with empty username). The `UNION` operator combines results from a second `SELECT` that retrieves ALL usernames and passwords from the `users` table. The `--` comments out the rest. The application then displays all users and their passwords in the response.

**Impact**: Full disclosure of all credentials in the database. An attacker can see every username and password.

---

### 2.3 Blind SQL Injection

**Payloads used**:

*True condition*:
- Username: `' OR 1=1 -- `
- Password: `anything`

*False condition*:
- Username: `' OR 1=2 -- `
- Password: `anything`

**Explanation**: In blind SQL injection, the attacker does not see direct query output but can infer information based on the application's behavior (login success vs. failure).

- When the injected condition is TRUE (`1=1`), the query returns rows → **Login Successful**.
- When the injected condition is FALSE (`1=2`), the query returns no rows → **Login Failed**.

By systematically testing conditions, an attacker can extract data character by character. For example:
```sql
' OR (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a' --
```
If login succeeds, the first character of admin's password is `'a'`. Repeating this for each position reveals the full password.

**Impact**: Even without visible output, an attacker can extract the entire database contents one bit/character at a time.

---

### 2.4 Database Modification Attack

**Payload used (change admin password)**:
- Username: `admin`
- Password: `anything'; UPDATE users SET password='hacked' WHERE username='admin'; -- `

**Resulting queries** (stacked):
```sql
SELECT * FROM users WHERE username='admin' AND password='anything';
UPDATE users SET password='hacked' WHERE username='admin';
-- '
```

**Explanation**: The semicolon `;` terminates the first (SELECT) query, then a second query (UPDATE) is injected and executed. The `--` comments out the trailing quote. This is known as a **stacked query injection**. In our implementation, `multi_query()` is used, which allows multiple SQL statements to execute in a single call, making this attack possible.

**Impact**: The admin account password is silently changed from `admin123` to `hacked`. The attacker can now log in as admin with the new password. This demonstrates how SQL injection can modify critical data, potentially leading to full system compromise.

---

## 3. How the Attacks Modified the Database

### Before the Attack
| username | password  |
|----------|-----------|
| user1    | pass1     |
| admin    | admin123  |

### After Database Modification Attack (Option A — Password Change)
| username | password  |
|----------|-----------|
| user1    | pass1     |
| admin    | **hacked** |

### After Database Modification Attack (Option B — User Insertion)
| username | password  |
|----------|-----------|
| user1    | pass1     |
| admin    | admin123  |
| **hacker** | **hacker123** |

The modification was verified by:
1. Checking phpMyAdmin before and after the attack (screenshots).
2. Successfully logging in with the modified/new credentials.

---

## 4. How the Fixes Prevent Each Attack

The secure application (`secure_app/`) implements four layers of defense:

### 4.1 Prepared Statements (Parameterized Queries)

**Implementation**:
```php
$stmt = $conn->prepare("SELECT username, password FROM users WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
```

**How it prevents SQLi**: Prepared statements separate SQL code from data. The `?` placeholder tells the database engine "this is a data value, not SQL code." When `bind_param()` is called, the database treats the entire input as a literal string value, regardless of its contents. Even if the input contains `'`, `OR`, `--`, `UNION`, or `;`, the database will search for a username with that exact string — it will never interpret it as SQL syntax.

**Attacks prevented**: ALL types of SQL injection (authentication bypass, union injection, blind SQLi, stacked queries).

---

### 4.2 Password Hashing (bcrypt)

**Implementation**:
```php
// Storing passwords:
$hashed = password_hash($password, PASSWORD_DEFAULT);

// Verifying passwords:
if (password_verify($password, $row['password'])) { ... }
```

**How it prevents attacks**: Passwords are stored as irreversible bcrypt hashes (e.g., `$2y$10$xyz...`), not plaintext. Even if an attacker somehow extracts data (via a different vulnerability), they see hashed values, not actual passwords. Additionally, this makes union-based injection useless — even if the attacker dumps the password column, they cannot use the hashed values to log in.

**Attacks prevented**: Union-based injection (data exfiltration is useless), credential re-use.

---

### 4.3 Strict Input Validation and Sanitization

**Implementation**:
```php
$username = trim($_POST['username']);
if (strlen($username) > 50 || !preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
    $valid_input = false;
}
```

**How it prevents attacks**: Input validation ensures that only alphanumeric characters and underscores are accepted for usernames. Special characters required for SQL injection (`'`, `"`, `;`, `-`, `(`, `)`, etc.) are rejected before they ever reach the database query. This acts as an additional defense layer even if prepared statements were somehow bypassed.

**Attacks prevented**: Blocks all injection payloads at the input level.

---

### 4.4 Suppressing SQL Error Messages

**Implementation**:
```php
// Instead of:
echo "SQL Error: " . $conn->error;  // INSECURE — reveals database internals

// Secure version:
echo "An error occurred. Please try again later.";  // Generic, safe message
```

**How it prevents attacks**: Detailed SQL error messages reveal database structure, table names, column names, and query syntax to attackers. This information is invaluable for crafting injection payloads. By displaying only generic error messages, the secure app gives attackers no feedback about query structure, making it significantly harder to discover and exploit vulnerabilities.

**Attacks prevented**: Reduces attacker reconnaissance ability; makes error-based SQL injection impossible.

---

## 5. Summary of Defense-in-Depth

| Defense Layer | Attacks It Mitigates |
|---------------|---------------------|
| Prepared Statements | ALL SQL injection types |
| Password Hashing | Data theft, credential exposure |
| Input Validation | Injection payloads blocked at entry |
| Error Suppression | Error-based injection, reconnaissance |

Each layer provides independent protection. Together, they create a **defense-in-depth** strategy where even if one layer fails, others continue to protect the application.

---

## 6. Conclusion

SQL Injection remains one of the most critical web application vulnerabilities (OWASP Top 10). This assignment demonstrated that a single unsanitized input can lead to complete compromise of authentication, data confidentiality, and data integrity. The defense implementation proves that standard, well-known countermeasures — primarily prepared statements and password hashing — effectively prevent all tested attack vectors when properly applied.
