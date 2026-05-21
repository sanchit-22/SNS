<?php
// authentication.php - SECURE version
// Uses prepared statements, password hashing, input validation
// Never displays SQL errors to the user

include("connection.php");

// ---------- Input Validation & Sanitization ----------
$username = isset($_POST['username']) ? trim($_POST['username']) : '';
$password = isset($_POST['password']) ? $_POST['password'] : '';

// Validate: username must be non-empty, alphanumeric, max 50 chars
$valid_input = true;
if (empty($username) || empty($password)) {
    $valid_input = false;
}
if (strlen($username) > 50 || !preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
    $valid_input = false;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Result (Secure)</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: Arial, sans-serif; background-color: #e8f5e9;
            display: flex; justify-content: center; align-items: center; min-height: 100vh;
        }
        .login-container {
            background: white; padding: 40px; border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 100%; max-width: 500px;
        }
        h2 { text-align: center; margin-bottom: 20px; }
        p { text-align: center; margin-top: 10px; }
        a { display: block; text-align: center; color: #2e7d32; text-decoration: none; margin-top: 15px; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
<div class="login-container">

<?php
if (!$valid_input) {
    echo "<h2 style='color: red;'>Login Failed</h2>";
    echo "<p>Invalid username or password.</p>";
} else {
    // ---------- Prepared Statement ----------
    // Only fetch the hashed password for the given username
    $stmt = $conn->prepare("SELECT username, password FROM users WHERE username = ?");

    if ($stmt) {
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result && $result->num_rows === 1) {
            $row = $result->fetch_assoc();
            // ---------- Password Verification using password_verify() ----------
            if (password_verify($password, $row['password'])) {
                echo "<h2 style='color: green;'>Login Successful – Welcome!</h2>";
                echo "<p>Welcome, <strong>" . htmlspecialchars($row['username']) . "</strong>!</p>";
            } else {
                echo "<h2 style='color: red;'>Login Failed</h2>";
                echo "<p>Invalid username or password.</p>";
            }
        } else {
            // User not found - same generic message (prevents user enumeration)
            echo "<h2 style='color: red;'>Login Failed</h2>";
            echo "<p>Invalid username or password.</p>";
        }

        $stmt->close();
    } else {
        // Do NOT reveal SQL error details
        echo "<h2 style='color: red;'>Login Failed</h2>";
        echo "<p>An error occurred. Please try again later.</p>";
    }
}

$conn->close();
?>

<br>
<a href="index.php">Back to Login</a>
</div>
</body>
</html>
