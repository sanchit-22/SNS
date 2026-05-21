<?php
// authentication.php - Intentionally VULNERABLE to SQL Injection
// Uses unsanitized user input directly in SQL query
// Supports multi_query for stacked query (database modification) attacks

include("connection.php");

// Get user input directly - NO sanitization (intentionally vulnerable)
$username = $_POST['username'];
$password = $_POST['password'];

// VULNERABLE QUERY - directly interpolates user input
$sql = "SELECT * FROM users WHERE username='$username' AND password='$password'";
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Result</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
<div class="login-container">

<?php
// Use multi_query to support stacked queries (needed for DB modification attacks)
if ($conn->multi_query($sql)) {
    $result = $conn->store_result();
    if ($result && $result->num_rows > 0) {
        echo "<h2 style='color: green;'>Login Successful – Welcome!</h2>";
        echo "<h3>User Details:</h3>";
        echo "<table border='1' cellpadding='8' cellspacing='0'>";
        echo "<tr><th>Username</th><th>Password</th></tr>";
        while ($row = $result->fetch_assoc()) {
            echo "<tr>";
            echo "<td>" . $row['username'] . "</td>";
            echo "<td>" . $row['password'] . "</td>";
            echo "</tr>";
        }
        echo "</table>";
        $result->free();
    } else {
        echo "<h2 style='color: red;'>Login Failed</h2>";
        echo "<p>Invalid username or password.</p>";
    }
    // Process any remaining results from stacked queries
    while ($conn->more_results() && $conn->next_result()) {
        $extra = $conn->store_result();
        if ($extra) {
            $extra->free();
        }
    }
} else {
    // Display SQL error (intentionally insecure - helps attacker debug)
    echo "<h2 style='color: red;'>Login Failed</h2>";
    echo "<p>SQL Error: " . $conn->error . "</p>";
}

$conn->close();
?>

<br>
<a href="index.php">Back to Login</a>
</div>
</body>
</html>
