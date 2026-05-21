<?php
// setup_secure.php
// Run this ONCE to convert plaintext passwords in the database to bcrypt hashes
// for the secure_app to work with password_verify()
//
// Usage: Open http://localhost/setup_secure.php in your browser
//        (place this file in C:\xampp\htdocs\ or alongside your app folders)

$server = "localhost";
$db_user = "root";
$db_pass = "";
$db_name = "lab5";

$conn = new mysqli($server, $db_user, $db_pass, $db_name);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

echo "<h2>Setting up hashed passwords for secure_app</h2>";

// First, we need to alter the password column to store longer bcrypt hashes (60 chars)
$conn->query("ALTER TABLE users MODIFY password VARCHAR(255)");
echo "<p>✓ Altered password column to VARCHAR(255)</p>";

// Define the users and their original plaintext passwords
$users = [
    ['username' => 'user1', 'password' => 'pass1'],
    ['username' => 'admin', 'password' => 'admin123']
];

foreach ($users as $user) {
    $hashed = password_hash($user['password'], PASSWORD_DEFAULT);
    $stmt = $conn->prepare("UPDATE users SET password = ? WHERE username = ?");
    $stmt->bind_param("ss", $hashed, $user['username']);
    $stmt->execute();
    echo "<p>✓ Updated <strong>" . $user['username'] . "</strong> → hashed password</p>";
    $stmt->close();
}

echo "<hr>";
echo "<p><strong>Done!</strong> The secure_app can now authenticate using password_verify().</p>";
echo "<p>Original credentials still work: <code>user1/pass1</code> and <code>admin/admin123</code></p>";
echo "<p><strong>Important:</strong> After running this script, the vulnerable_app will NO LONGER work for normal login (since passwords are now hashed). ";
echo "If you need to test both apps, re-run the database setup SQL to restore plaintext passwords for vulnerable_app, then run this script again for secure_app.</p>";

$conn->close();
?>
