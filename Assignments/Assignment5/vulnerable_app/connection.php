<?php
// connection.php - Database connection for vulnerable app
// Connects to MySQL using mysqli

$server = "localhost";
$db_user = "root";
$db_pass = "";
$db_name = "lab5";

// Create connection - using mysqli with multi_query support (default)
$conn = new mysqli($server, $db_user, $db_pass, $db_name);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>
