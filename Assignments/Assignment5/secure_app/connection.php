<?php
// connection.php - Database connection for secure app
// Same connection but used with prepared statements

$server = "localhost";
$db_user = "root";
$db_pass = "";
$db_name = "lab5";

// Create connection
$conn = new mysqli($server, $db_user, $db_pass, $db_name);

// Check connection - do NOT reveal details to user
if ($conn->connect_error) {
    die("An error occurred. Please try again later.");
}
?>
