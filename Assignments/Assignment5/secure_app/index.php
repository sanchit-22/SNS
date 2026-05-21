<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Login Page</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: Arial, sans-serif;
            background-color: #e8f5e9;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 500px;
        }
        h2 { text-align: center; margin-bottom: 20px; color: #2e7d32; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; color: #555; }
        input[type="text"], input[type="password"] {
            width: 100%; padding: 10px; border: 1px solid #ddd;
            border-radius: 4px; font-size: 14px;
        }
        input:focus { outline: none; border-color: #2e7d32; box-shadow: 0 0 3px rgba(46,125,50,0.3); }
        button {
            width: 100%; padding: 12px; background-color: #2e7d32; color: white;
            border: none; border-radius: 4px; font-size: 16px; cursor: pointer; margin-top: 10px;
        }
        button:hover { background-color: #1b5e20; }
        .badge { background: #2e7d32; color: white; padding: 3px 8px; border-radius: 4px; font-size: 12px; }
        a { display: block; text-align: center; color: #2e7d32; text-decoration: none; margin-top: 15px; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Login (Secure App) <span class="badge">Protected</span></h2>
        <form action="authentication.php" method="POST">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
