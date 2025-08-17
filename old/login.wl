<html>
<head>
    <title>cozis news - login</title>
    <style>
        body {
            line-height: 200%;
            font-family: monospace;
            max-width: 800px;
            margin: 20px auto;
        }
        nav {
            overflow: auto;
            background: #5780C9;
            color: #6E93D4;
            padding: 5px 10px;
            border-top-left-radius: 3px;
            border-top-right-radius: 3px;
        }
        nav div {
            float: left
        }
        nav div:last-child {
            float: right
        }
        nav a {
            font-size: 14px;
            color: #1D2B42;
        }
        nav a.current {
            font-weight: bold;
        }
        main {
            padding: 5px 10px;
            background: #F7E6C0;
            border-bottom-left-radius: 3px;
            border-bottom-right-radius: 3px;
        }
        footer {
            padding: 5px 10px;
        }
        
        /* Login form styles */
        .login-container {
            max-width: 400px;
            margin: 40px auto;
            padding: 30px;
            background: #E8D4A9;
            border-radius: 5px;
            border: 1px solid #D4C298;
        }
        .login-container h2 {
            text-align: center;
            margin-bottom: 30px;
            color: #1D2B42;
            font-size: 18px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            margin-bottom: 5px;
            color: #7A5F2A;
            font-size: 14px;
        }
        .form-group input {
            width: 100%;
            padding: 8px;
            font-family: monospace;
            font-size: 14px;
            background: #F7E6C0;
            border: 1px solid #D4C298;
            border-radius: 3px;
            box-sizing: border-box;
        }
        .form-group input:focus {
            outline: none;
            border-color: #5780C9;
            background: #fff;
        }
        .login-button {
            width: 100%;
            padding: 10px;
            background: #5780C9;
            color: #F7E6C0;
            border: none;
            border-radius: 3px;
            font-family: monospace;
            font-size: 14px;
            cursor: pointer;
            margin-bottom: 15px;
        }
        .login-button:hover {
            background: #1D2B42;
        }
        .form-links {
            text-align: center;
            font-size: 12px;
        }
        .form-links a {
            color: #7A5F2A;
            margin: 0 10px;
        }
        .form-links a:hover {
            color: #1D2B42;
        }
    </style>
</head>
<body>
    <nav>
        <div>
            <a href="/new">new</a>
            |
            <a href="">hot</a>
        </div>
        <div>
            <a href="">settings</a>
            |
            <a href="/login" class="current">login</a>
        </div>
    </nav>
    <main>
        <div class="login-container">
            <h2>Welcome back!</h2>
            <form action="/api/login" method="POST">
                <div class="form-group">
                    <label for_="username">Username:</label>
                    <input type="text" id="username" name="username" required />
                </div>
                <div class="form-group">
                    <label for_="password">Password:</label>
                    <input type="password" id="password" name="password" required />
                </div>
                <button type="submit" class="login-button">log in</button>
                <div class="form-links">
                    <a href="">forgot password?</a>
                    |
                    <a href="">create account</a>
                </div>
            </form>
        </div>
    </main>
    <footer>
        Made with love by cozis
    </footer>
</body>
</html>
