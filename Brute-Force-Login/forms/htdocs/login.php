<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>Login</title>

    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">

    <!-- Custom Styles -->
    <style>
        body {
            background-color: #f8f9fa;
        }

        .container {
            margin-top: 100px;
        }

        .card {
            border: none;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
        }

        .card-header {
            background-color: #007bff;
            color: #fff;
            text-align: center;
            padding: 20px;
            border-radius: 10px 10px 0 0;
        }

        .card-body {
            padding: 30px;
        }

        .btn-primary {
            background-color: #007bff;
            border: none;
        }

        .btn-primary:hover {
            background-color: #0056b3;
        }
    </style>
</head>

<body>
    <?php
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        $username = $_POST["username"];
        $password = $_POST["password"];

        if (empty($username) || empty($password)) {
            http_response_code(400);
            echo "<script>
                alert('Username and password are required.');
                window.history.back();
              </script>";
            exit;
        }
        $real_username = "admin";
        $real_password = file_get_contents("../conf/password.txt");
        $real_username = trim($real_username);
        $real_password = trim($real_password);
        if ($username != $real_username || $password != $real_password) {
            http_response_code(401);
            echo "<script>
                alert('Incorrect username or password.');
                window.history.back();
              </script>";
            exit;
        }
        header("Location: home/home.php");
        exit;
    }

    // to make the above with get

    if ($_SERVER["REQUEST_METHOD"] == "GET") {
        $username = $_GET["username"];
        $password = $_GET["password"];
        if (isset($username) and isset($password)) {
            $real_username = "admin";
            $real_password = file_get_contents("../conf/password.txt");
            $real_username = trim($real_username);
            $real_password = trim($real_password);
            if ($username != $real_username || $password != $real_password) {
                http_response_code(401);
                echo "<script>
                    alert('Incorrect username or password.');
                    window.history.back();
                </script>";
                exit;
            }
            header("Location: home/home.php");
            exit;
        }
    }
    ?>

    <div class="container">
        <div class="row">
            <div class="col-md-6 offset-md-3">
                <div class="card">
                    <div class="card-header">
                        <h2>Welcome to Your Website</h2>
                        <p>Login or Sign Up to get started</p>
                    </div>
                    <div class="card-body">
                        <div class="text-center mb-4">
                            <a href="#" class="btn btn-primary btn-lg">Login</a>
                            <a href="#" class="btn btn-outline-primary btn-lg">Sign Up</a>
                        </div>
                        <hr>
                        <p class="text-center">Or</p>
                        <form action="login.php" method="POST">
                            <div class="form-group">
                                <label for="email">Email or Username</label>
                                <input name="username" type="text" class="form-control" id="email" placeholder="Enter your email or Username">
                            </div>
                            <div class="form-group">
                                <label for="password">Password</label>
                                <input name="password" type="password" class="form-control" id="password" placeholder="Enter your password">
                            </div>
                            <button name="submit" type="submit" class="btn btn-primary btn-block">Login</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap JS and dependencies -->
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.3/dist/umd/popper.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>

</body>

</html>