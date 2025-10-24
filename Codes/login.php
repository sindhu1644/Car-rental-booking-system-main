<?php
// Database connection
$conn = new mysqli('localhost', 'root', '', 'vehicle_rentals');

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Registration logic
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['register'])) {
    $first_name = $_POST['first_name'];
    $middle_name = $_POST['middle_name'];
    $last_name = $_POST['last_name'];
    $gender = $_POST['gender'];
    $dob = $_POST['dob'];
    $mobile = $_POST['mobile'];
    $email = $_POST['email'];
    $password = password_hash($_POST['password'], PASSWORD_BCRYPT);

    $stmt = $conn->prepare("INSERT INTO Users (first_name, middle_name, last_name, gender, dob, mobile, email, password) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("ssssssss", $first_name, $middle_name, $last_name, $gender, $dob, $mobile, $email, $password);

    if ($stmt->execute()) {
        // Redirect to home page on successful registration
        header("Location: home.html");
        exit();
    } else {
        echo "<p style='color: red; text-align: center;'>Error: " . $stmt->error . "</p>";
    }
    $stmt->close();
}

// Login logic
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['login'])) {
    $email = $_POST['email'];
    $password = $_POST['password'];

    $stmt = $conn->prepare("SELECT password FROM Users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        $stmt->bind_result($hashed_password);
        $stmt->fetch();
        if (password_verify($password, $hashed_password)) {
            // Redirect to home page on successful login
            header("Location: home.html");
            exit();
        } else {
            echo "<p style='color: red; text-align: center;'>Incorrect password.</p>";
        }
    } else {
        echo "<p style='color: red; text-align: center;'>No account found with that email.</p>";
    }
    $stmt->close();
}

$conn->close();
?>
