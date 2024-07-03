<?php
$servername = "127.0.0.1";
$username = "root";
$password = "";
$dbname = "yalaney";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Function to sanitize input data
function sanitize_input($data) {
    return htmlspecialchars(stripslashes(trim($data)));
}

// Initialize variables and errors array
$errors = [];
$fName = $lName = $email = $password = $repeat_password = "";

// Validate form data
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (empty($_POST["fName"])) {
        $errors[] = "First name is required.";
    } else {
        $fName = sanitize_input($_POST["fName"]);
    }

    if (empty($_POST["lName"])) {
        $errors[] = "Last name is required.";
    } else {
        $lName = sanitize_input($_POST["lName"]);
    }

    if (empty($_POST["email"])) {
        $errors[] = "Email is required.";
    } elseif (!filter_var($_POST["email"], FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Invalid email format.";
    } else {
        $email = sanitize_input($_POST["email"]);
    }

    if (empty($_POST["password"])) {
        $errors[] = "Password is required.";
    } elseif (strlen($_POST["password"]) < 6) {
        $errors[] = "Password must be at least 6 characters.";
    } else {
        $password = sanitize_input($_POST["password"]);
    }

    if (empty($_POST["psw-repeat"])) {
        $errors[] = "Repeat password is required.";
    } else {
        $repeat_password = sanitize_input($_POST["psw-repeat"]);
    }

    if ($password !== $repeat_password) {
        $errors[] = "Passwords do not match.";
    }

    if (empty($errors)) {
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        $stmt = $conn->prepare("INSERT INTO user_accounts (firstName, lastName, email, pWord) VALUES (?, ?, ?, ?)");
        if ($stmt) {
            $stmt->bind_param("ssss", $fName, $lName, $email, $hashed_password);
            if ($stmt->execute()) {
                echo "New record created successfully";
            } else {
                echo "Error: " . $stmt->error;
            }
            $stmt->close();
        } else {
            echo "Error preparing statement: " . $conn->error;
        }
    } else {
        foreach ($errors as $error) {
            echo "<p>Error: $error</p>";
        }
    }
}

$conn->close();
?>
