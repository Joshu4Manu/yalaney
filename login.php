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
$email = $password = "";

// Validate form data
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (empty($_POST["email"])) {
        $errors[] = "Email is required.";
    } elseif (!filter_var($_POST["email"], FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Invalid email format.";
    } else {
        $email = sanitize_input($_POST["email"]);
    }

    if (empty($_POST["password"])) {
        $errors[] = "Password is required.";
    } else {
        $password = sanitize_input($_POST["password"]);
    }

    // If there are no errors, proceed to check credentials
    if (empty($errors)) {
        // Prepare and bind
        $stmt = $conn->prepare("SELECT pWord FROM user_accounts WHERE email = ?");
        if ($stmt) {
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $stmt->store_result();
            
            if ($stmt->num_rows > 0) {
                $stmt->bind_result($hashed_password);
                $stmt->fetch();
                
                // Verify password
                if (password_verify($password, $hashed_password)) {
                    echo "Login successful. Welcome!";
                    // Handle successful login (e.g., start a session, set cookies, redirect)
                } else {
                    echo "Invalid password.";
                }
            } else {
                echo "No account found with that email.";
            }
            $stmt->close();
        } else {
            echo "Error preparing statement: " . $conn->error;
        }
    } else {
        // Print validation errors
        foreach ($errors as $error) {
            echo "<p>Error: $error</p>";
        }
    }
}

$conn->close();
?>
