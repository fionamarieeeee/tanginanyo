<?php
include("./connection/config.php");
include("./helpers/SystemOperators.php");

$con = connection();
$so = new SystemOperators();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['btnSubmit'])) {
    $uid = filter_input(INPUT_POST, 'uid', FILTER_SANITIZE_SPECIAL_CHARS);
    $firstname = filter_input(INPUT_POST, 'firstname', FILTER_SANITIZE_SPECIAL_CHARS);
    $lastname = filter_input(INPUT_POST, 'lastname', FILTER_SANITIZE_SPECIAL_CHARS);
    $address = filter_input(INPUT_POST, 'address', FILTER_SANITIZE_SPECIAL_CHARS);

    if (empty($uid) || empty($firstname) || empty($lastname) || empty($address)) {
        echo "<script>alert('Please fill in all fields.');</script>";
    } else {
        $encrypted_fname = $so->encrypt($firstname);
        $encrypted_lname = $so->encrypt($lastname);
        $encrypted_address = $so->encrypt($address);

        $select_query = "SELECT * FROM `users` WHERE `user_id` = ?";
        $select_stmt = $con->prepare($select_query);
        if (!$select_stmt) {
            die("Prepare failed: " . $con->error);
        }

        $select_stmt->bind_param("s", $uid);
        if ($select_stmt->execute()) {
            $result = $select_stmt->get_result();
            if ($result->num_rows > 0) {
                echo "<script>alert('User already exists!');</script>";
            } else {
                $insert_query = "INSERT INTO `users` (`user_id`, `firstname`, `lastname`, `address`) VALUES (?, ?, ?, ?)";
                $insert_stmt = $con->prepare($insert_query);
                if (!$insert_stmt) {
                    die("Prepare failed: " . $con->error);
                }

                $insert_stmt->bind_param("ssss", $uid, $encrypted_fname, $encrypted_lname, $encrypted_address);
                try {
                    if ($insert_stmt->execute()) {
                        echo "<script>alert('User information inserted successfully!'); window.location.href = window.location.href;</script>";
                    } else {
                        echo "<script>alert('Failed to insert user information.');</script>";
                    }
                } catch (mysqli_sql_exception $e) {
                    echo "<script>alert('Database Error: " . addslashes($e->getMessage()) . "');</script>";
                }
                $insert_stmt->close();
            }
        } else {
            echo "<script>alert('Failed to execute SELECT query.');</script>";
        }
        $select_stmt->close();
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Registration</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 30px; }
        .form-fields { width: 450px; }
        .form-items { margin-bottom: 10px; }
        .form-items label { display: inline-block; width: 150px; }
        .form-items input { width: 250px; height: 25px; box-sizing: border-box; }
        button { padding: 6px 15px; font-size: 16px; cursor: pointer; }
        table { margin-top: 30px; border-collapse: collapse; }
        th, td { padding: 8px 15px; text-align: left; }
        th { font-weight: bold; }
    </style>
</head>
<body>
    <form action="" method="post">
        <div class="form-fields">
            <div class="form-items">
                <label for="uid">Enter User ID:</label>
                <input type="text" id="uid" name="uid" required>
            </div>
            <div class="form-items">
                <label for="firstname">Enter First Name:</label>
                <input type="text" id="firstname" name="firstname" required>
            </div>
            <div class="form-items">
                <label for="lastname">Enter Last Name:</label>
                <input type="text" id="lastname" name="lastname" required>
            </div>
            <div class="form-items">
                <label for="address">Enter Address:</label>
                <input type="text" id="address" name="address" required>
            </div>
        </div>
        <button type="submit" name="btnSubmit">Submit</button>
    </form>

    <?php
    $query = "SELECT `user_id`, `firstname`, `lastname`, `address` FROM `users`";
    $stmt = $con->prepare($query);
    if ($stmt && $stmt->execute()) {
        $result = $stmt->get_result();
    ?>
        <table>
            <thead>
                <tr>
                    <th>User ID</th>
                    <th>First Name</th>
                    <th>Last Name</th>
                    <th>Address</th>
                </tr>
            </thead>
            <tbody>
                <?php while ($row = $result->fetch_assoc()) { ?>
                <tr>
                    <td><?php echo htmlspecialchars($row['user_id']); ?></td>
                    <td><?php echo htmlspecialchars($so->decrypt($row['firstname'])); ?></td>
                    <td><?php echo htmlspecialchars($so->decrypt($row['lastname'])); ?></td>
                    <td><?php echo htmlspecialchars($so->decrypt($row['address'])); ?></td>
                </tr>
                <?php } ?>
            </tbody>
        </table>
    <?php
        $stmt->close();
    }
    ?>
</body>
</html>