<?php
session_start();
require_once '../config/database.php';
require_once '../config/security.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$error = '';
$success = '';
$action = $_GET['action'] ?? 'view';

// Get current user data
try {
    $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch();
    
    // Decrypt data
    $userData = [];
    if ($user['encrypted_data']) {
        $userData = json_decode(Security::decryptData($user['encrypted_data']), true) ?? [];
    }
} catch (PDOException $e) {
    $error = 'Error loading profile';
}

// UPDATE Profile
if ($action === 'edit' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!Security::verifyToken($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid CSRF token';
    } else {
        $first_name = Security::sanitize($_POST['first_name'] ?? '');
        $last_name = Security::sanitize($_POST['last_name'] ?? '');
        $phone = Security::sanitize($_POST['phone'] ?? '');
        $address = Security::sanitize($_POST['address'] ?? '');
        $city = Security::sanitize($_POST['city'] ?? '');
        $new_password = $_POST['new_password'] ?? '';
        
        if (empty($first_name) || empty($last_name)) {
            $error = 'First name and last name are required';
        } else {
            try {
                // Encrypt sensitive data
                $encryptedData = Security::encryptData(json_encode([
                    'phone' => $phone,
                    'address' => $address,
                    'city' => $city
                ]));
                
                if (!empty($new_password)) {
                    // Validate new password
                    $passValidation = Security::validatePassword($new_password);
                    if (!$passValidation['valid']) {
                        $error = $passValidation['message'];
                    } else {
                        $hashedPassword = Security::hashPassword($new_password);
                        $stmt = $pdo->prepare('
                            UPDATE users 
                            SET first_name = ?, last_name = ?, phone = ?, address = ?, city = ?, encrypted_data = ?, password = ?
                            WHERE id = ?
                        ');
                        $stmt->execute([
                            $first_name,
                            $last_name,
                            $phone,
                            $address,
                            $city,
                            $encryptedData,
                            $hashedPassword,
                            $_SESSION['user_id']
                        ]);
                        
                        $success = 'Profile updated successfully with new password!';
                    }
                } else {
                    $stmt = $pdo->prepare('
                        UPDATE users 
                        SET first_name = ?, last_name = ?, phone = ?, address = ?, city = ?, encrypted_data = ?
                        WHERE id = ?
                    ');
                    $stmt->execute([
                        $first_name,
                        $last_name,
                        $phone,
                        $address,
                        $city,
                        $encryptedData,
                        $_SESSION['user_id']
                    ]);
                    
                    $success = 'Profile updated successfully!';
                }
                
                // Refresh user data
                $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
                $stmt->execute([$_SESSION['user_id']]);
                $user = $stmt->fetch();
                $userData = json_decode(Security::decryptData($user['encrypted_data']), true) ?? [];
                $action = 'view';
            } catch (PDOException $e) {
                $error = 'Database error: ' . $e->getMessage();
            }
        }
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Profile</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: Arial, sans-serif;
            background: #f5f5f5;
        }
        
        .navbar {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .navbar a {
            color: white;
            text-decoration: none;
            padding: 8px 16px;
            background: rgba(255, 255, 255, 0.2);
            border-radius: 4px;
            margin-left: 10px;
        }
        
        .navbar a:hover {
            background: rgba(255, 255, 255, 0.3);
        }
        
        .container {
            max-width: 600px;
            margin: 30px auto;
            padding: 0 20px;
        }
        
        .card {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        
        h2 {
            color: #333;
            margin-bottom: 20px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: bold;
        }
        
        input, textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }
        
        input:focus, textarea:focus {
            outline: none;
            border-color: #667eea;
        }
        
        input[disabled] {
            background: #f5f5f5;
        }
        
        .btn {
            padding: 10px 20px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            margin-right: 10px;
        }
        
        .btn:hover {
            background: #764ba2;
        }
        
        .btn-secondary {
            background: #6c757d;
        }
        
        .btn-secondary:hover {
            background: #5a6268;
        }
        
        .error {
            background: #fee;
            color: #c33;
            padding: 12px;
            border-radius: 4px;
            margin-bottom: 20px;
            border-left: 4px solid #c33;
        }
        
        .success {
            background: #efe;
            color: #3c3;
            padding: 12px;
            border-radius: 4px;
            margin-bottom: 20px;
            border-left: 4px solid #3c3;
        }
        
        .info-row {
            display: flex;
            padding: 12px 0;
            border-bottom: 1px solid #eee;
        }
        
        .info-label {
            font-weight: bold;
            width: 150px;
            color: #667eea;
        }
        
        .info-value {
            flex: 1;
            color: #666;
        }
        
        .password-hint {
            font-size: 12px;
            color: #999;
            margin-top: 5px;
        }
    </style>
</head>
<body>
    <div class="navbar">
        <h1>👤 User Profile</h1>
        <div>
            <a href="dashboard.php">Dashboard</a>
            <a href="logout.php">Logout</a>
        </div>
    </div>
    
    <div class="container">
        <div class="card">
            <?php if ($error): ?>
                <div class="error">❌ <?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            
            <?php if ($success): ?>
                <div class="success">✅ <?php echo htmlspecialchars($success); ?></div>
            <?php endif; ?>
            
            <!-- VIEW MODE -->
            <?php if ($action === 'view'): ?>
                <h2>My Profile</h2>
                
                <div class="info-row">
                    <span class="info-label">First Name:</span>
                    <span class="info-value"><?php echo htmlspecialchars($user['first_name']); ?></span>
                </div>
                
                <div class="info-row">
                    <span class="info-label">Last Name:</span>
                    <span class="info-value"><?php echo htmlspecialchars($user['last_name']); ?></span>
                </div>
                
                <div class="info-row">
                    <span class="info-label">Email:</span>
                    <span class="info-value"><?php echo htmlspecialchars($user['email']); ?></span>
                </div>
                
                <div class="info-row">
                    <span class="info-label">Phone:</span>
                    <span class="info-value"><?php echo htmlspecialchars($userData['phone'] ?? 'Not provided'); ?></span>
                </div>
                
                <div class="info-row">
                    <span class="info-label">City:</span>
                    <span class="info-value"><?php echo htmlspecialchars($userData['city'] ?? 'Not provided'); ?></span>
                </div>
                
                <div class="info-row">
                    <span class="info-label">Address:</span>
                    <span class="info-value"><?php echo htmlspecialchars($userData['address'] ?? 'Not provided'); ?></span>
                </div>
                
                <div class="info-row">
                    <span class="info-label">Member Since:</span>
                    <span class="info-value"><?php echo htmlspecialchars(date('M d, Y', strtotime($user['created_at']))); ?></span>
                </div>
                
                <a href="profile.php?action=edit" class="btn">✏️ Edit Profile</a>
                <a href="dashboard.php" class="btn btn-secondary">Back</a>
            
            <!-- EDIT MODE -->
            <?php else: ?>
                <h2>Edit Profile</h2>
                
                <form method="POST" action="">
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                        <div class="form-group">
                            <label>First Name *</label>
                            <input type="text" name="first_name" value="<?php echo htmlspecialchars($user['first_name']); ?>" required>
                        </div>
                        
                        <div class="form-group">
                            <label>Last Name *</label>
                            <input type="text" name="last_name" value="<?php echo htmlspecialchars($user['last_name']); ?>" required>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label>Email (Cannot be changed)</label>
                        <input type="email" value="<?php echo htmlspecialchars($user['email']); ?>" disabled>
                    </div>
                    
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                        <div class="form-group">
                            <label>Phone</label>
                            <input type="text" name="phone" value="<?php echo htmlspecialchars($userData['phone'] ?? ''); ?>">
                        </div>
                        
                        <div class="form-group">
                            <label>City</label>
                            <input type="text" name="city" value="<?php echo htmlspecialchars($userData['city'] ?? ''); ?>">
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label>Address</label>
                        <textarea name="address" rows="3"><?php echo htmlspecialchars($userData['address'] ?? ''); ?></textarea>
                    </div>
                    
                    <div class="form-group">
                        <label>New Password (Leave blank to keep current)</label>
                        <input type="password" name="new_password">
                        <div class="password-hint">Minimum 8 alphanumeric characters</div>
                    </div>
                    
                    <input type="hidden" name="csrf_token" value="<?php echo Security::generateToken(); ?>">
                    
                    <button type="submit" class="btn">Save Changes</button>
                    <a href="profile.php?action=view" class="btn btn-secondary">Cancel</a>
                </form>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
