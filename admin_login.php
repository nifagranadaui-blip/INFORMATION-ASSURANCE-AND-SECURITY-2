<?php
// Security Headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
session_start();

// Database configuration
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_NAME', 'admin_portal');

// Initialize variables
$error = '';
$success = '';
$show_mfa_form = false;
$email_for_mfa = '';

try {
    // Create database connection with error handling
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    
    // Check connection
    if ($conn->connect_error) {
        throw new Exception('Database connection failed: ' . $conn->connect_error);
    }
    
    // Set charset to utf8mb4
    $conn->set_charset('utf8mb4');
    
    // Handle login form submission
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        
        // Check CSRF token
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            $error = 'Invalid CSRF token. Please try again.';
        } else {
            
            // Sanitize input
            $email = sanitize_input($_POST['email'] ?? '');
            $password = $_POST['password'] ?? '';
            
            // Validate email format
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $error = 'Invalid email format.';
            } elseif (empty($password)) {
                $error = 'Password is required.';
            } else {
                
                // Check if this is MFA verification
                if (isset($_POST['mfa_code'])) {
                    $mfa_code = sanitize_input($_POST['mfa_code']);
                    verify_mfa_and_login($conn, $email, $mfa_code);
                } else {
                    // First step: verify credentials
                    authenticate_user($conn, $email, $password);
                }
            }
        }
    }
    
    // Generate CSRF token if not exists
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    
} catch (Exception $e) {
    $error = 'An error occurred: ' . htmlspecialchars($e->getMessage());
    error_log($e->getMessage());
}

/**
 * Sanitize input to prevent XSS attacks
 */
function sanitize_input($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    return $data;
}

/**
 * Authenticate user with credentials
 */
function authenticate_user($conn, $email, $password) {
    global $error, $show_mfa_form, $email_for_mfa;
    
    // Prepared statement to prevent SQL injection
    $stmt = $conn->prepare('SELECT id, email, password_hash, mfa_enabled, mfa_secret FROM admins WHERE email = ? AND is_active = 1');
    
    if (!$stmt) {
        $error = 'Database error. Please try again later.';
        error_log($conn->error);
        return;
    }
    
    // Bind parameters
    $stmt->bind_param('s', $email);
    
    // Execute query
    if (!$stmt->execute()) {
        $error = 'Database error. Please try again later.';
        error_log($stmt->error);
        $stmt->close();
        return;
    }
    
    // Get result
    $result = $stmt->get_result();
    
    if ($result->num_rows !== 1) {
        // Use generic error to prevent email enumeration
        $error = 'Invalid email or password.';
        $stmt->close();
        // Add rate limiting delay
        sleep(2);
        return;
    }
    
    $row = $result->fetch_assoc();
    $stmt->close();
    
    // Verify password
    if (!password_verify($password, $row['password_hash'])) {
        $error = 'Invalid email or password.';
        // Add rate limiting delay
        sleep(2);
        return;
    }
    
    // Check if MFA is enabled
    if ($row['mfa_enabled']) {
        // Store email in session temporarily for MFA verification
        $_SESSION['temp_email'] = $row['email'];
        $_SESSION['temp_user_id'] = $row['id'];
        $_SESSION['mfa_secret'] = $row['mfa_secret'];
        $show_mfa_form = true;
        $email_for_mfa = $row['email'];
    } else {
        // Direct login without MFA
        set_admin_session($row['id'], $row['email']);
        $_SESSION['success'] = 'Login successful! Redirecting...';
        header('Location: dashboard.php');
        exit;
    }
}

/**
 * Verify MFA code and login
 */
function verify_mfa_and_login($conn, $email, $mfa_code) {
    global $error;
    
    // Verify MFA code
    if (!isset($_SESSION['mfa_secret']) || !verify_totp($_SESSION['mfa_secret'], $mfa_code)) {
        $error = 'Invalid MFA code. Please try again.';
        return;
    }
    
    // MFA verified, create session
    if (isset($_SESSION['temp_user_id'])) {
        set_admin_session($_SESSION['temp_user_id'], $email);
        
        // Clear temporary session data
        unset($_SESSION['temp_email']);
        unset($_SESSION['temp_user_id']);
        unset($_SESSION['mfa_secret']);
        
        $_SESSION['success'] = 'Login successful! Redirecting...';
        header('Location: dashboard.php');
        exit;
    }
}

/**
 * Set admin session
 */
function set_admin_session($user_id, $email) {
    global $conn;
    
    // Regenerate session ID for security
    session_regenerate_id(true);
    
    // Set session variables
    $_SESSION['admin_id'] = $user_id;
    $_SESSION['admin_email'] = $email;
    $_SESSION['login_time'] = time();
    $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'];
    
    // Log login activity
    $stmt = $conn->prepare('INSERT INTO login_logs (admin_id, ip_address, user_agent, login_time) VALUES (?, ?, ?, NOW())');
    if ($stmt) {
        $ip = $_SERVER['REMOTE_ADDR'];
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $stmt->bind_param('iss', $user_id, $ip, $user_agent);
        $stmt->execute();
        $stmt->close();
    }
}

/**
 * Verify TOTP (Time-based One-Time Password)
 * Requires: composer require sonata-project/google-authenticator
 */
function verify_totp($secret, $code, $discrepancy = 1) {
    // TOTP verification logic
    // This is a simplified implementation
    // For production, use a library like:
    // https://packagist.org/packages/sonata-project/google-authenticator
    
    $code = (int)$code;
    $time = floor(time() / 30);
    
    for ($i = -$discrepancy; $i <= $discrepancy; $i++) {
        $hash = hash_hmac('sha1', pack('N*', 0) . pack('N*', $time + $i), base32_decode($secret), true);
        $offset = ord($hash[19]) & 0xf;
        $totp = (((ord($hash[$offset]) & 0x7f) << 24) |
                ((ord($hash[$offset + 1]) & 0xff) << 16) |
                ((ord($hash[$offset + 2]) & 0xff) << 8) |
                (ord($hash[$offset + 3]) & 0xff)) % 1000000;
        
        if ($totp === $code) {
            return true;
        }
    }
    
    return false;
}

/**
 * Base32 decode helper
 */
function base32_decode($encoded) {
    $base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $encoded = strtoupper($encoded);
    $bits = '';
    $bitstring = '';
    
    for ($i = 0; $i < strlen($encoded); $i++) {
        $char_value = strpos($base32chars, $encoded[$i]);
        if ($char_value === false) {
            throw new Exception('Invalid base32 character');
        }
        $bits .= str_pad(decbin($char_value), 5, '0', STR_PAD_LEFT);
    }
    
    for ($i = 0; $i + 8 <= strlen($bits); $i += 8) {
        $bitstring .= chr(bindec(substr($bits, $i, 8)));
    }
    
    return $bitstring;
}

// Store variables for use in HTML
$show_mfa_form = $show_mfa_form ?? false;
$email_for_mfa = $email_for_mfa ?? '';
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        
        .container {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
            width: 100%;
            max-width: 400px;
        }
        
        h2 {
            color: #667eea;
            margin-bottom: 30px;
            text-align: center;
            font-size: 24px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 600;
            font-size: 14px;
        }
        
        input {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
            transition: all 0.3s ease;
        }
        
        input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        button {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: opacity 0.3s ease;
        }
        
        button:hover {
            opacity: 0.9;
        }
        
        button:active {
            opacity: 0.8;
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
        
        .info {
            text-align: center;
            margin-top: 20px;
            color: #666;
            font-size: 14px;
        }
        
        .security-info {
            background: #f0f4ff;
            padding: 12px;
            border-radius: 4px;
            margin-top: 20px;
            font-size: 12px;
            color: #555;
            border-left: 4px solid #667eea;
        }
        
        .mfa-message {
            background: #fff3cd;
            padding: 12px;
            border-radius: 4px;
            margin-bottom: 20px;
            font-size: 13px;
            color: #856404;
            border-left: 4px solid #ffc107;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>🔐 Admin Login</h2>
        
        <?php if ($error): ?>
            <div class="error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        
        <?php if ($success): ?>
            <div class="success"><?php echo htmlspecialchars($success); ?></div>
        <?php endif; ?>
        
        <?php if ($show_mfa_form): ?>
            <!-- MFA Verification Form -->
            <div class="mfa-message">
                📱 Multi-Factor Authentication enabled. Please enter your MFA code.
            </div>
            
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <input type="hidden" name="email" value="<?php echo htmlspecialchars($email_for_mfa); ?>">
                
                <div class="form-group">
                    <label>MFA Code (6 digits)</label>
                    <input type="text" name="mfa_code" maxlength="6" pattern="[0-9]{6}" inputmode="numeric" placeholder="000000" required autofocus>
                </div>
                
                <button type="submit">Verify MFA Code</button>
            </form>
        <?php else: ?>
            <!-- Login Form -->
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                
                <div class="form-group">
                    <label for="email">Email Address</label>
                    <input type="email" id="email" name="email" required autocomplete="email" placeholder="admin@example.com">
                </div>
                
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required autocomplete="current-password" placeholder="••••••••">
                </div>
                
                <button type="submit">Login</button>
            </form>
        <?php endif; ?>
        
        <div class="security-info">
            ✓ This is a secure, password-protected area<br>
            ✓ All data is encrypted in transit<br>
            ✓ MFA available for enhanced security
        </div>
        
        <div class="info">
            <p>Admin Portal - Secure Access Only</p>
        </div>
    </div>
</body>
</html>
