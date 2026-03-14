<?php
session_start();
require_once '../config/database.php';
require_once '../config/security.php';

if (isset($_SESSION['user_id'])) {
    header('Location: dashboard.php');
    exit;
}

$error = '';
$success = '';
$step = $_GET['step'] ?? 'login';
$user_email = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // STEP 1: Initial Login
    if ($step === 'login') {
        $email = Security::sanitize($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        
        if (empty($email) || empty($password)) {
            $error = 'Email and password required';
        } else {
            try {
            //encryption of email
            $email = Security::sanitize($_POST['email']);

            $encryptedEmail = Security::encrypt($email);

            $stmt = $pdo->prepare("INSERT INTO users (email, password) VALUES (?, ?)");
            $stmt->execute([$encryptedEmail, $hashedPassword]);
                // Prepared statement prevents SQL injection
                $stmt = $pdo->prepare('
                    SELECT id, first_name, last_name, email, password, is_verified, locked_until
                    FROM users 
                    WHERE email = ? LIMIT 1
                ');
                $stmt->execute([$email]);
                $user = $stmt->fetch();
                
                if ($user) {
                    // Check if account is locked
                    if ($user['locked_until'] && strtotime($user['locked_until']) > time()) {
                        $error = 'Account locked. Please try again later.';
                    } else if (!$user['is_verified']) {
                        $error = 'Email not verified. Please check your email.';
                    } else if (Security::verifyPassword($password, $user['password'])) {
                        // Password correct - send OTP
                        $otp = Security::generateOTP();
                        $expiryTime = date('Y-m-d H:i:s', strtotime('+' . Security::OTP_EXPIRY_MINUTES . ' minutes'));
                        
                        // Save OTP to database
                        $stmt = $pdo->prepare('UPDATE users SET otp_code = ?, otp_expiry = ? WHERE id = ?');
                        $stmt->execute([$otp, $expiryTime, $user['id']]);
                        
                        // Send OTP email
                        Security::sendOTPEmail($user['email'], $otp, $user['first_name']);
                        
                        // Reset failed attempts
                        $stmt = $pdo->prepare('UPDATE users SET failed_attempts = 0 WHERE id = ?');
                        $stmt->execute([$user['id']]);
                        
                        $_SESSION['login_email'] = $email;
                        $_SESSION['login_user_id'] = $user['id'];
                        
                        $success = 'Login successful! OTP sent to your email.';
                        $step = 'otp';
                    } else {
                        // Incorrect password - increment failed attempts
                        $stmt = $pdo->prepare('
                            UPDATE users 
                            SET failed_attempts = failed_attempts + 1,
                                locked_until = IF(failed_attempts >= ?, DATE_ADD(NOW(), INTERVAL ? MINUTE), locked_until)
                            WHERE id = ?
                        ');
                        $stmt->execute([
                            Security::MAX_LOGIN_ATTEMPTS - 1,
                            Security::LOCKOUT_DURATION_MINUTES,
                            $user['id']
                        ]);
                        
                        $error = 'Invalid email or password';
                    }
                } else {
                    $error = 'Invalid email or password';
                }
                
                // Log login attempt
                $stmt = $pdo->prepare('
                    INSERT INTO login_logs (user_id, ip_address, user_agent, success)
                    VALUES (?, ?, ?, ?)
                ');
                $stmt->execute([
                    $user['id'] ?? null,
                    Security::getClientIP(),
                    Security::getUserAgent(),
                    ($step === 'otp') ? 1 : 0
                ]);
            } catch (PDOException $e) {
                $error = 'Login failed. Please try again.';
            }
        }
    }
    
    // STEP 2: OTP Verification
    if ($step === 'otp' && isset($_POST['otp'])) {
        $otp = Security::sanitize($_POST['otp'] ?? '');
        $user_id = $_SESSION['login_user_id'] ?? null;
        
        if (!$user_id || empty($otp)) {
            $error = 'Invalid OTP request';
        } else {
            try {
                $stmt = $pdo->prepare('
                    SELECT id, first_name, email 
                    FROM users 
                    WHERE id = ? AND otp_code = ? AND otp_expiry > NOW()
                    LIMIT 1
                ');
                $stmt->execute([$user_id, $otp]);
                $user = $stmt->fetch();
                
                if ($user) {
                    // Clear OTP and set session
                    $stmt = $pdo->prepare('UPDATE users SET otp_code = NULL, otp_expiry = NULL WHERE id = ?');
                    $stmt->execute([$user_id]);
                    
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['user_name'] = $user['first_name'];
                    $_SESSION['user_email'] = $user['email'];
                    $_SESSION['login_time'] = time();
                    
                    unset($_SESSION['login_email']);
                    unset($_SESSION['login_user_id']);
                    
                    header('Location: dashboard.php');
                    exit;
                } else {
                    $error = 'Invalid OTP or OTP expired';
                }
            } catch (PDOException $e) {
                $error = 'OTP verification failed';
            }
        }
    }
}

// Determine step
if (isset($_SESSION['login_user_id'])) {
    $step = 'otp';
}
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Login</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        
        .container {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
            width: 100%;
            max-width: 450px;
        }
        
        h2 {
            color: #667eea;
            margin-bottom: 30px;
            text-align: center;
        }
        
        .progress {
            display: flex;
            justify-content: space-between;
            margin-bottom: 30px;
            gap: 10px;
        }
        
        .progress-step {
            flex: 1;
            height: 4px;
            background: #eee;
            border-radius: 2px;
        }
        
        .progress-step.active,
        .progress-step.completed {
            background: #667eea;
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
        
        input {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
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
        }
        
        button:hover {
            opacity: 0.9;
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
        
        .info a {
            color: #667eea;
            text-decoration: none;
            font-weight: bold;
        }
        
        .otp-input {
            text-align: center;
            font-size: 24px;
            letter-spacing: 10px;
            font-weight: bold;
            font-family: monospace;
        }
        
        .security-badge {
            display: flex;
            align-items: center;
            gap: 8px;
            background: #f0f7ff;
            padding: 12px;
            border-radius: 4px;
            margin-bottom: 20px;
            font-size: 12px;
            color: #555;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>👤 User Login</h2>
        
        <!-- Progress Bar -->
        <div class="progress">
            <div class="progress-step <?php echo ($step === 'login') ? 'active' : 'completed'; ?>"></div>
            <div class="progress-step <?php echo ($step === 'otp') ? 'active' : ''; ?>"></div>
        </div>
        
        <?php if ($error): ?>
            <div class="error">🔴 <?php echo $error; ?></div>
        <?php endif; ?>
        
        <?php if ($success): ?>
            <div class="success">✅ <?php echo $success; ?></div>
        <?php endif; ?>
        
        <!-- STEP 1: Login Form -->
        <?php if ($step === 'login'): ?>
            <div class="security-badge">
                <span>🔒</span>
                <span><strong>Two-Factor Authentication:</strong> Extra security with OTP</span>
            </div>
            
            <form method="POST" action="login.php?step=login">
                <div class="form-group">
                    <label>Email</label>
                    <input type="email" name="email" required>
                </div>
                
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" required>
                </div>
                
                <button type="submit">Login & Receive OTP</button>
            </form>
            
            <div class="info">
                <p>Don't have an account? <a href="register.php">Register here</a></p>
            </div>
        
        <!-- STEP 2: OTP Verification -->
        <?php else: ?>
            <div class="security-badge">
                <span>✉️</span>
                <span>OTP sent to your registered email. Valid for 5 minutes.</span>
            </div>
            
            <form method="POST" action="login.php?step=otp">
                <div class="form-group">
                    <label>Enter OTP Code *</label>
                    <input 
                        type="text" 
                        name="otp" 
                        class="otp-input" 
                        maxlength="6" 
                        placeholder="000000" 
                        required
                        pattern="[0-9]{6}"
                    >
                    <div style="font-size: 12px; color: #666; text-align: center; margin-top: 10px;">
                        Check your email for the 6-digit code
                    </div>
                </div>
                
                <button type="submit">Verify & Login</button>
            </form>
            
            <div class="info">
                <p>Didn't receive OTP? <a href="login.php">Try login again</a></p>
            </div>
        <?php endif; ?>
    </div>
    
    <script>
        // Allow only numbers in OTP field
        document.addEventListener('DOMContentLoaded', function() {
            const otpInput = document.querySelector('.otp-input');
            if (otpInput) {
                otpInput.addEventListener('input', function() {
                    this.value = this.value.replace(/[^0-9]/g, '');
                });
            }
        });
    </script>
</body>
</html>
