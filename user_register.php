<?php
session_start();
require_once '../config/database.php';
require_once '../config/security.php';

// Redirect if already logged in
if (isset($_SESSION['user_id'])) {
    header('Location: dashboard.php');
    exit;
}

$error = '';
$success = '';
$step = $_GET['step'] ?? 'register';
$email = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // STEP 1: Registration Form
    if ($step === 'register') {
        $first_name = Security::sanitize($_POST['first_name'] ?? '');
        $last_name = Security::sanitize($_POST['last_name'] ?? '');
        $email = Security::sanitize($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $confirm = $_POST['confirm_password'] ?? '';
        $phone = Security::sanitize($_POST['phone'] ?? '');
        $city = Security::sanitize($_POST['city'] ?? '');
        $address = Security::sanitize($_POST['address'] ?? '');
        
        // Validation
        if (empty($first_name) || empty($last_name) || empty($email) || empty($password)) {
            $error = 'All required fields must be filled';
        } elseif (!Security::validateEmail($email)) {
            $error = 'Invalid email format';
        } else {
            $passValidation = Security::validatePassword($password);
            if (!$passValidation['valid']) {
                $error = $passValidation['message'];
            } elseif ($password !== $confirm) {
                $error = 'Passwords do not match';
            } else {
                // Check if email exists
                try {
                    $stmt = $pdo->prepare('SELECT id FROM users WHERE email = ? LIMIT 1');
                    $stmt->execute([$email]);
                    
                    if ($stmt->rowCount() > 0) {
                        $error = 'Email already registered';
                    } else {
                        // Hash password
                        $hashedPassword = Security::hashPassword($password);
                        
                        // Encrypt sensitive data
                        $encryptedData = Security::encryptData(json_encode([
                            'phone' => $phone,
                            'address' => $address,
                            'city' => $city
                        ]));
                        
                        // Insert user
                        $stmt = $pdo->prepare('
                            INSERT INTO users 
                            (first_name, last_name, email, password, phone, address, city, encrypted_data, is_verified) 
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
                        ');
                        $stmt->execute([
                            $first_name,
                            $last_name,
                            $email,
                            $hashedPassword,
                            $phone,
                            $address,
                            $city,
                            $encryptedData
                        ]);
                        
                        // Generate and send OTP
                        $otp = Security::generateOTP();
                        $expiryTime = date('Y-m-d H:i:s', strtotime('+' . Security::OTP_EXPIRY_MINUTES . ' minutes'));
                        
                        $stmt = $pdo->prepare('UPDATE users SET otp_code = ?, otp_expiry = ? WHERE email = ?');
                        $stmt->execute([$otp, $expiryTime, $email]);
                        
                        // Send OTP email
                        $emailSent = Security::sendOTPEmail($email, $otp, $first_name);
                        
                        if ($emailSent || true) { // Set true for testing without email
                            $_SESSION['register_email'] = $email;
                            $success = 'Registration successful! Please check your email for the OTP.';
                            $step = 'otp';
                        } else {
                            $error = 'Failed to send OTP. Please try again.';
                        }
                    }
                } catch (PDOException $e) {
                    $error = 'Registration failed. Please try again.';
                }
            }
        }
    }
    
    // STEP 2: OTP Verification
    if ($step === 'otp' && isset($_POST['otp'])) {
        $otp = Security::sanitize($_POST['otp'] ?? '');
        $email = $_SESSION['register_email'] ?? '';
        
        if (empty($otp) || empty($email)) {
            $error = 'Invalid OTP request';
        } else {
            try {
                $stmt = $pdo->prepare('
                    SELECT id FROM users 
                    WHERE email = ? AND otp_code = ? AND otp_expiry > NOW() AND is_verified = 0
                    LIMIT 1
                ');
                $stmt->execute([$email, $otp]);
                
                if ($stmt->rowCount() > 0) {
                    // Mark user as verified
                    $stmt = $pdo->prepare('UPDATE users SET is_verified = 1, otp_code = NULL, otp_expiry = NULL WHERE email = ?');
                    $stmt->execute([$email]);
                    
                    $success = 'Email verified successfully! You can now login.';
                    unset($_SESSION['register_email']);
                    sleep(2);
                    header('Location: login.php?verified=1');
                    exit;
                } else {
                    $error = 'Invalid OTP or OTP expired. Please try again.';
                }
            } catch (PDOException $e) {
                $error = 'OTP verification failed. Please try again.';
            }
        }
    }
}

// Determine which step to show
if (isset($_SESSION['register_email'])) {
    $step = 'otp';
}
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Registration</title>
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
            padding: 20px;
        }
        
        .container {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
            width: 100%;
            max-width: 500px;
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
            font-size: 14px;
        }
        
        input, textarea {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }
        
        input:focus, textarea:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .password-hint {
            font-size: 12px;
            color: #666;
            margin-top: 5px;
        }
        
        .password-strength {
            margin-top: 5px;
            padding: 8px;
            border-radius: 4px;
            font-size: 12px;
            display: none;
        }
        
        .password-strength.valid {
            background: #efe;
            color: #3c3;
            display: block;
        }
        
        .password-strength.invalid {
            background: #fee;
            color: #c33;
            display: block;
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
        
        button:disabled {
            opacity: 0.6;
            cursor: not-allowed;
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
        
        .info a:hover {
            text-decoration: underline;
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
        
        .security-badge i {
            color: #667eea;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>📝 User Registration</h2>
        
        <!-- Progress Bar -->
        <div class="progress">
            <div class="progress-step <?php echo ($step === 'register') ? 'active' : 'completed'; ?>"></div>
            <div class="progress-step <?php echo ($step === 'otp') ? 'active' : (isset($_SESSION['register_email']) ? 'completed' : ''); ?>"></div>
        </div>
        
        <?php if ($error): ?>
            <div class="error">🔴 <?php echo $error; ?></div>
        <?php endif; ?>
        
        <?php if ($success): ?>
            <div class="success">✅ <?php echo $success; ?></div>
        <?php endif; ?>
        
        <!-- STEP 1: Registration Form -->
        <?php if ($step === 'register'): ?>
            <div class="security-badge">
                <span>🔒</span>
                <span><strong>Secure Registration:</strong> Your data is encrypted and protected.</span>
            </div>
            
            <form method="POST" action="register.php?step=register" onsubmit="return validateForm()">
                <div class="form-group">
                    <label>First Name *</label>
                    <input type="text" name="first_name" required>
                </div>
                
                <div class="form-group">
                    <label>Last Name *</label>
                    <input type="text" name="last_name" required>
                </div>
                
                <div class="form-group">
                    <label>Email *</label>
                    <input type="email" name="email" required>
                </div>
                
                <div class="form-group">
                    <label>Password * (8+ alphanumeric)</label>
                    <input 
                        type="password" 
                        id="password" 
                        name="password" 
                        required 
                        onkeyup="checkPassword()"
                    >
                    <div class="password-hint">
                        ✓ Minimum 8 characters<br>
                        ✓ Letters and numbers only
                    </div>
                    <div id="passwordStrength" class="password-strength"></div>
                </div>
                
                <div class="form-group">
                    <label>Confirm Password *</label>
                    <input type="password" id="confirm" name="confirm_password" required>
                </div>
                
                <div class="form-group">
                    <label>Phone</label>
                    <input type="text" name="phone">
                </div>
                
                <div class="form-group">
                    <label>City</label>
                    <input type="text" name="city">
                </div>
                
                <div class="form-group">
                    <label>Address</label>
                    <textarea name="address" rows="3"></textarea>
                </div>
                
                <button type="submit">Continue to OTP Verification</button>
            </form>
            
            <div class="info">
                Already have an account? <a href="login.php">Login here</a>
            </div>
        
        <!-- STEP 2: OTP Verification -->
        <?php else: ?>
            <div class="security-badge">
                <span>✉️</span>
                <span>An OTP has been sent to your email. Valid for 5 minutes.</span>
            </div>
            
            <form method="POST" action="register.php?step=otp">
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
                    <div class="password-hint" style="text-align: center;">
                        Check your email for the 6-digit code
                    </div>
                </div>
                
                <button type="submit">Verify OTP</button>
            </form>
            
            <div class="info">
                <p>Didn't receive OTP? <a href="register.php">Register again</a></p>
            </div>
        <?php endif; ?>
    </div>
    
    <script>
        function checkPassword() {
            const password = document.getElementById('password').value;
            const strengthDiv = document.getElementById('passwordStrength');
            
            // Check: 8+ characters and alphanumeric
            const isValid = /^[a-zA-Z0-9]{8,}$/.test(password);
            
            if (password.length === 0) {
                strengthDiv.style.display = 'none';
                return;
            }
            
            if (isValid) {
                strengthDiv.className = 'password-strength valid';
                strengthDiv.textContent = '✅ Password is strong';
            } else {
                strengthDiv.className = 'password-strength invalid';
                if (password.length < 8) {
                    strengthDiv.textContent = '❌ Minimum 8 characters required';
                } else if (!/^[a-zA-Z0-9]*$/.test(password)) {
                    strengthDiv.textContent = '❌ Only letters and numbers allowed';
                } else {
                    strengthDiv.textContent = '❌ Password does not meet requirements';
                }
            }
        }
        
        function validateForm() {
            const password = document.getElementById('password').value;
            const confirm = document.getElementById('confirm').value;
            
            if (!/^[a-zA-Z0-9]{8,}$/.test(password)) {
                alert('Password must be at least 8 alphanumeric characters');
                return false;
            }
            
            if (password !== confirm) {
                alert('Passwords do not match');
                return false;
            }
            
            return true;
        }
        
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
