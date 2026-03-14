<?php
session_start();
require_once '../config/database.php';
require_once '../config/security.php';

if (!isset($_SESSION['admin_id'])) {
    header('Location: login.php');
    exit;
}

$action = $_GET['action'] ?? 'list';
$error = '';
$success = '';

// Add Product
if ($action === 'add' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = Security::sanitize($_POST['name'] ?? '');
    $description = Security::sanitize($_POST['description'] ?? '');
    $price = $_POST['price'] ?? '';
    $quantity = $_POST['quantity'] ?? '';
    
    if (empty($name) || empty($price) || !isset($quantity)) {
        $error = 'All fields required';
    } else {
        try {
            $stmt = $pdo->prepare('INSERT INTO products (name, description, price, quantity) VALUES (?, ?, ?, ?)');
            $stmt->execute([$name, $description, $price, $quantity]);
            $success = 'Product added successfully';
            $action = 'list';
        } catch (PDOException $e) {
            $error = 'Error adding product';
        }
    }
}

// Delete Product
if ($action === 'delete' && isset($_GET['id'])) {
    $pdo->prepare('DELETE FROM products WHERE id = ?')->execute([$_GET['id']]);
    header('Location: products.php');
    exit;
}

// Get Products
$products = $pdo->query('SELECT * FROM products ORDER BY created_at DESC')->fetchAll();
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage Products</title>
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
        }
        
        .container {
            display: flex;
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .sidebar {
            width: 250px;
            background: white;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            min-height: calc(100vh - 70px);
        }
        
        .sidebar a {
            display: block;
            padding: 12px;
            margin-bottom: 10px;
            color: #667eea;
            text-decoration: none;
            border-radius: 4px;
            border-left: 4px solid transparent;
        }
        
        .sidebar a:hover,
        .sidebar a.active {
            background: #f0f0f0;
            border-left-color: #667eea;
        }
        
        .content {
            flex: 1;
            padding: 30px;
        }
        
        h2 {
            color: #333;
            margin-bottom: 20px;
        }
        
        .btn {
            padding: 10px 20px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            margin-bottom: 20px;
        }
        
        .btn:hover {
            background: #764ba2;
        }
        
        .btn-danger {
            background: #dc3545;
        }
        
        .btn-danger:hover {
            background: #c82333;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            border-radius: 4px;
            overflow: hidden;
        }
        
        th {
            background: #667eea;
            color: white;
            padding: 15px;
            text-align: left;
        }
        
        td {
            padding: 15px;
            border-bottom: 1px solid #eee;
        }
        
        tr:hover {
            background: #f9f9f9;
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        label {
            display: block;
            margin-bottom: 5px;
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
        
        .card {
            background: white;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
        }
        
        .error {
            background: #fee;
            color: #c33;
            padding: 12px;
            border-radius: 4px;
            margin-bottom: 20px;
        }
        
        .success {
            background: #efe;
            color: #3c3;
            padding: 12px;
            border-radius: 4px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="navbar">
        <h1>📦 Manage Products</h1>
        <a href="logout.php">Logout</a>
    </div>
    
    <div class="container">
        <div class="sidebar">
            <a href="dashboard.php">📊 Dashboard</a>
            <a href="users.php">👥 Users</a>
            <a href="products.php" class="active">📦 Products</a>
        </div>
        
        <div class="content">
            <?php if ($error): ?>
                <div class="error"><?php echo $error; ?></div>
            <?php endif; ?>
            
            <?php if ($success): ?>
                <div class="success"><?php echo $success; ?></div>
            <?php endif; ?>
            
            <?php if ($action === 'list'): ?>
                <a href="products.php?action=add" class="btn">+ Add New Product</a>
                
                <table>
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Price</th>
                            <th>Quantity</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($products as $product): ?>
                        <tr>
                            <td><?php echo Security::sanitize($product['name']); ?></td>
                            <td>$<?php echo number_format($product['price'], 2); ?></td>
                            <td><?php echo $product['quantity']; ?></td>
                            <td>
                                <a href="products.php?action=delete&id=<?php echo $product['id']; ?>" class="btn btn-danger" onclick="return confirm('Delete product?')">Delete</a>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php else: ?>
                <div class="card">
                    <h2>Add New Product</h2>
                    <form method="POST">
                        <div class="form-group">
                            <label>Product Name</label>
                            <input type="text" name="name" required>
                        </div>
                        <div class="form-group">
                            <label>Description</label>
                            <textarea name="description" rows="4"></textarea>
                        </div>
                        <div class="form-group">
                            <label>Price</label>
                            <input type="number" name="price" step="0.01" required>
                        </div>
                        <div class="form-group">
                            <label>Quantity</label>
                            <input type="number" name="quantity" required>
                        </div>
                        <button type="submit" class="btn">Add Product</button>
                        <a href="products.php" class="btn" style="background: #666;">Cancel</a>
                    </form>
                </div>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
