<?php
session_start();
require_once '../config/database.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$products = $pdo->query('SELECT * FROM products')->fetchAll();
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Dashboard</title>
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
        
        .navbar a:hover {
            background: rgba(255, 255, 255, 0.3);
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 30px;
        }
        
        h2 {
            color: #333;
            margin-bottom: 30px;
        }
        
        .products {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
        }
        
        .product-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        
        .product-card h3 {
            color: #333;
            margin-bottom: 10px;
        }
        
        .product-card p {
            color: #666;
            margin-bottom: 15px;
            font-size: 14px;
        }
        
        .price {
            font-size: 20px;
            color: #667eea;
            font-weight: bold;
            margin-bottom: 15px;
        }
        
        .btn {
            padding: 10px 20px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        
        .btn:hover {
            background: #764ba2;
        }
    </style>
</head>
<body>
    <div class="navbar">
        <h1>👤 User Dashboard</h1>
        <div>
            <span><?php echo $_SESSION['user_name']; ?></span>
            <a href="logout.php">Logout</a>
        </div>
    </div>
    
    <div class="container">
        <h2>Available Products</h2>
        
        <div class="products">
            <?php foreach ($products as $product): ?>
            <div class="product-card">
                <h3><?php echo htmlspecialchars($product['name']); ?></h3>
                <p><?php echo htmlspecialchars($product['description'] ?? 'No description'); ?></p>
                <div class="price">$<?php echo number_format($product['price'], 2); ?></div>
                <p>In Stock: <?php echo $product['quantity']; ?></p>
            </div>
            <?php endforeach; ?>
        </div>
    </div>
</body>
</html>
