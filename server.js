const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const JWT_SECRET = process.env.JWT_SECRET || "AGRO_COOLER_SUPER_SECRET_JWT_KEY_8899";
const IOT_SECRET_TOKEN = process.env.IOT_SECRET_TOKEN || "AGRO_COOLER_SECURE_KEY_9921";

// --- DATABASE SETUP ---
const dbFile = path.join(__dirname, 'agro_cooler.db');
const db = new sqlite3.Database(dbFile, (err) => {
  if (err) console.error('Database error:', err.message);
  else console.log('Connected to SQLite persistent database.');
});

db.serialize(() => {
  // Users Table (Role-based: farmer, buyer, logistics, admin)
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL
  )`);

  // Products Table
  db.run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    price REAL NOT NULL,
    unit TEXT NOT NULL,
    farmer TEXT NOT NULL,
    category TEXT NOT NULL,
    image TEXT,
    stock INTEGER NOT NULL
  )`);

  // Orders Table
  db.run(`CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    buyerName TEXT NOT NULL,
    phone TEXT NOT NULL,
    address TEXT NOT NULL,
    total REAL NOT NULL,
    status TEXT NOT NULL,
    paymentStatus TEXT DEFAULT 'Pending',
    date TEXT NOT NULL
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    orderId TEXT,
    name TEXT,
    price REAL,
    quantity INTEGER,
    FOREIGN KEY(orderId) REFERENCES orders(id)
  )`);

  // Coolers & Telemetry History Table
  db.run(`CREATE TABLE IF NOT EXISTS coolers (
    deviceId TEXT PRIMARY KEY,
    temperature REAL,
    humidity REAL,
    status TEXT,
    shelfLifeDays INTEGER,
    powerStatus TEXT,
    lastUpdated TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS cooler_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    deviceId TEXT,
    temperature REAL,
    timestamp TEXT
  )`);

  // Seed default admin/farmer/buyer if empty
  db.get("SELECT COUNT(*) as count FROM users", async (err, row) => {
    if (row && row.count === 0) {
      const farmerPassword = await bcrypt.hash('password123', 8);
      const buyerPassword = await bcrypt.hash('shopper123', 8);
      db.run("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)", 
        ['Okafor Farms', 'farmer@agrocooler.com', farmerPassword, 'farmer']);
      db.run("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)", 
        ['Market Shopper', 'shopper@agrocooler.com', buyerPassword, 'buyer']);
    }
  });

  // Seed default products if empty
  db.get("SELECT COUNT(*) as count FROM products", (err, row) => {
    if (row && row.count === 0) {
      const defaultProducts = [
        ['Fresh Organic Tomatoes', 1500, 'basket', 'Okafor Farms', 'Vegetables', 'https://images.unsplash.com/photo-1592924357228-91a4daadcfea?w=500', 120],
        ['Hass Avocados (Grade A)', 3000, 'kg', 'GreenValley Agro', 'Fruits', 'https://images.unsplash.com/photo-1523049673857-eb18f1d7b578?w=500', 50],
        ['Yellow Maize / Corn', 800, 'bag', 'Alheri Cooperatives', 'Grains', 'https://images.unsplash.com/photo-1551754655-cd97e68e27c7?w=500', 500],
        ['Sweet Pineapple Bunch', 2200, 'crate', 'Sunny Orchard', 'Fruits', 'https://images.unsplash.com/photo-1502741126161-b048400d3d18?w=500', 75],
        ['Ginger Tubers (Fresh)', 1800, 'kg', 'Spice Grove', 'Roots', 'https://images.unsplash.com/photo-1506801310323-534be5e7bb0b?w=500', 90],
        ['Pure Local Honey', 4200, 'jar', 'BeeCare Farms', 'Pantry', 'https://images.unsplash.com/photo-1504198453319-5ce911bafcde?w=500', 40]
      ];
      const stmt = db.prepare("INSERT INTO products (name, price, unit, farmer, category, image, stock) VALUES (?, ?, ?, ?, ?, ?, ?)");
      defaultProducts.forEach(p => stmt.run(p));
      stmt.finalize();

      db.run("INSERT OR REPLACE INTO coolers (deviceId, temperature, humidity, status, shelfLifeDays, powerStatus, lastUpdated) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ['AC-8842', 3.8, 85, 'Optimal Cold-Chain Maintained', 16, 'Active (Solar + Grid)', new Date().toLocaleTimeString()]);
    }
  });
});

// --- MIDDLEWARE: Auth & Sanitization ---
function sanitizeInput(str) {
  if (typeof str !== 'string') return str;
  return str.replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function verifyToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).json({ error: 'No token provided.' });
  jwt.verify(token.split(' ')[1], JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Failed to authenticate token.' });
    req.user = decoded;
    next();
  });
}

// --- AUTH ENDPOINTS ---
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password || !role) return res.status(400).json({ error: 'All fields required.' });

  try {
    const sanitizedName = sanitizeInput(name);
    const sanitizedEmail = sanitizeInput(email);
    const sanitizedRole = sanitizeInput(role);
    const hashedPassword = await bcrypt.hash(password, 8);

    db.run("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)", 
      [sanitizedName, sanitizedEmail, hashedPassword, sanitizedRole], function(err) {
      if (err) return res.status(400).json({ error: 'Email already registered or invalid input.' });

      const token = jwt.sign({ id: this.lastID, email: sanitizedEmail, role: sanitizedRole }, JWT_SECRET, { expiresIn: 86400 });
      res.status(201).json({
        success: true,
        message: 'User registered successfully.',
        token,
        user: { id: this.lastID, name: sanitizedName, email: sanitizedEmail, role: sanitizedRole }
      });
    });
  } catch (err) {
    res.status(500).json({ error: 'Server registration error.' });
  }
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'User not found.' });

    const passwordIsValid = await bcrypt.compare(password, user.password);
    if (!passwordIsValid) return res.status(401).json({ error: 'Invalid password.' });

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: 86400 });
    res.json({ success: true, token, user: { name: user.name, email: user.email, role: user.role } });
  });
});

app.get('/api/auth/me', verifyToken, (req, res) => {
  db.get("SELECT id, name, email, role FROM users WHERE id = ?", [req.user.id], (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'User not found.' });
    res.json({ success: true, user });
  });
});

// --- PRODUCT ENDPOINTS ---
app.get('/api/products', (req, res) => {
  db.all("SELECT * FROM products ORDER BY id DESC", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/products', verifyToken, (req, res) => {
  if (req.user.role !== 'farmer' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized: Only farmers can list products.' });
  }

  let { name, price, unit, farmer, category, image, stock } = req.body;
  const cleanName = sanitizeInput(name);
  const cleanFarmer = sanitizeInput(farmer);
  const cleanCategory = sanitizeInput(category);
  const cleanUnit = sanitizeInput(unit);
  const cleanImage = sanitizeInput(image) || 'https://images.unsplash.com/photo-1488459716790-a3db5f5efc7ec?w=500';

  const query = `INSERT INTO products (name, price, unit, farmer, category, image, stock) VALUES (?, ?, ?, ?, ?, ?, ?)`;
  db.run(query, [cleanName, Number(price), cleanUnit, cleanFarmer, cleanCategory, cleanImage, Number(stock)], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    const newProduct = { id: this.lastID, name: cleanName, price, unit: cleanUnit, farmer: cleanFarmer, category: cleanCategory, image: cleanImage, stock };
    io.emit('product_added', newProduct);
    res.status(201).json({ success: true, product: newProduct });
  });
});

app.patch('/api/products/:id/stock', verifyToken, (req, res) => {
  if (req.user.role !== 'farmer' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized: Only farmers can update stock.' });
  }

  const productId = Number(req.params.id);
  const newStock = Number(req.body.stock);
  if (!Number.isInteger(productId) || Number.isNaN(newStock) || newStock < 0) {
    return res.status(400).json({ error: 'Invalid product ID or stock value.' });
  }

  db.get('SELECT farmer FROM products WHERE id = ?', [productId], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ error: 'Product not found.' });

    db.get('SELECT name FROM users WHERE id = ?', [req.user.id], (err, user) => {
      if (err) return res.status(500).json({ error: err.message });
      const farmerName = user?.name?.toLowerCase();
      if (req.user.role !== 'admin' && row.farmer.toLowerCase() !== farmerName) {
        return res.status(403).json({ error: 'Unauthorized: You may only update your own product stock.' });
      }

      db.run('UPDATE products SET stock = ? WHERE id = ?', [newStock, productId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        io.emit('product_stock_updated', { id: productId, stock: newStock });
        res.json({ success: true, id: productId, stock: newStock });
      });
    });
  });
});

// --- ORDER & PAYMENT SIMULATION ENDPOINTS ---
app.get('/api/orders', (req, res) => {
  db.all("SELECT * FROM orders ORDER BY date DESC", [], async (err, orders) => {
    if (err) return res.status(500).json({ error: err.message });
    const fullOrders = await Promise.all(orders.map(async (order) => {
      return new Promise((resolve) => {
        db.all("SELECT name, price, quantity FROM order_items WHERE orderId = ?", [order.id], (err, items) => {
          resolve({ ...order, items: items || [] });
        });
      });
    }));
    res.json(fullOrders);
  });
});

app.post('/api/orders', (req, res) => {
  const { items, buyerName, address, phone, paymentRef } = req.body;
  if (!items || !items.length || !buyerName) return res.status(400).json({ error: 'Invalid order payload.' });

  const orderId = 'ORD-' + Math.floor(100000 + Math.random() * 900000);
  const total = items.reduce((sum, i) => sum + (Number(i.price) * Number(i.quantity)), 0);
  const dateStr = new Date().toLocaleDateString();
  const paymentStatus = paymentRef ? 'Paid (Verified via Paystack)' : 'Cash on Delivery / Pending';
  const status = 'Confirmed - Logistics Dispatched';

  const validateAndUpdateStock = (item) => {
    return new Promise((resolve, reject) => {
      if (!item.id || !item.quantity || item.quantity <= 0) {
        return reject(new Error('Invalid item quantity.'));
      }

      db.get("SELECT stock FROM products WHERE id = ?", [item.id], (err, row) => {
        if (err || !row) return reject(new Error('Product not found.'));
        if (row.stock < item.quantity) return reject(new Error(`Insufficient stock for ${item.name}.`));

        db.run("UPDATE products SET stock = stock - ? WHERE id = ? AND stock >= ?", [item.quantity, item.id, item.quantity], function(err) {
          if (err || this.changes === 0) return reject(new Error(`Unable to reserve stock for ${item.name}.`));
          resolve();
        });
      });
    });
  };

  db.serialize(async () => {
    db.run("BEGIN TRANSACTION");
    try {
      for (const item of items) {
        await validateAndUpdateStock(item);
      }

      db.run("INSERT INTO orders (id, buyerName, phone, address, total, status, paymentStatus, date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [orderId, sanitizeInput(buyerName), sanitizeInput(phone), sanitizeInput(address), total, status, paymentStatus, dateStr]);

      const stmt = db.prepare("INSERT INTO order_items (orderId, name, price, quantity) VALUES (?, ?, ?, ?)");
      items.forEach(item => {
        stmt.run([orderId, sanitizeInput(item.name), Number(item.price), Number(item.quantity)]);
      });
      stmt.finalize();

      db.run("COMMIT", (err) => {
        if (err) {
          db.run("ROLLBACK");
          return res.status(500).json({ error: 'Failed to process order.' });
        }
        const newOrder = { id: orderId, items, buyerName, address, phone, total, status, paymentStatus, date: dateStr };
        io.emit('order_created', newOrder);
        res.status(201).json({ success: true, order: newOrder });
      });
    } catch (error) {
      db.run("ROLLBACK");
      res.status(400).json({ error: error.message });
    }
  });
});

// --- SECURE IOT ENDPOINT & ANALYTICS HISTORY ---
app.post('/api/iot/cooler', (req, res) => {
  const deviceToken = req.headers['x-device-token'];
  if (!deviceToken || deviceToken !== IOT_SECRET_TOKEN) {
    return res.status(401).json({ error: 'Unauthorized IoT device token.' });
  }

  const { deviceId, temperature, humidity } = req.body;
  const targetId = sanitizeInput(deviceId) || 'AC-8842';
  const temp = parseFloat(temperature);
  const hum = humidity ? parseFloat(humidity) : 80;
  const lastUpdated = new Date().toLocaleTimeString();
  const timestampIso = new Date().toISOString();

  let status = 'Optimal Cold-Chain Maintained';
  let shelfLifeDays = 16;
  if (temp > 10) {
    status = 'CRITICAL WARNING: Temperature Rising! Spoilage Imminent!';
    shelfLifeDays = Math.max(1, Math.floor(16 - (temp - 4) * 1.8));
  } else if (temp > 6) {
    status = 'CAUTION: Warm Threshold Reached';
    shelfLifeDays = 7;
  }

  db.serialize(() => {
    db.run(`INSERT OR REPLACE INTO coolers (deviceId, temperature, humidity, status, shelfLifeDays, powerStatus, lastUpdated) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [targetId, temp, hum, status, shelfLifeDays, 'Active', lastUpdated]);
    
    db.run(`INSERT INTO cooler_logs (deviceId, temperature, timestamp) VALUES (?, ?, ?)`, [targetId, temp, timestampIso]);
  });

  const coolerPayload = { deviceId: targetId, temperature: temp, humidity: hum, status, shelfLifeDays, powerStatus: 'Active', lastUpdated };
  io.emit('iot_update', coolerPayload);
  res.json({ success: true, status, shelfLifeDays });
});

app.get('/api/iot/status', (req, res) => {
  db.get("SELECT * FROM coolers LIMIT 1", [], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(row || { deviceId: 'AC-8842', temperature: 3.8, humidity: 85, status: 'Optimal', shelfLifeDays: 16 });
  });
});

app.get('/api/iot/history', (req, res) => {
  db.all("SELECT temperature, timestamp FROM cooler_logs ORDER BY id DESC LIMIT 15", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows.reverse());
  });
});

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
server.listen(PORT, HOST, () => {
  console.log(`Agro-Cooler enterprise server running on port ${PORT}`);
});