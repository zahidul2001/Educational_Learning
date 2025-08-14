const express = require('express');
const path = require('path');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 5000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Static ফাইল সার্ভ করা (public.html ফোল্ডার)
app.use(express.static(path.join(__dirname, '..')));

// Root route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'index.html'));
});

// MySQL Connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'zahidul846hasan',
  database: 'nextgen_learning'
});

db.connect(err => {
  if (err) {
    console.error('❌ MySQL connection failed:', err);
    return;
  }
  console.log('✅ Connected to MySQL database');
});

// Register Endpoint
app.post('/api/auth/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, error: 'Email and password required' });
  }

  try {
    db.query('SELECT email FROM users WHERE email = ?', [email], async (err, results) => {
      if (err) return res.status(500).json({ success: false, error: 'Database error' });

      if (results.length > 0) {
        return res.status(400).json({ success: false, error: 'Email already exists' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      db.query(
        'INSERT INTO users (email, password) VALUES (?, ?)',
        [email, hashedPassword],
        (err, results) => {
          if (err) return res.status(500).json({ success: false, error: 'Registration failed' });

          res.json({
            success: true,
            message: 'User registered successfully',
            userId: results.insertId
          });
        }
      );
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Login Endpoint
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, error: 'Email and password required' });
  }

  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) return res.status(500).json({ success: false, error: 'Database error' });

    if (results.length === 0) {
      return res.status(400).json({ success: false, error: 'Invalid credentials' });
    }

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ success: false, error: 'Invalid credentials' });
    }

    // Create a simple token (base64 encode userId and email)
    const token = Buffer.from(`${user.id}:${user.email}`).toString('base64');
    res.json({ success: true, message: 'Login successful', token, email: user.email });
  });
});

// Start server
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));

// Example usage for registration:
// const hashedPassword = await bcrypt.hash('yourPasswordHere', 10);
// Store hashedPassword in users.password


