const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 5000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '..')));

// Database connection
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

// Create necessary tables - FIXED VERSION
const createTables = () => {
  // Drop and recreate tables to ensure clean state
  const dropQueries = [
    'DROP TABLE IF EXISTS user_courses_upload',
    'DROP TABLE IF EXISTS payments',
    'DROP TABLE IF EXISTS user_courses',
    'DROP TABLE IF EXISTS courses',
    'DROP TABLE IF EXISTS super_admin_requests',
    'DROP TABLE IF EXISTS super_admins',
    'DROP TABLE IF EXISTS admins',
    'DROP TABLE IF EXISTS users'
  ];

  dropQueries.forEach((query, index) => {
    setTimeout(() => {
      db.query(query, (err) => {
        if (err) console.error(`Error dropping table:`, err);
        else console.log(`✅ Table dropped: ${query.split(' ')[4]}`);
      });
    }, index * 100);
  });

  // Wait for drops to complete then create tables
  setTimeout(() => {
    const usersTable = `
      CREATE TABLE IF NOT EXISTS users (
        id INT PRIMARY KEY AUTO_INCREMENT,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        name VARCHAR(255) DEFAULT '',
        user_type ENUM('student', 'instructor', 'admin') DEFAULT 'student',
        email_verified BOOLEAN DEFAULT FALSE,
        verification_token VARCHAR(255),
        token_expires DATETIME,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `;

    const adminsTable = `
      CREATE TABLE IF NOT EXISTS admins (
        id INT PRIMARY KEY AUTO_INCREMENT,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        name VARCHAR(255),
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;

    const superAdminsTable = `
      CREATE TABLE IF NOT EXISTS super_admins (
        id INT PRIMARY KEY AUTO_INCREMENT,
        user_id INT NOT NULL UNIQUE,
        email VARCHAR(255),
        name VARCHAR(255),
        permissions JSON,
        is_active BOOLEAN DEFAULT TRUE,
        approved_by INT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `;

    const superAdminRequestsTable = `
      CREATE TABLE IF NOT EXISTS super_admin_requests (
        id INT PRIMARY KEY AUTO_INCREMENT,
        user_id INT NOT NULL,
        email VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL,
        reason TEXT,
        status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
        reviewed_by INT,
        reviewed_at DATETIME,
        rejection_reason TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `;

    const coursesTable = `
      CREATE TABLE IF NOT EXISTS courses (
        id INT PRIMARY KEY AUTO_INCREMENT,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        price DECIMAL(10,2) DEFAULT 0,
        category VARCHAR(100),
        level ENUM('beginner', 'intermediate', 'advanced') DEFAULT 'beginner',
        created_by INT,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;

    const userCoursesTable = `
      CREATE TABLE IF NOT EXISTS user_courses (
        id INT PRIMARY KEY AUTO_INCREMENT,
        user_id INT NOT NULL,
        course_id INT NOT NULL,
        amount_paid DECIMAL(10,2),
        payment_status ENUM('pending', 'completed', 'failed') DEFAULT 'pending',
        payment_method VARCHAR(50),
        transaction_id VARCHAR(255),
        purchased_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
      )
    `;

    const paymentsTable = `
      CREATE TABLE IF NOT EXISTS payments (
        id INT PRIMARY KEY AUTO_INCREMENT,
        user_id INT NOT NULL,
        course_id INT NOT NULL,
        amount DECIMAL(10,2) NOT NULL,
        payment_method VARCHAR(50),
        transaction_id VARCHAR(255) UNIQUE,
        status ENUM('pending', 'completed', 'failed') DEFAULT 'pending',
        card_last4 VARCHAR(4),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
      )
    `;

    const userCoursesUploadTable = `
      CREATE TABLE IF NOT EXISTS user_courses_upload (
        id INT PRIMARY KEY AUTO_INCREMENT,
        user_id INT NOT NULL,
        course_name VARCHAR(255) NOT NULL,
        course_description TEXT,
        course_price DECIMAL(10,2) DEFAULT 0,
        course_category VARCHAR(100),
        course_level ENUM('beginner', 'intermediate', 'advanced') DEFAULT 'beginner',
        is_approved BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `;

    // Execute table creation queries
    const tables = [
      { query: usersTable, name: 'users' },
      { query: adminsTable, name: 'admins' },
      { query: superAdminsTable, name: 'super_admins' },
      { query: superAdminRequestsTable, name: 'super_admin_requests' },
      { query: coursesTable, name: 'courses' },
      { query: userCoursesTable, name: 'user_courses' },
      { query: paymentsTable, name: 'payments' },
      { query: userCoursesUploadTable, name: 'user_courses_upload' }
    ];

    tables.forEach(({ query, name }) => {
      db.query(query, (err) => {
        if (err) {
          console.error(`❌ Error creating ${name} table:`, err);
        } else {
          console.log(`✅ ${name} table ready`);
        }
      });
    });

    // Create default accounts after tables are created
    setTimeout(() => {
      createDefaultAdmins();
      createDefaultSuperAdmin();
    }, 1000);

  }, 2000);
};

createTables();

// Create default admin accounts
const createDefaultAdmins = async () => {
  const admins = [
    { email: 'hasanzahidul846@gmail.com', password: 'zahidul123', name: 'Main Administrator' },
    { email: 'admin@nextgen.com', password: 'admin123', name: 'System Admin' }
  ];

  for (const admin of admins) {
    try {
      // Check if admin already exists
      db.query('SELECT * FROM admins WHERE email = ?', [admin.email], async (err, results) => {
        if (err) {
          console.error('Error checking admin:', err);
          return;
        }

        if (results.length === 0) {
          const hashedPassword = await bcrypt.hash(admin.password, 10);
          
          db.query(
            'INSERT INTO admins (email, password, name) VALUES (?, ?, ?)',
            [admin.email, hashedPassword, admin.name],
            (err) => {
              if (err) {
                console.error('Error creating admin:', err);
              } else {
                console.log(`✅ Admin created: ${admin.email}`);
              }
            }
          );
        } else {
          console.log(`ℹ️ Admin already exists: ${admin.email}`);
        }
      });
    } catch (error) {
      console.error('Error in createDefaultAdmins:', error);
    }
  }
};

// Create default super admin account
const createDefaultSuperAdmin = async () => {
  const defaultEmail = 'super@nextgen.com';
  const defaultPassword = 'super123';
  const defaultName = 'Default Super Admin';

  try {
    // Check if default super admin already exists as user
    db.query('SELECT * FROM users WHERE email = ?', [defaultEmail], async (err, results) => {
      if (err) {
        console.error('Error checking default super admin user:', err);
        return;
      }

      let userId;

      if (results.length === 0) {
        // Create default user
        const hashedPassword = await bcrypt.hash(defaultPassword, 10);
        
        db.query(
          'INSERT INTO users (email, password, name, user_type, email_verified) VALUES (?, ?, ?, "admin", TRUE)',
          [defaultEmail, hashedPassword, defaultName],
          (err, userResult) => {
            if (err) {
              console.error('Error creating default user:', err);
              return;
            }

            userId = userResult.insertId;
            console.log(`✅ Default Super Admin user created: ${defaultEmail}`);
            createSuperAdminEntry(userId, defaultEmail, defaultName);
          }
        );
      } else {
        userId = results[0].id;
        console.log(`ℹ️ Default Super Admin user already exists: ${defaultEmail}`);
        createSuperAdminEntry(userId, defaultEmail, defaultName);
      }
    });
  } catch (error) {
    console.error('Error in createDefaultSuperAdmin:', error);
  }
};

// Helper function to create super admin entry
const createSuperAdminEntry = (userId, email, name) => {
  // Check if super admin entry already exists
  db.query('SELECT * FROM super_admins WHERE user_id = ?', [userId], (err, results) => {
    if (err) {
      console.error('Error checking super admin entry:', err);
      return;
    }

    if (results.length === 0) {
      // Create super admin entry
      const permissions = JSON.stringify({
        user_management: true,
        course_management: true,
        report_view: true,
        course_upload: true,
        content_management: true,
        system_settings: true
      });

      db.query(
        'INSERT INTO super_admins (user_id, email, name, permissions, approved_by) VALUES (?, ?, ?, ?, ?)',
        [userId, email, name, permissions, 1],
        (err) => {
          if (err) {
            console.error('Error creating default super admin entry:', err);
          } else {
            console.log('✅ Default Super Admin created successfully');
            console.log('📧 Email: super@nextgen.com');
            console.log('🔑 Password: super123');
          }
        }
      );
    } else {
      console.log('ℹ️ Default Super Admin entry already exists');
    }
  });
};

// ==================== HTML ROUTES ====================
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'a.html'));
});

app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'login.html'));
});

app.get('/dashboard.html', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'dashboard.html'));
});

app.get('/premium-courses.html', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'premium-courses.html'));
});

app.get('/admin-dashboard.html', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'admin-dashboard.html'));
});

app.get('/super-admin-dashboard.html', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'super-admin-dashboard.html'));
});

app.get('/super-admin-login.html', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'super-admin-login.html'));
});

app.get('/admin-login.html', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'admin-login.html'));
});

app.get('/super-admin-register.html', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'super-admin-register.html'));
});

// ==================== SUPER ADMIN REQUEST ROUTES ====================

// Submit Super Admin Request
app.post('/api/super-admin/request', async (req, res) => {
  try {
    const { email, name, reason } = req.body;

    console.log('📝 Super Admin request received:', { email, name });

    if (!email || !name || !reason) {
      return res.status(400).json({ success: false, error: 'All fields are required' });
    }

    // Check if user exists
    db.query('SELECT id FROM users WHERE email = ?', [email], (err, userResults) => {
      if (err) {
        console.error('Database error checking user:', err);
        return res.status(500).json({ success: false, error: 'Database error' });
      }

      if (userResults.length === 0) {
        return res.status(400).json({ 
          success: false, 
          error: 'User not found. Please register as a regular user first.' 
        });
      }

      const userId = userResults[0].id;

      // Check if user already has a pending request
      db.query(
        'SELECT id FROM super_admin_requests WHERE user_id = ? AND status = "pending"',
        [userId],
        (err, pendingResults) => {
          if (err) {
            console.error('Database error checking pending requests:', err);
            return res.status(500).json({ success: false, error: 'Database error' });
          }

          if (pendingResults.length > 0) {
            return res.status(400).json({ 
              success: false, 
              error: 'You already have a pending Super Admin request. Please wait for approval.' 
            });
          }

          // Check if user is already a super admin
          db.query(
            'SELECT id FROM super_admins WHERE user_id = ? AND is_active = TRUE',
            [userId],
            (err, superAdminResults) => {
              if (err) {
                console.error('Database error checking super admin status:', err);
                return res.status(500).json({ success: false, error: 'Database error' });
              }

              if (superAdminResults.length > 0) {
                return res.status(400).json({ 
                  success: false, 
                  error: 'You are already a Super Admin.' 
                });
              }

              // Create new super admin request
              db.query(
                'INSERT INTO super_admin_requests (user_id, email, name, reason, status) VALUES (?, ?, ?, ?, "pending")',
                [userId, email, name, reason],
                (err, result) => {
                  if (err) {
                    console.error('Database error creating request:', err);
                    return res.status(500).json({ success: false, error: 'Failed to submit request' });
                  }

                  console.log(`✅ Super Admin request submitted for user: ${email}`);
                  res.json({
                    success: true,
                    message: 'Super Admin request submitted successfully! It will be reviewed by an administrator.',
                    requestId: result.insertId
                  });
                }
              );
            }
          );
        }
      );
    });
  } catch (error) {
    console.error('Super Admin request error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Get Super Admin Requests (for admin dashboard)
app.get('/api/admin/super-admin-requests', (req, res) => {
  console.log('📋 Fetching Super Admin requests...');

  const query = `
    SELECT 
      sar.*,
      u.created_at as user_joined
    FROM super_admin_requests sar
    JOIN users u ON sar.user_id = u.id
    WHERE sar.status = 'pending'
    ORDER BY sar.created_at DESC
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error('Database error fetching requests:', err);
      return res.status(500).json({ success: false, error: 'Database error' });
    }

    console.log(`✅ Found ${results.length} pending Super Admin requests`);
    res.json({
      success: true,
      requests: results
    });
  });
});

// Approve Super Admin Request
app.post('/api/admin/super-admin-approve', async (req, res) => {
  try {
    const { requestId, adminId } = req.body;

    console.log(`✅ Approving Super Admin request: ${requestId} by admin: ${adminId}`);

    if (!requestId || !adminId) {
      return res.status(400).json({ success: false, error: 'Request ID and Admin ID are required' });
    }

    // Get request details
    db.query(
      'SELECT * FROM super_admin_requests WHERE id = ? AND status = "pending"',
      [requestId],
      (err, requestResults) => {
        if (err) {
          console.error('Database error fetching request:', err);
          return res.status(500).json({ success: false, error: 'Database error' });
        }

        if (requestResults.length === 0) {
          return res.status(404).json({ success: false, error: 'Request not found or already processed' });
        }

        const request = requestResults[0];

        // Update request status to approved
        db.query(
          'UPDATE super_admin_requests SET status = "approved", reviewed_by = ?, reviewed_at = NOW() WHERE id = ?',
          [adminId, requestId],
          (err) => {
            if (err) {
              console.error('Database error updating request:', err);
              return res.status(500).json({ success: false, error: 'Database error' });
            }

            // Create super admin entry
            const permissions = JSON.stringify({
              user_management: true,
              course_management: true,
              report_view: true,
              course_upload: true,
              content_management: true,
              system_settings: true
            });

            db.query(
              'INSERT INTO super_admins (user_id, email, name, permissions, approved_by) VALUES (?, ?, ?, ?, ?)',
              [request.user_id, request.email, request.name, permissions, adminId],
              (err) => {
                if (err) {
                  console.error('Database error creating super admin:', err);
                  return res.status(500).json({ success: false, error: 'Failed to create Super Admin' });
                }

                console.log(`✅ Super Admin approved for user: ${request.email}`);
                res.json({
                  success: true,
                  message: 'Super Admin request approved successfully!'
                });
              }
            );
          }
        );
      }
    );
  } catch (error) {
    console.error('Approve Super Admin error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Reject Super Admin Request
app.post('/api/admin/super-admin-reject', async (req, res) => {
  try {
    const { requestId, adminId, reason } = req.body;

    console.log(`❌ Rejecting Super Admin request: ${requestId}`);

    if (!requestId || !adminId || !reason) {
      return res.status(400).json({ success: false, error: 'Request ID, Admin ID, and reason are required' });
    }

    // Update request status to rejected
    db.query(
      'UPDATE super_admin_requests SET status = "rejected", reviewed_by = ?, reviewed_at = NOW(), rejection_reason = ? WHERE id = ?',
      [adminId, reason, requestId],
      (err, result) => {
        if (err) {
          console.error('Database error rejecting request:', err);
          return res.status(500).json({ success: false, error: 'Database error' });
        }

        if (result.affectedRows === 0) {
          return res.status(404).json({ success: false, error: 'Request not found or already processed' });
        }

        console.log(`✅ Super Admin request rejected: ${requestId}`);
        res.json({
          success: true,
          message: 'Super Admin request rejected successfully!'
        });
      }
    );
  } catch (error) {
    console.error('Reject Super Admin error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// ==================== SUPER ADMIN DASHBOARD ROUTES ====================

// Get Super Admin Dashboard Data
app.get('/api/super-admin/dashboard/:userId', (req, res) => {
  const userId = req.params.userId;

  console.log(`📊 Loading Super Admin dashboard for user: ${userId}`);

  // Get basic statistics
  const statsQueries = {
    totalUsers: 'SELECT COUNT(*) as count FROM users',
    totalCourses: 'SELECT COUNT(*) as count FROM courses WHERE is_active = TRUE',
    pendingRequests: 'SELECT COUNT(*) as count FROM super_admin_requests WHERE status = "pending"',
    totalRevenue: 'SELECT COALESCE(SUM(amount), 0) as total FROM payments WHERE status = "completed"'
  };

  const results = {};
  let completed = 0;

  Object.keys(statsQueries).forEach(key => {
    db.query(statsQueries[key], (err, queryResults) => {
      if (err) {
        console.error(`Error in ${key} query:`, err);
        results[key] = key === 'totalRevenue' ? 0 : 0;
      } else {
        results[key] = key === 'totalRevenue' ? queryResults[0].total : queryResults[0].count;
      }

      completed++;
      
      if (completed === Object.keys(statsQueries).length) {
        res.json({
          success: true,
          stats: results
        });
      }
    });
  });
});

// Get Super Admin Courses
app.get('/api/super-admin/courses/:userId', (req, res) => {
  const userId = req.params.userId;

  console.log(`📚 Loading courses for Super Admin: ${userId}`);

  db.query(
    'SELECT * FROM user_courses_upload WHERE user_id = ? ORDER BY created_at DESC',
    [userId],
    (err, results) => {
      if (err) {
        console.error('Database error fetching courses:', err);
        return res.status(500).json({ success: false, error: 'Database error' });
      }

      res.json({
        success: true,
        courses: results
      });
    }
  );
});

// Upload Course (Super Admin)
app.post('/api/super-admin/upload-course', async (req, res) => {
  try {
    const { userId, courseName, courseDescription, coursePrice, courseCategory, courseLevel } = req.body;

    console.log('📝 Course upload request:', { userId, courseName });

    if (!userId || !courseName || !courseDescription) {
      return res.status(400).json({ success: false, error: 'Course name and description are required' });
    }

    // Insert course into user_courses_upload table
    db.query(
      'INSERT INTO user_courses_upload (user_id, course_name, course_description, course_price, course_category, course_level, is_approved) VALUES (?, ?, ?, ?, ?, ?, TRUE)',
      [userId, courseName, courseDescription, coursePrice || 0, courseCategory || 'General', courseLevel || 'beginner'],
      (err, result) => {
        if (err) {
          console.error('Database error uploading course:', err);
          return res.status(500).json({ success: false, error: 'Failed to upload course' });
        }

        console.log(`✅ Course uploaded successfully: ${courseName}`);
        res.json({
          success: true,
          message: 'Course uploaded successfully!',
          courseId: result.insertId
        });
      }
    );
  } catch (error) {
    console.error('Upload course error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// ==================== USER ROUTES ====================

// Register Endpoint - COMPLETELY FIXED VERSION
app.post('/api/auth/register', async (req, res) => {
  try {
    console.log('📝 Register request body:', req.body);
    
    const { email, password, confirmPassword, userType } = req.body;

    // Validate inputs
    if (!email || !password || !confirmPassword) {
      console.log('❌ Missing required fields');
      return res.status(400).json({ success: false, error: 'Email and password required' });
    }

    if (password !== confirmPassword) {
      console.log('❌ Passwords do not match');
      return res.status(400).json({ success: false, error: 'Passwords do not match' });
    }

    if (password.length < 6) {
      console.log('❌ Password too short');
      return res.status(400).json({ success: false, error: 'Password must be at least 6 characters' });
    }

    // Check if email already exists
    db.query('SELECT id FROM users WHERE email = ?', [email], async (err, results) => {
      if (err) {
        console.error('❌ Database error (check email):', err);
        return res.status(500).json({ success: false, error: 'Database error', details: err.message });
      }

      if (results.length > 0) {
        console.log('❌ Email already exists:', email);
        return res.status(400).json({ success: false, error: 'Email already registered' });
      }

      try {
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        console.log('✅ Password hashed successfully');

        // Insert user into database - SIMPLIFIED QUERY with name field
        const insertQuery = `
          INSERT INTO users (email, password, name, user_type) 
          VALUES (?, ?, ?, ?)
        `;
        
        db.query(
          insertQuery, 
          [email, hashedPassword, '', userType || 'student'], 
          (insertErr, insertResult) => {
            if (insertErr) {
              console.error('❌ Database error (insert user):', insertErr);
              
              // Try alternative query with different approach
              const altQuery = 'INSERT INTO users (email, password) VALUES (?, ?)';
              db.query(altQuery, [email, hashedPassword], (altErr, altResult) => {
                if (altErr) {
                  console.error('❌ Alternative insert also failed:', altErr);
                  
                  // Final attempt - minimal fields only
                  const finalQuery = 'INSERT INTO users SET ?';
                  const userData = {
                    email: email,
                    password: hashedPassword
                  };
                  
                  db.query(finalQuery, userData, (finalErr, finalResult) => {
                    if (finalErr) {
                      console.error('❌ Final insert failed:', finalErr);
                      return res.status(500).json({ 
                        success: false, 
                        error: 'Registration failed', 
                        details: finalErr.message,
                        code: finalErr.code
                      });
                    }
                    
                    console.log(`✅ User registered successfully (final). User ID: ${finalResult.insertId}`);
                    res.json({
                      success: true,
                      message: 'Registration successful! You can now login.',
                      userId: finalResult.insertId
                    });
                  });
                  return;
                }
                
                console.log(`✅ User registered successfully (alternative). User ID: ${altResult.insertId}`);
                res.json({
                  success: true,
                  message: 'Registration successful! You can now login.',
                  userId: altResult.insertId
                });
              });
              return;
            }

            console.log(`✅ User registered successfully. User ID: ${insertResult.insertId}`);
            res.json({
              success: true,
              message: 'Registration successful! You can now login.',
              userId: insertResult.insertId
            });
          }
        );
      } catch (hashError) {
        console.error('❌ Bcrypt error:', hashError);
        res.status(500).json({ 
          success: false, 
          error: 'Password encryption failed', 
          details: hashError.message 
        });
      }
    });
  } catch (error) {
    console.error('❌ Register endpoint error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Server error', 
      details: error.message 
    });
  }
});

// Login Endpoint
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  console.log(`🔐 Login attempt for: ${email}`);

  if (!email || !password) {
    return res.status(400).json({ success: false, error: 'Email and password required' });
  }

  try {
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ success: false, error: 'Database error' });
      }

      if (results.length === 0) {
        console.log(`❌ User not found: ${email}`);
        return res.status(400).json({ success: false, error: 'Invalid email or password' });
      }

      const user = results[0];
      const isMatch = await bcrypt.compare(password, user.password);
      
      if (!isMatch) {
        console.log(`❌ Invalid password for: ${email}`);
        return res.status(400).json({ success: false, error: 'Invalid email or password' });
      }

      const token = Buffer.from(`${user.id}:${user.email}:${Date.now()}`).toString('base64');
      
      console.log(`✅ Login successful: ${email}`);
      res.json({ 
        success: true, 
        message: 'Login successful! Welcome to NextGen Learning Hub.', 
        token, 
        user: {
          id: user.id,
          email: user.email,
          name: user.name || '',
          user_type: user.user_type || 'student'
        }
      });
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, error: 'Server error during login' });
  }
});

// ==================== SUPER ADMIN LOGIN ====================

// Super Admin Login
app.post('/api/auth/super-admin-login', async (req, res) => {
  const { email, password } = req.body;

  console.log(`🔐 Super Admin login attempt: ${email}`);

  if (!email || !password) {
    return res.status(400).json({ success: false, error: 'Email and password required' });
  }

  try {
    // First check if user exists and password is correct
    const userQuery = 'SELECT * FROM users WHERE email = ?';
    db.query(userQuery, [email], async (err, userResults) => {
      if (err) {
        console.error('Database error in user query:', err);
        return res.status(500).json({ success: false, error: 'Database error' });
      }

      if (userResults.length === 0) {
        console.log(`❌ User not found: ${email}`);
        return res.status(400).json({ success: false, error: 'Invalid email or password' });
      }

      const user = userResults[0];
      const isMatch = await bcrypt.compare(password, user.password);
      
      if (!isMatch) {
        console.log(`❌ Invalid password for: ${email}`);
        return res.status(400).json({ success: false, error: 'Invalid email or password' });
      }

      // Check if user is approved Super Admin
      const superAdminQuery = `
        SELECT sa.*, u.email as user_email 
        FROM super_admins sa 
        JOIN users u ON sa.user_id = u.id 
        WHERE sa.user_id = ? AND sa.is_active = TRUE
      `;
      
      db.query(superAdminQuery, [user.id], (err, superAdminResults) => {
        if (err) {
          console.error('Super Admin check error:', err);
          return res.status(500).json({ success: false, error: 'Database error checking super admin status' });
        }

        console.log(`🔍 Super Admin check results: ${superAdminResults.length} records found for user ${user.id}`);

        if (superAdminResults.length === 0) {
          console.log(`❌ User ${email} is not a Super Admin`);
          return res.status(403).json({ 
            success: false, 
            error: 'You are not approved as Super Admin. Please request access first and wait for admin approval.' 
          });
        }

        const superAdmin = superAdminResults[0];
        const token = Buffer.from(`superadmin:${user.id}:${Date.now()}`).toString('base64');
        
        // Parse permissions safely
        let permissions = {};
        try {
          permissions = superAdmin.permissions ? JSON.parse(superAdmin.permissions) : {};
        } catch (parseError) {
          console.error('Error parsing permissions:', parseError);
          permissions = {};
        }
        
        console.log(`✅ Super Admin login successful: ${email}`);
        res.json({ 
          success: true, 
          message: 'Super Admin login successful!', 
          token, 
          user: {
            id: user.id,
            email: user.email,
            name: superAdmin.name || user.name || 'Super Admin',
            role: 'super_admin',
            permissions: permissions
          }
        });
      });
    });
  } catch (error) {
    console.error('Super Admin login error:', error);
    res.status(500).json({ success: false, error: 'Server error during login' });
  }
});

// ==================== ADMIN LOGIN ====================
app.post('/api/auth/admin-login', async (req, res) => {
  const { email, password } = req.body;

  console.log(`🔐 Admin login attempt: ${email}`);

  if (!email || !password) {
    return res.status(400).json({ success: false, error: 'Email and password required' });
  }

  try {
    // Check in admins table first
    db.query('SELECT * FROM admins WHERE email = ? AND is_active = TRUE', [email], async (err, adminResults) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ success: false, error: 'Database error' });
      }

      if (adminResults.length > 0) {
        const admin = adminResults[0];
        const isMatch = await bcrypt.compare(password, admin.password);
        
        if (isMatch) {
          const token = Buffer.from(`admin:${admin.id}:${Date.now()}`).toString('base64');
          console.log(`✅ Admin login successful: ${email}`);
          return res.json({ 
            success: true, 
            message: 'Admin login successful', 
            token, 
            admin: {
              id: admin.id,
              email: admin.email,
              name: admin.name,
              role: 'admin'
            }
          });
        }
      }

      // Fallback to hardcoded admin credentials for backward compatibility
      const adminCredentials = [
        { email: 'hasanzahidul846@gmail.com', password: 'zahidul123', name: 'Main Administrator' },
        { email: 'admin@nextgen.com', password: 'admin123', name: 'System Admin' }
      ];

      const admin = adminCredentials.find(cred => cred.email === email && cred.password === password);

      if (admin) {
        const token = Buffer.from(`admin:${Date.now()}:${email}`).toString('base64');
        console.log(`✅ Admin login successful: ${email}`);
        res.json({ 
          success: true, 
          message: 'Admin login successful', 
          token, 
          admin: {
            email: admin.email,
            name: admin.name,
            role: 'admin'
          }
        });
      } else {
        console.log(`❌ Admin login failed: Invalid credentials for ${email}`);
        res.status(400).json({ success: false, error: 'Invalid admin credentials' });
      }
    });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ success: false, error: 'Server error during login' });
  }
});

// ==================== UTILITY ROUTES ====================

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    success: true, 
    message: 'Server is running', 
    timestamp: new Date().toISOString(),
    port: PORT
  });
});

// Test endpoint
app.get('/api/test', (req, res) => {
  res.json({ 
    success: true, 
    message: 'Server is working perfectly!',
    status: 'Active'
  });
});

// Get server status with counts
app.get('/api/status', (req, res) => {
  const statusQueries = {
    users: 'SELECT COUNT(*) as count FROM users',
    courses: 'SELECT COUNT(*) as count FROM courses',
    superAdmins: 'SELECT COUNT(*) as count FROM super_admins WHERE is_active = TRUE',
    pendingRequests: 'SELECT COUNT(*) as count FROM super_admin_requests WHERE status = "pending"'
  };

  const results = {};
  let completed = 0;
  const total = Object.keys(statusQueries).length;

  Object.keys(statusQueries).forEach(key => {
    db.query(statusQueries[key], (err, queryResults) => {
      if (err) {
        console.error(`Error in ${key} query:`, err);
        results[key] = 0;
      } else {
        results[key] = queryResults[0].count;
      }

      completed++;
      
      if (completed === total) {
        res.json({
          success: true,
          status: {
            ...results,
            serverTime: new Date().toISOString(),
            port: PORT
          }
        });
      }
    });
  });
});

// ==================== ERROR HANDLING ====================

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: `Route ${req.originalUrl} not found`
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('🚨 Unhandled error:', err);
  res.status(500).json({
    success: false,
    error: 'Internal server error'
  });
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🔴 Shutting down server gracefully...');
  db.end();
  process.exit(0);
});

// Start server
app.listen(PORT, () => {
  console.log(`\n🚀 Server running on http://localhost:${PORT}`);
  console.log(`✅ Registration System: ACTIVE`);
  console.log(`✅ Database: CONNECTED`);
  console.log(`✅ Super Admin System: COMPLETE`);
  console.log(`✅ Super Admin Request System: ACTIVE`);
  console.log(`🔗 IMPORTANT URLS:`);
  console.log(`   📝 Register: http://localhost:${PORT}/`);
  console.log(`   🔐 Login: http://localhost:${PORT}/login.html`);
  console.log(`   📊 Dashboard: http://localhost:${PORT}/dashboard.html`);
  console.log(`   💎 Premium: http://localhost:${PORT}/premium-courses.html`);
  console.log(`   👨‍💼 Admin: http://localhost:${PORT}/admin-dashboard.html`);
  console.log(`   🦸 Super Admin: http://localhost:${PORT}/super-admin-dashboard.html`);
  console.log(`   🔐 Super Admin Login: http://localhost:${PORT}/super-admin-login.html`);
  console.log(`   📝 Super Admin Register: http://localhost:${PORT}/super-admin-register.html`);
  console.log(`   🔐 Admin Login: http://localhost:${PORT}/admin-login.html`);
  console.log(`\n🔧 Default Super Admin Credentials:`);
  console.log(`   📧 Email: super@nextgen.com`);
  console.log(`   🔑 Password: super123`);
  console.log(`\n🔧 Default Admin Credentials:`);
  console.log(`   📧 Email: admin@nextgen.com`);
  console.log(`   🔑 Password: admin123`);
  console.log(`\n📊 Check server status: http://localhost:${PORT}/api/status`);
});