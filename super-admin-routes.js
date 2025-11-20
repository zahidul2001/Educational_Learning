// Super Admin API Routes
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./db-config');

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-admin-secret-key';

// Middleware to verify Super Admin token
const verifySuperAdmin = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ success: false, error: 'Access denied. No token provided.' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Check if user is a Super Admin
    if (decoded.role !== 'super_admin') {
      return res.status(403).json({ success: false, error: 'Access denied. Super Admin privileges required.' });
    }
    
    req.user = decoded;
    next();
  } catch (error) {
    res.status(400).json({ success: false, error: 'Invalid token.' });
  }
};

// Super Admin Login
router.post('/api/auth/super-admin-login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email and password are required' });
    }
    
    // Check if Super Admin exists and is approved
    const [superAdmins] = await db.execute(
      'SELECT * FROM Super_admins WHERE email = ? AND is_approved = 1',
      [email]
    );
    
    if (superAdmins.length === 0) {
      return res.status(401).json({ success: false, error: 'Invalid credentials or account not approved' });
    }
    
    const superAdmin = superAdmins[0];
    
    // Verify password
    const isPasswordValid = await bcrypt.compare(password, superAdmin.password);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }
    
    // Get permissions
    const [permissions] = await db.execute(
      'SELECT * FROM admin_permissions WHERE admin_id = ?',
      [superAdmin.id]
    );
    
    const userPermissions = permissions.length > 0 ? permissions[0] : {
      can_manage_users: 1,
      can_manage_courses: 1,
      can_manage_content: 1,
      can_view_report: 1
    };
    
    // Generate token
    const token = jwt.sign(
      { 
        id: superAdmin.id, 
        email: superAdmin.email, 
        role: 'super_admin',
        permissions: userPermissions
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({
      success: true,
      token,
      user: {
        id: superAdmin.id,
        name: superAdmin.name,
        email: superAdmin.email,
        permissions: userPermissions
      }
    });
    
  } catch (error) {
    console.error('Super Admin login error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Request Super Admin Access
router.post('/api/super-admin/request', async (req, res) => {
  try {
    const { userId, email, name, reason } = req.body;
    
    if (!userId || !email || !name || !reason) {
      return res.status(400).json({ success: false, error: 'All fields are required' });
    }
    
    // Check if user already has a pending request
    const [existingRequests] = await db.execute(
      'SELECT * FROM super_admin_request WHERE user_id = ? AND status = "pending"',
      [userId]
    );
    
    if (existingRequests.length > 0) {
      return res.status(400).json({ success: false, error: 'You already have a pending Super Admin request' });
    }
    
    // Check if user is already a Super Admin
    const [existingSuperAdmins] = await db.execute(
      'SELECT * FROM Super_admins WHERE email = ? AND is_approved = 1',
      [email]
    );
    
    if (existingSuperAdmins.length > 0) {
      return res.status(400).json({ success: false, error: 'User is already a Super Admin' });
    }
    
    // Create request
    await db.execute(
      'INSERT INTO super_admin_request (user_id, email, name, reason, status, created_at) VALUES (?, ?, ?, ?, "pending", NOW())',
      [userId, email, name, reason]
    );
    
    res.json({
      success: true,
      message: 'Super Admin access request submitted successfully'
    });
    
  } catch (error) {
    console.error('Super Admin request error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Get Super Admin Dashboard Data
router.get('/api/super-admin/dashboard', verifySuperAdmin, async (req, res) => {
  try {
    // Get total users
    const [usersResult] = await db.execute('SELECT COUNT(*) as total FROM users WHERE is_active = 1');
    const totalUsers = usersResult[0].total;
    
    // Get total courses
    const [coursesResult] = await db.execute('SELECT COUNT(*) as total FROM courses WHERE is_active = 1');
    const totalCourses = coursesResult[0].total;
    
    // Get total revenue (assuming you have an orders/payments table)
    const [revenueResult] = await db.execute('SELECT SUM(amount) as total FROM payments WHERE status = "completed"');
    const totalRevenue = revenueResult[0].total || 0;
    
    // Get pending requests
    const [requestsResult] = await db.execute('SELECT COUNT(*) as total FROM super_admin_request WHERE status = "pending"');
    const pendingRequests = requestsResult[0].total;
    
    res.json({
      success: true,
      stats: {
        totalUsers,
        totalCourses,
        totalRevenue,
        pendingRequests
      }
    });
    
  } catch (error) {
    console.error('Dashboard data error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Get Super Admin Requests
router.get('/api/super-admin/requests', verifySuperAdmin, async (req, res) => {
  try {
    const [requests] = await db.execute(`
      SELECT sr.*, u.name as user_name 
      FROM super_admin_request sr 
      LEFT JOIN users u ON sr.user_id = u.id 
      ORDER BY sr.created_at DESC
    `);
    
    res.json({
      success: true,
      requests: requests.map(request => ({
        id: request.id,
        user_id: request.user_id,
        name: request.name,
        email: request.email,
        reason: request.reason,
        status: request.status,
        created_at: request.created_at,
        reviewed_at: request.reviewed_at,
        reviewed_by: request.reviewed_by
      }))
    });
    
  } catch (error) {
    console.error('Get requests error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Respond to Super Admin Request
router.post('/api/super-admin/requests/respond', verifySuperAdmin, async (req, res) => {
  try {
    const { requestId, action, reviewedBy } = req.body;
    
    if (!requestId || !action || !reviewedBy) {
      return res.status(400).json({ success: false, error: 'All fields are required' });
    }
    
    // Get the request
    const [requests] = await db.execute(
      'SELECT * FROM super_admin_request WHERE id = ?',
      [requestId]
    );
    
    if (requests.length === 0) {
      return res.status(404).json({ success: false, error: 'Request not found' });
    }
    
    const request = requests[0];
    
    if (request.status !== 'pending') {
      return res.status(400).json({ success: false, error: 'Request has already been processed' });
    }
    
    // Update request status
    await db.execute(
      'UPDATE super_admin_request SET status = ?, reviewed_at = NOW(), reviewed_by = ? WHERE id = ?',
      [action, reviewedBy, requestId]
    );
    
    if (action === 'approved') {
      // Check if Super Admin already exists
      const [existingAdmins] = await db.execute(
        'SELECT * FROM Super_admins WHERE email = ?',
        [request.email]
      );
      
      if (existingAdmins.length === 0) {
        // Create Super Admin account with default password
        const hashedPassword = await bcrypt.hash('super123', 10);
        
        await db.execute(
          'INSERT INTO Super_admins (name, email, password, is_approved) VALUES (?, ?, ?, 1)',
          [request.name, request.email, hashedPassword]
        );
        
        // Get the new Super Admin ID
        const [newAdmins] = await db.execute(
          'SELECT id FROM Super_admins WHERE email = ?',
          [request.email]
        );
        
        const superAdminId = newAdmins[0].id;
        
        // Create default permissions
        await db.execute(
          'INSERT INTO admin_permissions (admin_id, can_manage_users, can_manage_courses, can_manage_content, can_view_report) VALUES (?, 1, 1, 1, 1)',
          [superAdminId]
        );
      } else {
        // Update existing Super Admin to approved
        await db.execute(
          'UPDATE Super_admins SET is_approved = 1 WHERE email = ?',
          [request.email]
        );
      }
    }
    
    res.json({
      success: true,
      message: `Request ${action} successfully`
    });
    
  } catch (error) {
    console.error('Respond to request error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Get All Users
router.get('/api/super-admin/users', verifySuperAdmin, async (req, res) => {
  try {
    const [users] = await db.execute(`
      SELECT id, name, email, role, is_active, created_at 
      FROM users 
      ORDER BY created_at DESC
    `);
    
    res.json({
      success: true,
      users: users.map(user => ({
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        is_active: user.is_active,
        created_at: user.created_at
      }))
    });
    
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Toggle User Status
router.post('/api/super-admin/users/toggle-status', verifySuperAdmin, async (req, res) => {
  try {
    const { userId, isActive } = req.body;
    
    if (!userId) {
      return res.status(400).json({ success: false, error: 'User ID is required' });
    }
    
    await db.execute(
      'UPDATE users SET is_active = ? WHERE id = ?',
      [isActive ? 1 : 0, userId]
    );
    
    res.json({
      success: true,
      message: `User ${isActive ? 'activated' : 'deactivated'} successfully`
    });
    
  } catch (error) {
    console.error('Toggle user status error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Upload Course
router.post('/api/super-admin/courses/upload', verifySuperAdmin, async (req, res) => {
  try {
    const { title, instructor, description, category, price, thumbnail, uploadedBy } = req.body;
    
    if (!title || !instructor || !description || !category || !price || !thumbnail) {
      return res.status(400).json({ success: false, error: 'All fields are required' });
    }
    
    // Insert course (assuming you have a courses table)
    await db.execute(
      `INSERT INTO courses (title, instructor, description, category, price, thumbnail, uploaded_by, is_active, created_at) 
       VALUES (?, ?, ?, ?, ?, ?, ?, 1, NOW())`,
      [title, instructor, description, category, price, thumbnail, uploadedBy]
    );
    
    res.json({
      success: true,
      message: 'Course uploaded successfully'
    });
    
  } catch (error) {
    console.error('Upload course error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

module.exports = router;