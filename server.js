require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const nodemailer = require('nodemailer');
const pgp = require('pg-promise')();

// Database Connection
const db = pgp(process.env.DATABASE_URL);

// Create database tables if they don't exist
const createTables = async () => {
  try {
    // Users table
    await db.none(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        phone TEXT,
        school TEXT,
        profile_image TEXT,
        balance NUMERIC DEFAULT 0,
        verified BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Add last_login and is_suspended columns if they don't exist
    await db.none(`
      DO $$ BEGIN
        ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMP;
        ALTER TABLE users ADD COLUMN IF NOT EXISTS is_suspended BOOLEAN DEFAULT FALSE;
      END $$;
    `);

    // Add school column if it doesn't exist (for existing databases)
    await db.none(`
      DO $$ BEGIN
        ALTER TABLE users ADD COLUMN IF NOT EXISTS school TEXT;
      EXCEPTION
        WHEN duplicate_column THEN NULL;
      END $$;
    `);

    // Add profile_image column if it doesn't exist
    await db.none(`
      DO $$ BEGIN
        ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_image TEXT;
      EXCEPTION
        WHEN duplicate_column THEN NULL;
      END $$;
    `);

    // Add verified column if it doesn't exist
    await db.none(`
      DO $$ BEGIN
        ALTER TABLE users ADD COLUMN IF NOT EXISTS verified BOOLEAN DEFAULT FALSE;
      EXCEPTION
        WHEN duplicate_column THEN NULL;
      END $$;
    `);

    // Orders table
    await db.none(`
      CREATE TABLE IF NOT EXISTS orders (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        assignment_title TEXT NOT NULL,
        subject TEXT NOT NULL,
        order_type TEXT NOT NULL,
        instructions TEXT,
        deadline TIMESTAMP NOT NULL,
        total_cost NUMERIC NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        files TEXT[],
        tutor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        payment_id TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Add instructions column if it doesn't exist
    await db.none(`
      DO $$ BEGIN
        ALTER TABLE orders ADD COLUMN IF NOT EXISTS instructions TEXT;
        ALTER TABLE orders ADD COLUMN IF NOT EXISTS files TEXT[];
        ALTER TABLE orders ADD COLUMN IF NOT EXISTS tutor_id INTEGER REFERENCES users(id) ON DELETE SET NULL;
        ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_id TEXT;
        ALTER TABLE orders ADD COLUMN IF NOT EXISTS pages INTEGER;
        ALTER TABLE orders ADD COLUMN IF NOT EXISTS description TEXT;
        ALTER TABLE orders ADD COLUMN IF NOT EXISTS additional_requirements TEXT;
        ALTER TABLE orders ADD COLUMN IF NOT EXISTS coupon_code TEXT;
        ALTER TABLE orders ADD COLUMN IF NOT EXISTS discount_amount NUMERIC DEFAULT 0;
      EXCEPTION
        WHEN duplicate_column THEN NULL;
      END $$;
    `);

    // Payments table
    await db.none(`
      CREATE TABLE IF NOT EXISTS payments (
        id SERIAL PRIMARY KEY,
        order_id INTEGER REFERENCES orders(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        amount NUMERIC NOT NULL,
        payment_method TEXT NOT NULL,
        transaction_id TEXT,
        reference TEXT,
        status TEXT NOT NULL DEFAULT 'completed',
        proof_file TEXT,
        original_name TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Add columns if they don't exist
    await db.none(`
      DO $$ BEGIN
        ALTER TABLE payments ADD COLUMN IF NOT EXISTS proof_file TEXT;
        ALTER TABLE payments ADD COLUMN IF NOT EXISTS original_name TEXT;
        ALTER TABLE payments ADD COLUMN IF NOT EXISTS reference TEXT;
        ALTER TABLE payments ALTER COLUMN transaction_id DROP NOT NULL;
      EXCEPTION
        WHEN duplicate_column THEN NULL;
      END $$;
    `);

    // Messages table
    await db.none(`
      CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        order_id INTEGER REFERENCES orders(id) ON DELETE CASCADE,
        sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        receiver_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        content TEXT NOT NULL,
        read BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Chat Settings table
    await db.none(`
      CREATE TABLE IF NOT EXISTS chat_settings (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE UNIQUE,
        theme TEXT DEFAULT 'default',
        custom_colors JSONB,
        sounds JSONB DEFAULT '{"sendSound": "send.mp3", "receiveSound": "receive.mp3", "volume": 50}',
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Coupons table
    await db.none(`
      CREATE TABLE IF NOT EXISTS coupons (
        id SERIAL PRIMARY KEY,
        code TEXT NOT NULL UNIQUE,
        discount_type TEXT NOT NULL DEFAULT 'percentage',
        discount_value NUMERIC NOT NULL,
        minimum_order_value NUMERIC DEFAULT 0,
        max_usage INTEGER,
        used_count INTEGER DEFAULT 0,
        is_active BOOLEAN DEFAULT TRUE,
        is_auto BOOLEAN DEFAULT FALSE,
        start_date TIMESTAMP,
        end_date TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Announcements table
    await db.none(`
      CREATE TABLE IF NOT EXISTS announcements (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        type TEXT DEFAULT 'news',
        icon TEXT DEFAULT 'fa-graduation-cap',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Tips table
    await db.none(`
      CREATE TABLE IF NOT EXISTS tips (
        id SERIAL PRIMARY KEY,
        content TEXT NOT NULL,
        author TEXT DEFAULT 'EssayMe Team',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Add initial data if tables are empty
    const announcementsCount = await db.one('SELECT count(*) FROM announcements');
    if (parseInt(announcementsCount.count) === 0) {
      await db.none(`
        INSERT INTO announcements (title, content, type, icon) VALUES
        ('Summer Semester Registration', 'Registration for summer courses is now open. Early bird discounts apply until May 1st.', 'news', 'fa-graduation-cap'),
        ('New Pricing Tiers Available', 'Check out our updated pricing for complex technical assignments and large projects.', 'news', 'fa-file-invoice-dollar')
      `);
    }

    const tipsCount = await db.one('SELECT count(*) FROM tips');
    if (parseInt(tipsCount.count) === 0) {
      await db.none(`
        INSERT INTO tips (content) VALUES
        ('Always start with a strong thesis statement. It acts as a roadmap for your entire essay.'),
        ('Avoid passive voice. Active verbs make your writing more direct and engaging.')
      `);
    }

    // Add is_auto column if it doesn't exist
    await db.none(`
      DO $$ BEGIN
        ALTER TABLE coupons ADD COLUMN IF NOT EXISTS is_auto BOOLEAN DEFAULT FALSE;
      EXCEPTION
        WHEN duplicate_column THEN NULL;
      END $$;
    `);

    console.log('✅ Database tables created or already exist');
    
    // Create admin user if it doesn't exist
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@essayme.com';
    const adminPassword = process.env.ADMIN_PASSWORD || 'Admin123!';
    
    // Check if admin user exists
    const existingAdmin = await db.oneOrNone('SELECT * FROM users WHERE email = $1', [adminEmail]);
    if (!existingAdmin) {
      const hashedPassword = await bcrypt.hash(adminPassword, 10);
      await db.none(`
        INSERT INTO users (name, email, password, role, verified)
        VALUES ($1, $2, $3, $4, $5)
      `, ['Admin', adminEmail, hashedPassword, 'admin', true]);
      console.log('✅ Admin user created');
    } else {
      console.log('✅ Admin user already exists');
    }
    
  } catch (error) {
    console.error('❌ Error creating database tables:', error.message);
  }
};

// Test database connection and create tables
db.connect()
  .then(obj => {
    console.log('✅ PostgreSQL database connected');
    obj.done(); // Release the connection
    createTables();
  })
  .catch(error => {
    console.error('❌ Database connection error:', error.message);
  });


const mailTransporter = nodemailer.createTransport({
  service: process.env.SMTP_SERVICE || undefined, // e.g. 'gmail'
  host: process.env.SMTP_HOST || (process.env.SMTP_SERVICE ? undefined : "smtp.gmail.com"),
  port: parseInt(process.env.SMTP_PORT, 10) || 587,
  secure: parseInt(process.env.SMTP_PORT, 10) === 465,
  pool: true, // Use connection pooling for better reliability
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
  tls: {
    // This allows it to work on various networks including those with self-signed certs
    rejectUnauthorized: false
  }
});

// Verify email transporter on startup
if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
  console.warn('⚠️ Warning: SMTP_USER or SMTP_PASS environment variables are not set. Email functionality will fail.');
}
console.log('📧 Verifying email transporter...');
console.log(`   Service: ${process.env.SMTP_SERVICE || 'Direct SMTP'}`);
console.log(`   Host: ${process.env.SMTP_HOST || "smtp.gmail.com"}`);
console.log(`   Port: ${process.env.SMTP_PORT || 587}`);
mailTransporter.verify((error, success) => {
  if (error) {
    console.error('❌ Email transporter verification failed:', error.message);
    console.error('  Check your SMTP_USER, SMTP_PASS, SMTP_HOST, and SMTP_PORT environment variables.');
  } else {
    console.log('✅ Email transporter is ready to send emails');
  }
});

// Simple mail helper that fails safely
async function sendMailSafe({ to, subject, text, html }) {
  try {
    if (!to) {
      console.warn('⚠️ No recipient specified for email:', subject);
      return;
    }
    
    const mailOptions = {
      from: `"EssayMe" <${process.env.SMTP_USER}>`,
      to,
      subject,
      text: text || (html ? html.replace(/<[^>]+>/g, ' ') : ''),
      html: html || undefined
    };

    const info = await mailTransporter.sendMail(mailOptions);
    console.log('✓ Email sent successfully:', info.messageId, '| To:', to, '| Subject:', subject);
    return info;
  } catch (e) {
    console.error('✗ Email send failed:', subject, 'to:', to);
    console.error('  Error detail:', e?.message || e);
    if (e?.response) console.error('  SMTP Response:', e.response);
  }
}

// Email template functions
const emailTemplates = {
  welcome: (name) => ({
    subject: 'Welcome to EssayMe',
    html: `<p>Hi ${name},</p>
           <p>Welcome to EssayMe! Your account has been created successfully.</p>
           <p>You can now submit assignments, chat with tutors, and track your progress.</p>
           <p>— EssayMe Team</p>`
  }),
  
  loginNotification: (name, time) => ({
    subject: 'Login Notification - EssayMe',
    html: `<p>Hi ${name},</p>
           <p>You have successfully logged in to your EssayMe account.</p>
           <p>Login time: ${time}</p>
           <p>If this wasn't you, please contact support immediately.</p>
           <p>— EssayMe Team</p>`
  }),
  
  assignmentReceived: (name, order) => ({
    subject: 'Your assignment has been received',
    html: `<p>Hi ${name},</p>
           <p>We received your assignment: <strong>${order.assignmentTitle}</strong>.</p>
           <ul>
             <li>Subject: ${order.subject}</li>
             <li>Type: ${order.orderType}</li>
             <li>Deadline: ${new Date(order.deadline).toLocaleString()}</li>
             <li>Total: ${fmtMoney(order.totalCost)}</li>
             ${order.couponCode ? `<li>Coupon Applied: ${order.couponCode} (-${fmtMoney(order.discountAmount)})</li>` : ''}
             <li>Status: ${order.status}</li>
           </ul>
           <p>We will keep you updated.</p>
           <p>— EssayMe Team</p>`
  }),

  balanceRecovered: (name, newBalance, reason) => ({
    subject: 'Your EssayMe Wallet Balance has been Adjusted',
    html: `<div style="font-family: Arial, sans-serif; color: #333;">
             <h2 style="color: #3b82f6;">Balance Adjustment Notification</h2>
             <p>Hi <strong>${name}</strong>,</p>
             <p>This is to inform you that your wallet balance has been manually adjusted by an administrator.</p>
             <div style="background-color: #f8fafc; padding: 15px; border-radius: 8px; border: 1px solid #e2e8f0; margin: 20px 0;">
               <p style="margin: 5px 0;"><strong>New Balance:</strong> <span style="color: #10b981; font-size: 1.2em;">${fmtMoney(newBalance)}</span></p>
               <p style="margin: 5px 0;"><strong>Reason:</strong> ${reason || 'Manual recovery/adjustment'}</p>
             </div>
             <p>You can view your updated balance and transaction history in your <a href="https://essayme.com/dashboard" style="color: #3b82f6; text-decoration: none; font-weight: bold;">Student Dashboard</a>.</p>
             <p>If you have any questions regarding this adjustment, please contact our support team or reply to this email.</p>
             <p>Best regards,<br><strong>The EssayMe Team</strong></p>
           </div>`
  }),
  
  assignmentAccepted: (name, order) => ({
    subject: 'Your assignment has been accepted by a tutor',
    html: `<p>Hi ${name},</p>
           <p>Great news! Your assignment has been accepted by a tutor and work has begun.</p>
           <ul>
             <li>Assignment: <strong>${order.assignmentTitle}</strong></li>
             <li>Subject: ${order.subject}</li>
             <li>Type: ${order.orderType}</li>
             <li>Deadline: ${new Date(order.deadline).toLocaleString()}</li>
             <li>Status: In Progress</li>
           </ul>
           <p>You can now communicate with your tutor through the chat system.</p>
           <p>— EssayMe Team</p>`
  }),
  
  assignmentCompleted: (name, order) => ({
    subject: 'Your assignment has been completed',
    html: `<p>Hi ${name},</p>
           <p>Your assignment <strong>${order.assignmentTitle}</strong> has been completed!</p>
           <ul>
             <li>Subject: ${order.subject}</li>
             <li>Type: ${order.orderType}</li>
             <li>Status: Completed</li>
           </ul>
           <p>You can now review the work and provide feedback.</p>
           <p>— EssayMe Team</p>`
  }),
  
  assignmentCancelled: (name, order) => ({
    subject: 'Your assignment has been cancelled',
    html: `<p>Hi ${name},</p>
           <p>Your assignment <strong>${order.assignmentTitle}</strong> has been cancelled.</p>
           <p>Status: Cancelled</p>
           <p>— EssayMe Team</p>`
  }),
  
  orderPaid: (name, order) => ({
    subject: 'Payment received for your assignment',
    html: `<p>Hi ${name},</p>
           <p>We have received payment for your assignment <strong>${order.assignmentTitle}</strong>.</p>
           <ul>
             <li>Amount Paid: ${fmtMoney(order.totalCost)}</li>
             ${order.couponCode ? `<li>Coupon Applied: ${order.couponCode} (-${fmtMoney(order.discountAmount)})</li>` : ''}
             <li>Transaction ID: ${order.paymentId}</li>
             <li>Status: Paid</li>
           </ul>
           <p>— EssayMe Team</p>`
  }),
  
  paymentDue: (name, order) => ({
    subject: 'Payment due for your assignment',
    html: `<p>Hi ${name},</p>
           <p>Payment is now due for your assignment <strong>${order.assignmentTitle}</strong>.</p>
           <ul>
             <li>Amount: ${fmtMoney(order.totalCost)}</li>
             ${order.couponCode ? `<li>Coupon Applied: ${order.couponCode} (-${fmtMoney(order.discountAmount)})</li>` : ''}
             <li>Status: Payment Due</li>
             <li>Deadline: ${new Date(order.deadline).toLocaleString()}</li>
           </ul>
           <p>Please make payment at your earliest convenience.</p>
           <p>— EssayMe Team</p>`
  }),
  
  paymentFailed: (name, order) => ({
    subject: 'Payment failed for your assignment',
    html: `<p>Hi ${name},</p>
           <p>We encountered an issue processing your payment for assignment <strong>${order.assignmentTitle}</strong>.</p>
           <ul>
             <li>Amount: ${fmtMoney(order.totalCost)}</li>
             <li>Status: Payment Failed</li>
           </ul>
           <p>Please try again or contact support if the issue persists.</p>
           <p>— EssayMe Team</p>`
  }),
  
  paymentRefunded: (name, order) => ({
    subject: 'Refund processed for your assignment',
    html: `<p>Hi ${name},</p>
           <p>A refund has been processed for your assignment <strong>${order.assignmentTitle}</strong>.</p>
           <ul>
             <li>Amount Refunded: ${fmtMoney(order.totalCost)}</li>
             <li>Transaction ID: ${order.paymentId}</li>
             <li>Status: Refunded</li>
           </ul>
           <p>Please allow 3-5 business days for the funds to appear in your account.</p>
           <p>— EssayMe Team</p>`
  }),

  accountSuspended: (name, reason) => ({
    subject: 'Important: Your EssayMe account has been suspended',
    html: `<p>Hi ${name},</p>
           <p>We are writing to inform you that your EssayMe account has been suspended.</p>
           ${reason ? `<p><strong>Reason:</strong> ${reason}</p>` : ''}
           <p>If you believe this is a mistake, please contact support.</p>
           <p>— EssayMe Team</p>`
  }),

  accountUnsuspended: (name) => ({
    subject: 'Your EssayMe account has been reactivated',
    html: `<p>Hi ${name},</p>
           <p>Your EssayMe account has been reactivated. You can now log in and continue using our services.</p>
           <p>— EssayMe Team</p>`
  }),

  accountDeleted: (name) => ({
    subject: 'Your EssayMe account has been deleted',
    html: `<p>Hi ${name},</p>
           <p>This is to confirm that your EssayMe account and all associated data have been deleted as requested.</p>
           <p>— EssayMe Team</p>`
  })
};

// Helper function to format currency
const fmtMoney = (amount) => `$${Number(amount).toFixed(2)}`;

// Initialize app
const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ limit: '100mb', extended: true }));

// Request Logger
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

// Ensure upload directory exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, `${file.fieldname}-${uniqueSuffix}${path.extname(file.originalname)}`);
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 100 * 1024 * 1024 } // Increased to 100MB
});

// Background Upload Endpoint
app.post('/upload-background', upload.single('background'), (req, res) => {
  if (!req.file) return res.status(400).json({ success: false, error: 'No file uploaded' });
  const fileUrl = `/uploads/${req.file.filename}`;
  res.json({ success: true, url: fileUrl });
});

// SSE Clients
let sseClients = [];

// Announcements & Tips Endpoints
app.get('/announcements', async (req, res) => {
  try {
    const announcements = await db.any('SELECT * FROM announcements ORDER BY created_at DESC LIMIT 5');
    res.json({ success: true, announcements });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/tips', async (req, res) => {
  try {
    const tips = await db.any('SELECT * FROM tips ORDER BY RANDOM() LIMIT 3');
    res.json({ success: true, tips });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// SSE Endpoint for real-time messages
app.get('/messages/stream', (req, res) => {
  console.log('HIT /messages/stream', req.query);
  const { assignmentId } = req.query;
  if (!assignmentId) {
    return res.status(400).json({ error: 'assignmentId is required' });
  }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const clientId = Date.now();
  const newClient = {
    id: clientId,
    assignmentId: String(assignmentId),
    res
  };

  sseClients.push(newClient);

  req.on('close', () => {
    sseClients = sseClients.filter(client => client.id !== clientId);
  });
});

// Helper to broadcast messages to SSE clients
const broadcastMessage = (assignmentId, message) => {
  const clients = sseClients.filter(client => client.assignmentId === String(assignmentId));
  clients.forEach(client => {
    client.res.write(`data: ${JSON.stringify({ type: 'message', message })}\n\n`);
  });
};

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString(), version: '1.0.0' });
});

// Update User Balance
app.post('/update-balance', async (req, res) => {
  try {
    const { userId, amount, method, reference } = req.body;
    
    if (!userId || amount === undefined) {
      return res.status(400).json({ success: false, error: 'userId and amount are required' });
    }

    // Update user balance
    const updatedUser = await db.one(`
      UPDATE users 
      SET balance = balance + $1, updated_at = CURRENT_TIMESTAMP 
      WHERE id = $2
      RETURNING balance
    `, [parseFloat(amount), parseInt(userId)]);

    // Record payment
    await db.none(`
      INSERT INTO payments (user_id, amount, payment_method, transaction_id, reference, status)
      VALUES ($1, $2, $3, $4, $5, $6)
    `, [parseInt(userId), parseFloat(amount), method || 'unknown', reference || 'N/A', reference || 'N/A', 'approved']);

    res.json({ 
      success: true, 
      message: 'Balance updated successfully', 
      newBalance: parseFloat(updatedUser.balance) 
    });

  } catch (error) {
    console.error('Error updating balance:', error);
    res.status(500).json({ success: false, error: 'Failed to update balance', details: error.message });
  }
});

// Authentication middleware
const requireAuth = async (req, res, next) => {
  const email = (req.body?.email || req.query?.email || req.headers['x-user-email'] || req.headers['X-User-Email'])?.toLowerCase();
  if (!email) {
    return res.status(401).json({ error: 'Missing email parameter' });
  }
  try {
    const user = await db.oneOrNone('SELECT * FROM users WHERE LOWER(email) = LOWER($1)', [email]);
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    req.user = user;
    next();
  } catch (error) {
    console.error('Error authenticating user:', error);
    res.status(500).json({ error: 'Authentication failed' });
  }
};

const requireAdmin = async (req, res, next) => {
  const email = (req.body?.email || req.query?.email || req.headers['x-user-email'] || req.headers['X-User-Email'])?.toLowerCase();
  if (!email) {
    console.warn('requireAdmin: Missing email');
    return res.status(401).json({ error: 'Missing email parameter' });
  }
  try {
    const user = await db.oneOrNone('SELECT * FROM users WHERE LOWER(email) = LOWER($1)', [email]);
    if (!user) {
      console.warn(`requireAdmin: User not found: ${email}`);
      return res.status(401).json({ error: 'User not found' });
    }
    if (user.role !== 'admin') {
      console.warn(`requireAdmin: Access denied for ${email}, role: ${user.role}`);
      return res.status(403).json({ error: 'Access denied' });
    }
    req.user = user;
    next();
  } catch (error) {
    console.error('Error authenticating admin:', error);
    res.status(500).json({ error: 'Authentication failed' });
  }
};

const requireTutor = async (req, res, next) => {
  const email = (req.body?.email || req.query?.email || req.headers['x-user-email'] || req.headers['X-User-Email'])?.toLowerCase();
  if (!email) {
    return res.status(401).json({ error: 'Missing email parameter' });
  }
  try {
    const user = await db.oneOrNone('SELECT * FROM users WHERE LOWER(email) = LOWER($1)', [email]);
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    if (user.role !== 'tutor' && user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }
    req.user = user;
    next();
  } catch (error) {
    console.error('Error authenticating tutor:', error);
    res.status(500).json({ error: 'Authentication failed' });
  }
};

// Admin Adjust User Balance (Recover/Change Money)
app.post('/tutor/adjust-balance', requireTutor, async (req, res) => {
  try {
    const { userId, newAmount, reason } = req.body;
    
    if (!userId || newAmount === undefined) {
      return res.status(400).json({ success: false, error: 'userId and newAmount are required' });
    }

    const userIdInt = parseInt(userId);
    const newAmountFloat = parseFloat(newAmount);

    // Get user details first for email
    const user = await db.one('SELECT name, email FROM users WHERE id = $1', [userIdInt]);

    // Update user balance directly to the new amount
    const updatedUser = await db.one(`
      UPDATE users 
      SET balance = $1, updated_at = CURRENT_TIMESTAMP 
      WHERE id = $2
      RETURNING balance
    `, [newAmountFloat, userIdInt]);

    // Record adjustment in payments for history - using 'Recovered' as reference prefix
    const adjReason = reason || 'Manual adjustment by admin';
    await db.none(`
      INSERT INTO payments (user_id, amount, payment_method, transaction_id, reference, status)
      VALUES ($1, $2, $3, $4, $5, $6)
    `, [userIdInt, newAmountFloat, 'admin_adjustment', `REC-${Date.now()}`, `Recovered: ${adjReason}`, 'approved']);

    // Send email notification
    await sendMailSafe({
      to: user.email,
      ...emailTemplates.balanceRecovered(user.name, updatedUser.balance, adjReason)
    });

    res.json({ 
      success: true, 
      message: 'User balance updated successfully and email sent', 
      newBalance: parseFloat(updatedUser.balance) 
    });

  } catch (error) {
    console.error('Error adjusting balance:', error);
    res.status(500).json({ success: false, error: 'Failed to adjust balance', details: error.message });
  }
});

// User Registration
app.post('/register', async (req, res) => {
  try {
    const { name, email, password, role = 'user', phone, school } = req.body;

    // Input validation
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'All required fields are not filled out' });
    }

    // Check if user already exists
    const existingUser = await db.oneOrNone('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Use 'student' instead of 'user' to match existing table structure
    const userRole = role === 'admin' || role === 'tutor' ? role : 'student';
    
    // Create user in database
    const newUser = await db.one(`
      INSERT INTO users (name, email, password, role, phone, school, profile_image, balance, verified)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING id, name, email, role, phone, school, balance, verified, profile_image, created_at, updated_at
    `, [name, email, hashedPassword, userRole, phone, school, null, 0, false]);

    // Send welcome email
    await sendMailSafe({
      to: email,
      ...emailTemplates.welcome(name)
    });

    res.status(201).json({
      message: 'Account created successfully',
      user: {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email,
        role: newUser.role,
        phone: newUser.phone,
        school: newUser.school,
        balance: newUser.balance,
        verified: newUser.verified,
        profileImage: newUser.profile_image
      }
    });

  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ error: 'Failed to register user', details: error.message });
  }
});

// User Login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await db.oneOrNone('SELECT * FROM users WHERE email = $1', [email]);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (user.is_suspended) {
      return res.status(403).json({ error: 'Your account has been suspended. Please contact support.' });
    }

    // Update last login
    await db.none('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);

    // Send login notification email (non-blocking)
    sendMailSafe({
      to: email,
      ...emailTemplates.loginNotification(user.name, new Date().toLocaleString())
    }).catch(err => console.error('Failed to send login email:', err));

    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        phone: user.phone,
        school: user.school,
        balance: user.balance,
        verified: user.verified,
        profileImage: user.profile_image
      }
    });

  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({ error: 'Failed to login', details: error.message });
  }
});

// Get User Profile by ID
app.get('/user/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const user = await db.oneOrNone('SELECT * FROM users WHERE id = $1', [parseInt(id)]);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.is_suspended) {
      return res.status(403).json({ error: 'Your account has been suspended. Please contact support.' });
    }

    res.json({
      success: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        phone: user.phone,
        school: user.school,
        balance: user.balance,
        verified: user.verified,
        profileImage: user.profile_image
      }
    });

  } catch (error) {
    console.error('Error fetching user by ID:', error);
    res.status(500).json({ error: 'Failed to fetch user', details: error.message });
  }
});

// Get User Profile by Email
app.get('/profile/:email', async (req, res) => {
  try {
    const { email } = req.params;
    const user = await db.oneOrNone('SELECT * FROM users WHERE email = $1', [email]);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      phone: user.phone,
      school: user.school,
      balance: user.balance,
      verified: user.verified,
      profileImage: user.profile_image
    });

  } catch (error) {
    console.error('Error fetching profile:', error);
    res.status(500).json({ error: 'Failed to fetch profile', details: error.message });
  }
});

// Update User Profile
app.put('/profile', requireAuth, async (req, res) => {
  try {
    const { name, phone, school, email } = req.body;
    const user = req.user;

    if (email && email !== user.email) {
      const existingUser = await db.oneOrNone('SELECT * FROM users WHERE email = $1', [email]);
      if (existingUser) {
        return res.status(409).json({ error: 'Email already registered' });
      }
    }

    // Update user in database
    const updatedUser = await db.one(`
      UPDATE users 
      SET 
        name = COALESCE($1, name), 
        email = COALESCE($2, email), 
        phone = COALESCE($3, phone), 
        school = COALESCE($4, school), 
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $5
      RETURNING id, name, email, role, phone, school, balance, verified, profile_image
    `, [name, email, phone, school, user.id]);

    res.json({
      message: 'Profile updated successfully',
      user: {
        id: updatedUser.id,
        name: updatedUser.name,
        email: updatedUser.email,
        role: updatedUser.role,
        phone: updatedUser.phone,
        school: updatedUser.school,
        balance: updatedUser.balance,
        verified: updatedUser.verified,
        profileImage: updatedUser.profile_image
      }
    });

  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).json({ error: 'Failed to update profile', details: error.message });
  }
});

// Change Password
app.put('/change-password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = req.user;

    const validPassword = await bcrypt.compare(currentPassword, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await db.none(`
      UPDATE users 
      SET password = $1, updated_at = CURRENT_TIMESTAMP 
      WHERE id = $2
    `, [hashedPassword, user.id]);

    res.json({ message: 'Password changed successfully' });

  } catch (error) {
    console.error('Error changing password:', error);
    res.status(500).json({ error: 'Failed to change password', details: error.message });
  }
});

// Upload Profile Image
app.post('/upload-profile', upload.single('profileImage'), requireAuth, async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    // Read the file and convert to base64
    const fs = require('fs');
    const filePath = req.file.path;
    const fileData = fs.readFileSync(filePath);
    const base64Image = `data:${req.file.mimetype};base64,${fileData.toString('base64')}`;

    const user = req.user;
    await db.none(`
      UPDATE users 
      SET profile_image = $1, updated_at = CURRENT_TIMESTAMP 
      WHERE id = $2
    `, [base64Image, user.id]);

    // Delete the temporary file
    try {
      fs.unlinkSync(filePath);
    } catch (unlinkError) {
      console.error('Error deleting temp file:', unlinkError);
    }

    res.json({
      message: 'Profile image uploaded successfully',
      profileImage: base64Image
    });

  } catch (error) {
    console.error('Error uploading profile image:', error);
    res.status(500).json({ error: 'Failed to upload profile image', details: error.message });
  }
});

// Update Account (Legacy/Consolidated endpoint)
app.post('/update-account', upload.single('profileImage'), async (req, res) => {
  try {
    const { userId, name, email, phone, school } = req.body;
    if (!userId) {
      return res.status(400).json({ success: false, error: 'userId is required' });
    }

    let profileImageUrl = null;
    if (req.file) {
      const fs = require('fs');
      const filePath = req.file.path;
      const fileData = fs.readFileSync(filePath);
      profileImageUrl = `data:${req.file.mimetype};base64,${fileData.toString('base64')}`;
      
      // Delete temp file
      try { fs.unlinkSync(filePath); } catch (e) {}
    }

    const updatedUser = await db.one(`
      UPDATE users 
      SET 
        name = COALESCE($1, name), 
        email = COALESCE($2, email), 
        phone = COALESCE($3, phone), 
        school = COALESCE($4, school),
        profile_image = COALESCE($5, profile_image),
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $6
      RETURNING id, name, email, role, phone, school, balance, verified, profile_image
    `, [name, email, phone, school, profileImageUrl, parseInt(userId)]);

    res.json({
      success: true,
      message: 'Account updated successfully',
      user: {
        id: updatedUser.id,
        name: updatedUser.name,
        email: updatedUser.email,
        role: updatedUser.role,
        phone: updatedUser.phone,
        school: updatedUser.school,
        balance: updatedUser.balance,
        verified: updatedUser.verified,
        profileImage: updatedUser.profile_image
      }
    });

  } catch (error) {
    console.error('Error updating account:', error);
    res.status(500).json({ success: false, error: 'Failed to update account', details: error.message });
  }
});

// Check Balance by ID
app.get('/check-balance/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    // Validate that id is a number
    if (!/^\d+$/.test(id)) {
      return res.status(400).json({ error: 'Invalid user ID format' });
    }
    
    const user = await db.oneOrNone('SELECT balance FROM users WHERE id = $1', [parseInt(id)]);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ balance: user.balance });

  } catch (error) {
    console.error('Error checking balance by ID:', error);
    res.status(500).json({ error: 'Failed to check balance', details: error.message });
  }
});

// Check Balance by Email
app.get('/check-balance/:email', async (req, res) => {
  try {
    const { email } = req.params;
    const user = await db.oneOrNone('SELECT balance FROM users WHERE email = $1', [email]);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ balance: user.balance });

  } catch (error) {
    console.error('Error checking balance:', error);
    res.status(500).json({ error: 'Failed to check balance', details: error.message });
  }
});

// Place Order
app.post('/place-order', upload.array('files'), requireAuth, async (req, res) => {
  try {
    const user = req.user;
    const {
      subject,
      orderType,
      assignmentTitle,
      description,
      deadline,
      pages,
      words,
      images,
      format,
      totalCost,
      couponCode,
      discountAmount
    } = req.body;

    // Get uploaded files
    const uploadedFiles = req.files ? req.files.map(f => f.filename) : [];

    // Check if user has enough balance
    let status = 'pending';
    if (user.balance < parseFloat(totalCost)) {
      status = 'pending'; // Use valid status from check constraint
    } else {
      status = 'checking-balance'; // Use valid status from check constraint
      // Deduct from balance
      await db.none(`
        UPDATE users 
        SET balance = balance - $1, updated_at = CURRENT_TIMESTAMP 
        WHERE id = $2
      `, [parseFloat(totalCost), user.id]);
    }

    const newOrder = await db.one(`
      INSERT INTO orders (
        user_id, assignment_title, subject, order_type, instructions, description, deadline, total_cost, status, files, tutor_id, payment_id, pages, additional_requirements, coupon_code, discount_amount
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
      RETURNING 
        id, user_id as "userId", assignment_title as "assignmentTitle", 
        subject, order_type as "orderType", instructions, description, deadline, 
        total_cost as "totalCost", status, files, tutor_id as "tutorId", 
        payment_id as "paymentId", created_at as "createdAt", updated_at as "updatedAt",
        pages, additional_requirements as "additionalRequirements", coupon_code as "couponCode", discount_amount as "discountAmount"
    `, [
      user.id,
      assignmentTitle,
      subject,
      orderType,
      description, // instructions
      description, // description
      new Date(deadline),
      parseFloat(totalCost),
      status,
      uploadedFiles,
      null,
      null,
      parseInt(pages) || 0,
      req.body.additionalRequirements || '',
      couponCode || null,
      parseFloat(discountAmount) || 0
    ]);

    // Send order received email
    await sendMailSafe({
      to: user.email,
      ...emailTemplates.assignmentReceived(user.name, newOrder)
    });

    res.status(201).json({
      message: 'Order placed successfully',
      order: newOrder
    });

  } catch (error) {
    console.error('Error placing order:', error);
    res.status(500).json({ error: 'Failed to place order', details: error.message });
  }
});

// Get Student Assignments (Alias for frontend)
app.get('/student/assignments', async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) {
      return res.status(400).json({ success: false, error: 'userId is required' });
    }

    const assignments = await db.manyOrNone(`
      SELECT id, assignment_title as title, status, subject, tutor_id as "assignedTutor"
      FROM orders 
      WHERE user_id = $1
      ORDER BY created_at DESC
    `, [parseInt(userId)]);

    res.json({
      success: true,
      assignments: assignments
    });

  } catch (error) {
    console.error('Error fetching student assignments:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch assignments', details: error.message });
  }
});

// Get User Orders by ID
app.get('/orders/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    // Validate that id is a number
    if (!/^\d+$/.test(id)) {
      return res.status(400).json({ error: 'Invalid user ID format' });
    }
    
    const user = await db.oneOrNone('SELECT id FROM users WHERE id = $1', [parseInt(id)]);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userOrders = await db.manyOrNone(`
      SELECT 
        id, user_id as "userId", assignment_title as "assignmentTitle", 
        subject, order_type as "orderType", instructions, deadline, 
        total_cost as "totalCost", status, files, tutor_id as "tutorId", 
        payment_id as "paymentId", created_at as "createdAt", updated_at as "updatedAt",
        coupon_code as "couponCode", discount_amount as "discountAmount"
      FROM orders 
      WHERE user_id = $1
    `, [user.id]);
    res.json({ success: true, orders: userOrders });

  } catch (error) {
    console.error('Error fetching user orders by ID:', error);
    res.status(500).json({ error: 'Failed to fetch user orders', details: error.message });
  }
});

// Get User Orders by Email
app.get('/orders/:email', async (req, res) => {
  try {
    const { email } = req.params;
    const user = await db.oneOrNone('SELECT id FROM users WHERE email = $1', [email]);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userOrders = await db.manyOrNone(`
      SELECT 
        id, user_id as "userId", assignment_title as "assignmentTitle", 
        subject, order_type as "orderType", instructions, deadline, 
        total_cost as "totalCost", status, files, tutor_id as "tutorId", 
        payment_id as "paymentId", created_at as "createdAt", updated_at as "updatedAt",
        coupon_code as "couponCode", discount_amount as "discountAmount"
      FROM orders 
      WHERE user_id = $1
    `, [user.id]);
    res.json({ success: true, orders: userOrders });

  } catch (error) {
    console.error('Error fetching user orders:', error);
    res.status(500).json({ error: 'Failed to fetch user orders', details: error.message });
  }
});

// Get Order by ID
app.get('/order/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const order = await db.oneOrNone(`
      SELECT 
        id, user_id as "userId", assignment_title as "assignmentTitle", 
        subject, order_type as "orderType", instructions, deadline, 
        total_cost as "totalCost", status, files, tutor_id as "tutorId", 
        payment_id as "paymentId", created_at as "createdAt", updated_at as "updatedAt",
        coupon_code as "couponCode", discount_amount as "discountAmount"
      FROM orders 
      WHERE id = $1
    `, [parseInt(id)]);

    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    res.json(order);

  } catch (error) {
    console.error('Error fetching order:', error);
    res.status(500).json({ error: 'Failed to fetch order', details: error.message });
  }
});

// Get User Payments
app.get('/payments/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const payments = await db.manyOrNone(`
      SELECT id, amount::FLOAT, payment_method, payment_method as method, reference, status, created_at as "createdAt"
      FROM payments 
      WHERE user_id = $1
      ORDER BY created_at DESC
    `, [parseInt(id)]);

    res.json({
      success: true,
      payments: payments
    });

  } catch (error) {
    console.error('Error fetching user payments:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch payments', details: error.message });
  }
});

// Update User Balance
app.post('/update-balance', async (req, res) => {
  try {
    const { userId, amount, method, reference } = req.body;
    
    if (!userId || amount === undefined) {
      return res.status(400).json({ success: false, error: 'userId and amount are required' });
    }

    // Update user balance
    const updatedUser = await db.one(`
      UPDATE users 
      SET balance = balance + $1, updated_at = CURRENT_TIMESTAMP 
      WHERE id = $2
      RETURNING balance
    `, [parseFloat(amount), parseInt(userId)]);

    // Record payment
    await db.none(`
      INSERT INTO payments (user_id, amount, payment_method, transaction_id, reference, status)
      VALUES ($1, $2, $3, $4, $5, $6)
    `, [parseInt(userId), parseFloat(amount), method || 'unknown', reference || 'N/A', reference || 'N/A', 'approved']);

    res.json({ 
      success: true, 
      message: 'Balance updated successfully', 
      newBalance: parseFloat(updatedUser.balance) 
    });

  } catch (error) {
    console.error('Error updating balance:', error);
    res.status(500).json({ success: false, error: 'Failed to update balance', details: error.message });
  }
});

// Submit Payment Proof
app.post('/submit-payment-proof', upload.single('proof'), async (req, res) => {
  try {
    const { userId, amount, method } = req.body;
    const proofFile = req.file ? req.file.filename : null;
    const originalName = req.file ? req.file.originalname : null;

    if (!userId || !amount || !proofFile) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    await db.none(`
      INSERT INTO payments (user_id, amount, payment_method, status, proof_file, original_name)
      VALUES ($1, $2, $3, $4, $5, $6)
    `, [parseInt(userId), parseFloat(amount), method, 'pending', proofFile, originalName]);

    res.json({ success: true, message: 'Payment proof submitted successfully' });
  } catch (error) {
    console.error('Error submitting payment proof:', error);
    res.status(500).json({ success: false, message: 'Failed to submit payment proof' });
  }
});

// Get File
app.get('/file/:filename', (req, res) => {
  const filePath = path.join(uploadDir, req.params.filename);
  if (fs.existsSync(filePath)) {
    // Use res.download to force download and set Content-Disposition
    res.download(filePath, req.params.filename, (err) => {
      if (err) {
        if (!res.headersSent) {
          res.status(500).json({ error: 'Error downloading file' });
        }
      }
    });
  } else {
    res.status(404).json({ error: 'File not found' });
  }
});

// Tutor Profile
app.get('/tutor/profile/:id', requireTutor, async (req, res) => {
  try {
    const { id } = req.params;
    const tutor = await db.oneOrNone('SELECT id, name, email, role, phone, school, profile_image FROM users WHERE id = $1', [parseInt(id)]);
    
    if (!tutor) {
      return res.status(404).json({ success: false, message: 'Tutor not found' });
    }

    res.json({ success: true, tutor });
  } catch (error) {
    console.error('Error fetching tutor profile:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch tutor profile' });
  }
});

// Update Assignment Status (Tutor)
app.post('/tutor/update-assignment-status', requireTutor, async (req, res) => {
  try {
    const { assignmentId, status } = req.body;
    const tutorId = req.user.id;

    const updatedOrder = await db.one(`
      UPDATE orders 
      SET status = $1, tutor_id = COALESCE(tutor_id, $2), updated_at = CURRENT_TIMESTAMP 
      WHERE id = $3
      RETURNING *
    `, [status, tutorId, parseInt(assignmentId)]);

    res.json({ success: true, message: 'Status updated successfully', order: updatedOrder });
  } catch (error) {
    console.error('Error updating assignment status:', error);
    res.status(500).json({ success: false, message: 'Failed to update status' });
  }
});

// Upload Completed Files
app.post('/tutor/upload-completed-files/:assignmentId', upload.array('files'), requireTutor, async (req, res) => {
  try {
    const { assignmentId } = req.params;
    const { comments } = req.body;
    const files = req.files ? req.files.map(f => f.filename) : [];

    await db.none(`
      UPDATE orders 
      SET status = 'completed', files = files || $1, updated_at = CURRENT_TIMESTAMP 
      WHERE id = $2
    `, [files, parseInt(assignmentId)]);

    res.json({ success: true, message: 'Files uploaded and assignment marked as completed' });
  } catch (error) {
    console.error('Error uploading completed files:', error);
    res.status(500).json({ success: false, message: 'Failed to upload files' });
  }
});

// Approve Payment
app.post('/tutor/approve-payment', requireTutor, async (req, res) => {
  try {
    const { paymentId } = req.body;

    const payment = await db.oneOrNone('SELECT * FROM payments WHERE id = $1', [parseInt(paymentId)]);
    if (!payment) {
      return res.status(404).json({ success: false, message: 'Payment not found' });
    }

    if (payment.status === 'completed') {
      return res.status(400).json({ success: false, message: 'Payment already approved' });
    }

    await db.tx(async t => {
      // Mark payment as completed
      await t.none('UPDATE payments SET status = $1 WHERE id = $2', ['completed', payment.id]);
      
      // Credit user balance
      await t.none('UPDATE users SET balance = balance + $1 WHERE id = $2', [parseFloat(payment.amount), payment.user_id]);
    });

    res.json({ success: true, message: 'Payment approved and balance updated' });
  } catch (error) {
    console.error('Error approving payment:', error);
    res.status(500).json({ success: false, message: 'Failed to approve payment' });
  }
});

// Reject Payment
app.post('/tutor/reject-payment', requireTutor, async (req, res) => {
  try {
    const { paymentId, reason } = req.body;

    await db.none('UPDATE payments SET status = $1 WHERE id = $2', ['rejected', parseInt(paymentId)]);

    res.json({ success: true, message: 'Payment rejected' });
  } catch (error) {
    console.error('Error rejecting payment:', error);
    res.status(500).json({ success: false, message: 'Failed to reject payment' });
  }
});

// Request Refund
app.post('/payments/request-refund', async (req, res) => {
  try {
    const { userId, orderId, amount, reason } = req.body;
    console.log(`Refund requested by user ${userId} for order ${orderId}, amount ${amount}, reason: ${reason}`);
    res.json({ success: true, message: 'Refund request submitted successfully' });
  } catch (error) {
    console.error('Error requesting refund:', error);
    res.status(500).json({ success: false, message: 'Failed to request refund' });
  }
});

// Request Withdraw
app.post('/payments/request-withdraw', async (req, res) => {
  try {
    const { userId, amount, method, details } = req.body;
    console.log(`Withdraw requested by user ${userId}, amount ${amount}, method: ${method}`);
    res.json({ success: true, message: 'Withdraw request submitted successfully' });
  } catch (error) {
    console.error('Error requesting withdraw:', error);
    res.status(500).json({ success: false, message: 'Failed to request withdraw' });
  }
});

// Update Order Status
app.put('/order/:id/status', async (req, res) => {
  try {
    const { id } = req.params;
    const { status, tutorEmail } = req.body;

    const order = await db.oneOrNone('SELECT * FROM orders WHERE id = $1', [parseInt(id)]);
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    let tutorId = null;
    if (tutorEmail) {
      const tutor = await db.oneOrNone('SELECT id FROM users WHERE email = $1', [tutorEmail]);
      tutorId = tutor?.id || null;
    }

    const updatedOrder = await db.one(`
      UPDATE orders 
      SET status = $1, tutor_id = COALESCE($2, tutor_id), updated_at = CURRENT_TIMESTAMP 
      WHERE id = $3
      RETURNING 
        id, user_id as "userId", assignment_title as "assignmentTitle", 
        subject, order_type as "orderType", instructions, deadline, 
        total_cost as "totalCost", status, files, tutor_id as "tutorId", 
        payment_id as "paymentId", created_at as "createdAt", updated_at as "updatedAt",
        coupon_code as "couponCode", discount_amount as "discountAmount"
    `, [status, tutorId, parseInt(id)]);

    // Get user
    const user = await db.one('SELECT * FROM users WHERE id = $1', [updatedOrder.userId]);

    // Send appropriate email notification based on status
    if (status === 'processing') {
      await sendMailSafe({
        to: user.email,
        ...emailTemplates.assignmentAccepted(user.name, updatedOrder)
      });
    } else if (status === 'completed') {
      await sendMailSafe({
        to: user.email,
        ...emailTemplates.assignmentCompleted(user.name, updatedOrder)
      });
    } else if (status === 'cancelled') {
      // Refund if payment was processed
      await db.none(`
        UPDATE users 
        SET balance = balance + $1, updated_at = CURRENT_TIMESTAMP 
        WHERE id = $2
      `, [updatedOrder.totalCost, updatedOrder.userId]);
      
      await sendMailSafe({
        to: user.email,
        ...emailTemplates.assignmentCancelled(user.name, updatedOrder)
      });
    } else if (status === 'payment-due') {
      await sendMailSafe({
        to: user.email,
        ...emailTemplates.paymentDue(user.name, updatedOrder)
      });
    }

    res.json({ message: 'Order status updated successfully', order: updatedOrder });

  } catch (error) {
    console.error('Error updating order status:', error);
    res.status(500).json({ error: 'Failed to update order status', details: error.message });
  }
});

// Delete Order
app.delete('/order/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const order = await db.oneOrNone(`
      SELECT 
        id, user_id as "userId", assignment_title as "assignmentTitle", 
        subject, order_type as "orderType", instructions, deadline, 
        total_cost as "totalCost", status, files, tutor_id as "tutorId", 
        payment_id as "paymentId", created_at as "createdAt", updated_at as "updatedAt",
        coupon_code as "couponCode", discount_amount as "discountAmount"
      FROM orders 
      WHERE id = $1
    `, [parseInt(id)]);

    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    // Refund if payment was processed
    if (order.status !== 'cancelled' && order.status !== 'payment-due') {
      await db.none(`
        UPDATE users 
        SET balance = balance + $1, updated_at = CURRENT_TIMESTAMP 
        WHERE id = $2
      `, [order.totalCost, order.userId]);
    }

    await db.none('DELETE FROM orders WHERE id = $1', [parseInt(id)]);

    res.json({ message: 'Order deleted successfully' });

  } catch (error) {
    console.error('Error deleting order:', error);
    res.status(500).json({ error: 'Failed to delete order', details: error.message });
  }
});

// Get Messages for an Assignment (New Endpoint for Frontend)
app.get('/messages', async (req, res) => {
  try {
    const { assignmentId } = req.query;
    if (!assignmentId) {
      return res.status(400).json({ success: false, error: 'assignmentId is required' });
    }

    const messages = await db.manyOrNone(`
      SELECT 
        id as "_id", 
        content, 
        createdat as "createdAt",
        CASE 
          WHEN senderid = (SELECT user_id FROM orders WHERE id = $1) THEN 'student'
          ELSE 'tutor'
        END as sender
      FROM messages 
      WHERE orderid = $1
      ORDER BY createdat ASC
    `, [parseInt(assignmentId)]);

    res.json({
      success: true,
      messages: messages
    });

  } catch (error) {
    console.error('Error fetching assignment messages:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch messages', details: error.message });
  }
});

// Post Message (New Endpoint for Frontend)
app.post('/messages', async (req, res) => {
  try {
    const { assignmentId, studentId, tutorId, sender, content } = req.body;
    
    if (!assignmentId || !content) {
      return res.status(400).json({ success: false, error: 'Missing required fields' });
    }

    const sId = parseInt(studentId);
    const tId = parseInt(tutorId);

    const sender_id = sender === 'student' ? sId : tId;
    const receiver_id = sender === 'student' ? tId : sId;

    if (isNaN(sender_id)) {
      return res.status(400).json({ success: false, error: 'Invalid sender ID' });
    }

    const newMessage = await db.one(`
      INSERT INTO messages (orderid, senderid, receiverid, content, read)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING id as "_id", orderid as "assignmentId", senderid, receiverid, content, read, createdat as "createdAt"
    `, [
      parseInt(assignmentId),
      sender_id,
      isNaN(receiver_id) ? null : receiver_id, // Tutor might not be assigned yet
      content,
      false
    ]);

    // Broadcast to SSE clients
    broadcastMessage(assignmentId, {
      ...newMessage,
      sender
    });

    res.json({ 
      success: true, 
      message: 'Message sent successfully', 
      sentMessage: newMessage 
    });

  } catch (error) {
    console.error('Error saving message:', error);
    res.status(500).json({ success: false, error: 'Failed to send message', details: error.message });
  }
});

// Send Message (Original legacy endpoint)
app.post('/send-message', requireAuth, async (req, res) => {
  try {
    const user = req.user;
    const { toUserId, message, orderId } = req.body;

    const newMessage = await db.one(`
      INSERT INTO messages (senderid, receiverid, content, orderid, read)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING id, senderid, receiverid, content, orderid, read, createdat as created_at
    `, [
      user.id,
      parseInt(toUserId),
      message,
      orderId ? parseInt(orderId) : null,
      false
    ]);

    res.json({ 
      message: 'Message sent successfully', 
      sentMessage: newMessage 
    });

  } catch (error) {
    console.error('Error sending message:', error);
    res.status(500).json({ error: 'Failed to send message', details: error.message });
  }
});

// Get Messages
app.get('/messages/:email', async (req, res) => {
  try {
    const { email } = req.params;
    const user = await db.oneOrNone('SELECT id FROM users WHERE email = $1', [email]);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Get all messages for the user
    const userMessages = await db.manyOrNone(`
      SELECT *, createdat as "createdAt" FROM messages 
      WHERE senderid = $1 OR receiverid = $1
      ORDER BY createdat ASC
    `, [user.id]);

    // Mark unread messages as read
    await db.none(`
      UPDATE messages 
      SET read = true 
      WHERE receiverid = $1 AND read = false
    `, [user.id]);

    res.json(userMessages);

  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ error: 'Failed to fetch messages', details: error.message });
  }
});

// Chat Settings Routes
app.get('/student/get-chat-settings', async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) {
      return res.status(400).json({ success: false, message: 'User ID is required' });
    }

    const settings = await db.oneOrNone('SELECT * FROM chat_settings WHERE user_id = $1', [parseInt(userId)]);

    if (settings) {
      res.json({
        success: true,
        settings: {
          theme: settings.theme,
          customColors: settings.custom_colors,
          sounds: settings.sounds
        }
      });
    } else {
      res.json({
        success: true,
        settings: {
          theme: 'default',
          customColors: null,
          sounds: { sendSound: 'send.mp3', receiveSound: 'receive.mp3', volume: 50 }
        }
      });
    }
  } catch (error) {
    console.error('Error getting chat settings:', error);
    res.status(500).json({ success: false, message: 'Failed to get chat settings', error: error.message });
  }
});

app.get('/student/get-chat-theme', async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) {
      return res.status(400).json({ success: false, message: 'User ID is required' });
    }

    const settings = await db.oneOrNone('SELECT * FROM chat_settings WHERE user_id = $1', [parseInt(userId)]);

    if (settings) {
      res.json({
        success: true,
        theme: {
          theme: settings.theme,
          customColors: settings.custom_colors
        }
      });
    } else {
      res.json({
        success: true,
        theme: {
          theme: 'default',
          customColors: null
        }
      });
    }
  } catch (error) {
    console.error('Error getting chat theme:', error);
    res.status(500).json({ success: false, message: 'Failed to get chat theme', error: error.message });
  }
});

app.post('/student/save-chat-settings', async (req, res) => {
  try {
    const { userId, theme, customColors, sounds } = req.body;
    if (!userId) {
      return res.status(400).json({ success: false, message: 'User ID is required' });
    }

    await db.none(`
      INSERT INTO chat_settings (user_id, theme, custom_colors, sounds, updated_at)
      VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
      ON CONFLICT (user_id) DO UPDATE SET
        theme = EXCLUDED.theme,
        custom_colors = EXCLUDED.custom_colors,
        sounds = EXCLUDED.sounds,
        updated_at = CURRENT_TIMESTAMP
    `, [parseInt(userId), theme || 'default', customColors || null, sounds || null]);

    res.json({ success: true, message: 'Chat settings saved successfully' });
  } catch (error) {
    console.error('Error saving chat settings:', error);
    res.status(500).json({ success: false, message: 'Failed to save chat settings', error: error.message });
  }
});

// Get All Users (Admin only)
app.get('/admin/users', requireAdmin, async (req, res) => {
  try {
    const usersList = await db.manyOrNone(`
      SELECT id, name, email, role, phone, school, balance, verified, profile_image as "profileImage", created_at as "createdAt"
      FROM users
    `);

    res.json(usersList);

  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Failed to fetch users', details: error.message });
  }
});

// Get All Orders (Admin only)
app.get('/admin/orders', requireAdmin, async (req, res) => {
  try {
    const ordersList = await db.manyOrNone(`
      SELECT 
        id, user_id as "userId", assignment_title as "assignmentTitle", 
        subject, order_type as "orderType", instructions, deadline, 
        total_cost as "totalCost", status, files, tutor_id as "tutorId", 
        payment_id as "paymentId", created_at as "createdAt", updated_at as "updatedAt",
        coupon_code as "couponCode", discount_amount as "discountAmount"
      FROM orders
    `);
    res.json(ordersList);
  } catch (error) {
    console.error('Error fetching orders:', error);
    res.status(500).json({ error: 'Failed to fetch orders', details: error.message });
  }
});

 // Get All Tutor Students (Tutor only)
app.get('/tutor/students', requireTutor, async (req, res) => {
  try {
    const tutorId = req.user.id;
    let students;
    
    // For admins, show all students
    if (req.user.role === 'admin') {
      students = await db.manyOrNone(`
        SELECT id, name, email, phone, school, profile_image as "profileImage", balance, created_at as "createdAt", last_login as "lastLogin", is_suspended as "isSuspended"
        FROM users
        WHERE role = 'student' -- Only show students, not admins or tutors
      `);
    } else {
      // For regular tutors, only show students with orders assigned to them
      const tutorOrders = await db.manyOrNone('SELECT DISTINCT user_id FROM orders WHERE tutor_id = $1', [tutorId]);
      const studentIds = [...new Set(tutorOrders.map(o => o.user_id))];
      
      if (studentIds.length === 0) {
        return res.json({ success: true, students: [] });
      }

      students = await db.manyOrNone(`
        SELECT id, name, email, phone, school, profile_image as "profileImage", balance, created_at as "createdAt", last_login as "lastLogin", is_suspended as "isSuspended"
        FROM users
        WHERE id = ANY($1)
      `, [studentIds]);
    }

    // Add stats to each student
    const studentsWithStats = await Promise.all(students.map(async (student) => {
      // Get student's orders
      let ordersQuery = 'SELECT * FROM orders WHERE user_id = $1';
      let queryParams = [student.id];
      
      // For non-admin tutors, only include orders assigned to them
      if (req.user.role !== 'admin') {
        ordersQuery += ' AND tutor_id = $2';
        queryParams.push(tutorId);
      }
      
      const studentOrders = await db.manyOrNone(ordersQuery, queryParams);
      
      // Calculate stats
      const totalAssignments = studentOrders.length;
      const completedAssignments = studentOrders.filter(order => order.status === 'completed').length;
      const activeAssignments = studentOrders.filter(order => order.status !== 'completed' && order.status !== 'cancelled').length;
      const totalSpent = studentOrders.reduce((sum, order) => sum + parseFloat(order.total_cost || 0), 0);
      
      return {
        ...student,
        stats: {
          totalAssignments,
          completedAssignments,
          activeAssignments,
          totalSpent
        },
        balance: await db.one('SELECT balance FROM users WHERE id = $1', [student.id]).then(result => result.balance),
        createdAt: await db.one('SELECT created_at FROM users WHERE id = $1', [student.id]).then(result => result.created_at)
      };
    }));

    res.json({ success: true, students: studentsWithStats });

  } catch (error) {
    console.error('Error fetching tutor students:', error);
    res.status(500).json({ error: 'Failed to fetch tutor students', details: error.message });
  }
});

// Admin: Suspend/Unsuspend User
app.post('/api/admin/users/:id/suspend', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { suspend, reason } = req.body;
    
    const user = await db.oneOrNone('SELECT * FROM users WHERE id = $1', [parseInt(id)]);
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    await db.none('UPDATE users SET is_suspended = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2', [suspend, parseInt(id)]);

    // Send notification email
    if (suspend) {
      sendMailSafe({
        to: user.email,
        ...emailTemplates.accountSuspended(user.name, reason)
      }).catch(err => console.error('Failed to send suspension email:', err));
    } else {
      sendMailSafe({
        to: user.email,
        ...emailTemplates.accountUnsuspended(user.name)
      }).catch(err => console.error('Failed to send unsuspension email:', err));
    }

    res.json({ success: true, message: `User ${suspend ? 'suspended' : 'unsuspended'} successfully` });
  } catch (error) {
    console.error('Error suspending user:', error);
    res.status(500).json({ success: false, error: 'Failed to suspend user', details: error.message });
  }
});

// Admin: Delete User and all associated data
app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    const user = await db.oneOrNone('SELECT * FROM users WHERE id = $1', [parseInt(id)]);
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    // Use a transaction to delete user and all related data
    await db.tx(async t => {
      // Delete orders (this might also need to delete order files, but for now we delete from DB)
      await t.none('DELETE FROM orders WHERE user_id = $1', [parseInt(id)]);
      // Delete payments
      await t.none('DELETE FROM payments WHERE user_id = $1', [parseInt(id)]);
      // Delete chat settings
      await t.none('DELETE FROM chat_settings WHERE user_id = $1', [parseInt(id)]);
      // Finally delete the user
      await t.none('DELETE FROM users WHERE id = $1', [parseInt(id)]);
    });

    // Send notification email
    sendMailSafe({
      to: user.email,
      ...emailTemplates.accountDeleted(user.name)
    }).catch(err => console.error('Failed to send deletion email:', err));

    res.json({ success: true, message: 'User and all associated data deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ success: false, error: 'Failed to delete user', details: error.message });
  }
});

// Get All Tutor Assignments (Tutor only)
app.get('/tutor/assignments', requireTutor, async (req, res) => {
  try {
    const tutorId = req.user.id;
    // For admins, show all orders, otherwise only those assigned to the tutor
    let assignments;
    if (req.user.role === 'admin') {
       assignments = await db.manyOrNone(`
         SELECT 
           o.id, o.user_id as "userId", o.assignment_title as "assignmentTitle", 
           o.subject, o.order_type as "orderType", o.instructions, o.deadline, 
           o.total_cost as "totalCost", o.status, o.files, o.tutor_id as "tutorId", 
           o.payment_id as "paymentId", o.created_at as "createdAt", o.updated_at as "updatedAt",
           o.pages, o.description, o.additional_requirements as "additionalRequirements",
           o.coupon_code as "couponCode", o.discount_amount as "discountAmount",
           u.name as "studentName", u.email as "studentEmail",
           json_build_object('id', u.id, 'name', u.name, 'email', u.email) as "userId"
         FROM orders o
         LEFT JOIN users u ON o.user_id = u.id
         ORDER BY o.created_at DESC
       `);
    } else {
      assignments = await db.manyOrNone(`
        SELECT 
          o.id, o.user_id as "userId", o.assignment_title as "assignmentTitle", 
          o.subject, o.order_type as "orderType", o.instructions, o.deadline, 
          o.total_cost as "totalCost", o.status, o.files, o.tutor_id as "tutorId", 
          o.payment_id as "paymentId", o.created_at as "createdAt", o.updated_at as "updatedAt",
          o.pages, o.description, o.additional_requirements as "additionalRequirements",
          u.name as "studentName", u.email as "studentEmail",
          json_build_object('id', u.id, 'name', u.name, 'email', u.email) as "userId"
        FROM orders o
        LEFT JOIN users u ON o.user_id = u.id
        WHERE o.tutor_id = $1
        ORDER BY o.created_at DESC
      `, [tutorId]);
    }
    
    // Process files to match frontend expectations
    const processedAssignments = assignments.map(assignment => {
      // Convert files array to object format with originalName and filename
      const processedFiles = (assignment.files || []).map(filename => ({
        originalName: filename.split('-').slice(1).join('-'), // Remove prefix
        filename: filename
      }));
      
      return {
        ...assignment,
        files: processedFiles
      };
    });
    
    res.json({ success: true, assignments: processedAssignments });

  } catch (error) {
    console.error('Error fetching tutor assignments:', error);
    res.status(500).json({ error: 'Failed to fetch tutor assignments', details: error.message });
  }
});

// Get Pending Payments (Tutor only)
app.get('/tutor/pending-payments', requireTutor, async (req, res) => {
  try {
    const tutorId = req.user.id;
    // For simplicity, we'll fetch payments that are marked as 'pending'
    // and join with users to get the expected format
    let payments;
    if (req.user.role === 'admin') {
      payments = await db.manyOrNone(`
        SELECT 
          p.id, p.amount::FLOAT, p.payment_method as "method", p.transaction_id as "reference", p.status, p.created_at as "createdAt",
          json_build_object('name', u.name, 'email', u.email) as "user",
          CASE WHEN p.proof_file IS NOT NULL THEN
            json_build_object('filename', p.proof_file, 'originalName', p.original_name)
          ELSE NULL END as "proofFile"
        FROM payments p
        JOIN users u ON p.user_id = u.id
        WHERE p.status = 'pending'
        ORDER BY p.created_at DESC
      `);
    } else {
      // If it's a tutor, they might only see payments for their assignments
      payments = await db.manyOrNone(`
        SELECT 
          p.id, p.amount::FLOAT, p.payment_method as "method", p.transaction_id as "reference", p.status, p.created_at as "createdAt",
          json_build_object('name', u.name, 'email', u.email) as "user",
          CASE WHEN p.proof_file IS NOT NULL THEN
            json_build_object('filename', p.proof_file, 'originalName', p.original_name)
          ELSE NULL END as "proofFile"
        FROM payments p
        JOIN users u ON p.user_id = u.id
        JOIN orders o ON p.order_id = o.id
        WHERE p.status = 'pending' AND o.tutor_id = $1
        ORDER BY p.created_at DESC
      `, [tutorId]);
    }
    res.json({ success: true, payments });
  } catch (error) {
    console.error('Error fetching pending payments:', error);
    res.status(500).json({ error: 'Failed to fetch pending payments', details: error.message });
  }
});

// Get Orders by Tutor (Tutor only)
app.get('/tutor/orders/:email', requireTutor, async (req, res) => {
  try {
    const tutor = req.user;
    const tutorOrders = await db.manyOrNone(`
      SELECT 
        id, user_id as "userId", assignment_title as "assignmentTitle", 
        subject, order_type as "orderType", instructions, deadline, 
        total_cost as "totalCost", status, files, tutor_id as "tutorId", 
        payment_id as "paymentId", created_at as "createdAt", updated_at as "updatedAt",
        coupon_code as "couponCode", discount_amount as "discountAmount"
      FROM orders 
      WHERE tutor_id = $1
    `, [tutor.id]);
    res.json(tutorOrders);

  } catch (error) {
    console.error('Error fetching tutor orders:', error);
    res.status(500).json({ error: 'Failed to fetch tutor orders', details: error.message });
  }
});

// Dashboard Stats (Admin only)
app.get('/admin/stats', requireAdmin, async (req, res) => {
  try {
    const totalUsers = await db.one('SELECT COUNT(*) FROM users');
    const totalOrders = await db.one('SELECT COUNT(*) FROM orders');
    const completedOrders = await db.one('SELECT COUNT(*) FROM orders WHERE status = $1', ['completed']);
    const pendingOrders = await db.one('SELECT COUNT(*) FROM orders WHERE status IN ($1, $2)', ['pending', 'processing']);
    const totalRevenue = await db.one('SELECT COALESCE(SUM(total_cost), 0) FROM orders WHERE status != $1', ['cancelled']);

    res.json({
      totalUsers: parseInt(totalUsers.count),
      totalOrders: parseInt(totalOrders.count),
      completedOrders: parseInt(completedOrders.count),
      pendingOrders: parseInt(pendingOrders.count),
      totalRevenue: parseFloat(totalRevenue.coalesce)
    });

  } catch (error) {
    console.error('Error fetching dashboard stats:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard stats', details: error.message });
  }
});

// Coupons Management (Admin only)
app.get('/api/admin/coupons', requireAdmin, async (req, res) => {
  try {
    // First check if updated_at column exists
    const hasUpdatedAt = await db.oneOrNone(`
      SELECT EXISTS (
        SELECT 1 
        FROM information_schema.columns 
        WHERE table_name = 'coupons' 
        AND column_name = 'updated_at'
      )
    `);
    
    const selectQuery = hasUpdatedAt.exists ? `
      SELECT 
        id, code, discount_type, discount_value, minimum_order_value, 
        max_usage, used_count, is_active, start_date, end_date, 
        created_at, updated_at
      FROM coupons
      ORDER BY created_at DESC
    ` : `
      SELECT 
        id, code, discount_type, discount_value, minimum_order_value, 
        max_usage, used_count, is_active, start_date, end_date, 
        created_at
      FROM coupons
      ORDER BY created_at DESC
    `;
    
    const coupons = await db.manyOrNone(selectQuery);
    
    res.json({ coupons });
  } catch (error) {
    console.error('Error fetching coupons:', error);
    res.status(500).json({ error: 'Failed to fetch coupons', details: error.message });
  }
});

app.post('/api/admin/coupons', requireAdmin, async (req, res) => {
  try {
    const { code, discountType, discountValue, minimumOrderValue, maxUsage, isActive, isAuto, startDate, endDate } = req.body;
    
    if (!code || discountValue === undefined) {
      return res.status(400).json({ success: false, error: 'Code and discount value are required' });
    }

    const newCoupon = await db.one(`
      INSERT INTO coupons (code, discount_type, discount_value, minimum_order_value, max_usage, is_active, is_auto, start_date, end_date)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING 
        id, code, discount_type, discount_value, minimum_order_value, 
        max_usage, used_count, is_active, is_auto, start_date, end_date, 
        created_at
    `, [
      code.toUpperCase(),
      discountType || 'percentage',
      parseFloat(discountValue),
      parseFloat(minimumOrderValue || 0),
      maxUsage ? parseInt(maxUsage) : null,
      isActive !== false,
      isAuto === true,
      startDate ? new Date(startDate) : null,
      endDate ? new Date(endDate) : null
    ]);

    res.json({ success: true, coupon: newCoupon });
  } catch (error) {
    console.error('Error creating coupon:', error);
    res.status(500).json({ success: false, error: 'Failed to create coupon', details: error.message });
  }
});

app.put('/api/admin/coupons/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { code, discountType, discountValue, minimumOrderValue, maxUsage, isActive, isAuto, startDate, endDate } = req.body;
    
    const updatedCoupon = await db.one(`
      UPDATE coupons 
      SET 
        code = $1, discount_type = $2, discount_value = $3, 
        minimum_order_value = $4, max_usage = $5, is_active = $6, 
        is_auto = $7, start_date = $8, end_date = $9, updated_at = CURRENT_TIMESTAMP
      WHERE id = $10
      RETURNING 
        id, code, discount_type, discount_value, minimum_order_value, 
        max_usage, used_count, is_active, is_auto, start_date, end_date, 
        created_at, updated_at
    `, [
      code.toUpperCase(),
      discountType || 'percentage',
      parseFloat(discountValue),
      parseFloat(minimumOrderValue || 0),
      maxUsage ? parseInt(maxUsage) : null,
      isActive !== false,
      isAuto === true,
      startDate ? new Date(startDate) : null,
      endDate ? new Date(endDate) : null,
      parseInt(id)
    ]);

    res.json({ success: true, coupon: updatedCoupon });
  } catch (error) {
    console.error('Error updating coupon:', error);
    res.status(500).json({ success: false, error: 'Failed to update coupon', details: error.message });
  }
});

app.delete('/api/admin/coupons/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    await db.none('DELETE FROM coupons WHERE id = $1', [parseInt(id)]);
    
    res.json({ success: true, message: 'Coupon deleted successfully' });
  } catch (error) {
    console.error('Error deleting coupon:', error);
    res.status(500).json({ success: false, error: 'Failed to delete coupon', details: error.message });
  }
});

// Get active auto-applied coupon
app.get('/api/coupons/auto', async (req, res) => {
  try {
    const now = new Date();
    const autoCoupon = await db.oneOrNone(`
      SELECT * FROM coupons 
      WHERE is_active = TRUE 
      AND is_auto = TRUE 
      AND (start_date IS NULL OR start_date <= $1)
      AND (end_date IS NULL OR end_date >= $1)
      AND (max_usage IS NULL OR used_count < max_usage)
      LIMIT 1
    `, [now]);

    if (autoCoupon) {
      res.json({ 
        success: true, 
        coupon: {
          id: autoCoupon.id,
          code: autoCoupon.code,
          discount_type: autoCoupon.discount_type,
          discount_value: parseFloat(autoCoupon.discount_value),
          minimum_order_value: parseFloat(autoCoupon.minimum_order_value)
        }
      });
    } else {
      res.json({ success: true, coupon: null });
    }
  } catch (error) {
    console.error('Error fetching auto coupon:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch auto coupon' });
  }
});

// Coupon application and validation
app.get(['/api/coupons/validate', '/api/coupon/apply'], async (req, res) => {
  try {
    const { code, userId } = req.query;
    if (!code) {
      return res.status(400).json({ success: false, error: 'Coupon code is required' });
    }

    const coupon = await db.oneOrNone('SELECT * FROM coupons WHERE code = $1 AND is_active = TRUE', [code.toUpperCase()]);

    if (!coupon) {
      return res.status(404).json({ success: false, error: 'Invalid or inactive coupon code' });
    }

    const now = new Date();
    if (coupon.start_date && new Date(coupon.start_date) > now) {
      return res.status(400).json({ success: false, error: 'Coupon is not yet active' });
    }
    if (coupon.end_date && new Date(coupon.end_date) < now) {
      return res.status(400).json({ success: false, error: 'Coupon has expired' });
    }
    if (coupon.max_usage && coupon.used_count >= coupon.max_usage) {
      return res.status(400).json({ success: false, error: 'Coupon usage limit reached' });
    }

    res.json({ 
      success: true, 
      coupon: {
        id: coupon.id,
        code: coupon.code,
        discount_type: coupon.discount_type,
        discount_value: parseFloat(coupon.discount_value),
        minimum_order_value: parseFloat(coupon.minimum_order_value)
      } 
    });
  } catch (error) {
    console.error('Error validating coupon:', error);
    res.status(500).json({ success: false, error: 'Failed to validate coupon' });
  }
});

app.post('/api/coupons/redeem', async (req, res) => {
  try {
    const { couponCode, userId, orderId, orderAmount } = req.body;
    
    if (!couponCode) {
      return res.status(400).json({ success: false, error: 'Coupon code is required' });
    }

    // Increment used_count for the coupon
    await db.none('UPDATE coupons SET used_count = used_count + 1 WHERE code = $1', [couponCode.toUpperCase()]);

    res.json({ success: true, message: 'Coupon redeemed successfully' });
  } catch (error) {
    console.error('Error redeeming coupon:', error);
    res.status(500).json({ success: false, error: 'Failed to redeem coupon' });
  }
});

// Alias for save-chat-settings used by some frontend components
app.post('/student/save-chat-theme', async (req, res) => {
  try {
    const { userId, theme, customColors } = req.body;
    if (!userId) {
      return res.status(400).json({ success: false, message: 'User ID is required' });
    }

    await db.none(`
      INSERT INTO chat_settings (user_id, theme, custom_colors, updated_at)
      VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
      ON CONFLICT (user_id) DO UPDATE SET
        theme = EXCLUDED.theme,
        custom_colors = EXCLUDED.custom_colors,
        updated_at = CURRENT_TIMESTAMP
    `, [parseInt(userId), theme || 'default', customColors || null]);

    res.json({ success: true, message: 'Chat theme saved successfully' });
  } catch (error) {
    console.error('Error saving chat theme:', error);
    res.status(500).json({ success: false, message: 'Failed to save chat theme', error: error.message });
  }
});

// Serve static files from frontend
app.use('/uploads', express.static('uploads'));

app.use(express.static(__dirname));

// Initialize server
const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT} with PostgreSQL database`);
});
