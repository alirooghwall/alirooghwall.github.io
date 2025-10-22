require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const path = require('path');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files
app.use(express.static(path.join(__dirname)));

// JWT and email config
const JWT_SECRET = process.env.JWT_SECRET;
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;
const BASE_URL = process.env.BASE_URL || 'https://mars-empire-mlm.onrender.com';
const PORT = process.env.PORT || 3000;

// Sanity checks
if (!JWT_SECRET) {
  console.error('❌ JWT_SECRET is not set');
  process.exit(1);
}
if (!process.env.MONGO_URI) {
  console.error('❌ MONGO_URI is not set');
  process.exit(1);
}
if (!EMAIL_USER || !EMAIL_PASS) {
  console.error('❌ EMAIL_USER and EMAIL_PASS are not set');
  process.exit(1);
}

// Email transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: EMAIL_USER, pass: EMAIL_PASS }
});

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB...'))
  .catch((err) => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  });

// User model with verification and reset
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  accountType: { type: String, enum: ['student', 'participant', 'admin'], default: 'participant' },
  mlmLevel: { type: String, default: 'beginner' }, // To be verified by admin
  phone: String,
  leaderName: String,
  userId: { type: String, unique: true }, // System-generated ID
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  isVerified: { type: Boolean, default: false },
  verificationToken: String,
  resetToken: String,
  resetExpires: Date,
  createdAt: { type: Date, default: Date.now },
});
const User = mongoose.model('User', userSchema);

// Checklist model
const checklistSchema = new mongoose.Schema({
  title: String,
  items: [{ text: String, completed: { type: Boolean, default: false } }],
  userId: String, // Reference to user
  isPredefined: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
});
const Checklist = mongoose.model('Checklist', checklistSchema);

// Tree model for MLM hierarchy
const treeSchema = new mongoose.Schema({
  userId: String, // The user
  leaderId: String, // Their leader
  verified: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
});
const Tree = mongoose.model('Tree', treeSchema);

// Middleware to check auth
const requireAuth = (req, res, next) => {
  const token = req.cookies?.token || req.headers.authorization?.split(' ')[1];
  if (!token) return res.redirect('/signin?redirect=' + encodeURIComponent(req.originalUrl));
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.clearCookie('token');
    res.redirect('/signin?redirect=' + encodeURIComponent(req.originalUrl));
  }
};

// Middleware to check verification
const requireVerified = (req, res, next) => {
  if (!req.user.isVerified) return res.send('<p>Please verify your email first. <a href="/resend-verification">Resend verification</a></p>');
  next();
};

// Middleware to check admin
const requireAdmin = (req, res, next) => {
  if (req.user.accountType !== 'admin') return res.status(403).send('<p>Access denied. Admin only.</p>');
  next();
};

// Health check
app.get('/health', (req, res) => res.send('OK'));

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/elements', requireAuth, requireVerified, (req, res) => {
  res.sendFile(path.join(__dirname, 'elements.html'));
});

app.get('/generic', requireAuth, requireVerified, (req, res) => {
  res.sendFile(path.join(__dirname, 'generic.html'));
});

// Signup with beautified UI
app.get('/signup', (req, res) => {
  const saved = req.cookies?.signupData ? JSON.parse(req.cookies.signupData) : {};
  res.send(`
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <title>Sign Up | MARS EMPIRE</title>
      <meta name="description" content="Join MARS EMPIRE for exclusive MLM resources and AI companion.">
      <link rel="stylesheet" href="assets/css/main.css">
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
      <style>
        body { background: linear-gradient(135deg, #1e1e2e, #2a2a3e); color: #ffffff; font-family: 'Source Sans Pro', sans-serif; margin: 0; padding: 0; }
        main { max-width: 400px; margin: 5rem auto; padding: 2rem; background: rgba(255,255,255,0.1); border-radius: 12px; box-shadow: 0 0 20px rgba(0,0,0,0.5); animation: fadeIn 0.5s; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(-20px); } to { opacity: 1; transform: translateY(0); } }
        h1 { text-align: center; color: #ff6b6b; margin-bottom: 1.5rem; }
        form { display: flex; flex-direction: column; }
        .input-group { position: relative; margin-bottom: 1rem; }
        input { padding: 0.75rem 0.75rem 0.75rem 2.5rem; border: 1px solid #ccc; border-radius: 8px; background: #333; color: #fff; font-size: 1rem; transition: border-color 0.3s; }
        input:focus { border-color: #ff6b6b; outline: none; }
        .input-group i { position: absolute; left: 0.75rem; top: 50%; transform: translateY(-50%); color: #ccc; }
        button { padding: 0.75rem; background: linear-gradient(45deg, #ff6b6b, #ff5252); color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 1rem; transition: background 0.3s; }
        button:hover { background: linear-gradient(45deg, #ff5252, #ff3838); }
        button:disabled { background: #666; cursor: not-allowed; }
        p { text-align: center; margin-top: 1rem; }
        a { color: #4ecdc4; text-decoration: none; transition: color 0.3s; }
        a:hover { color: #45b7aa; }
        .error { color: #ff6b6b; font-size: 0.9rem; margin-top: 0.5rem; }
      </style>
    </head>
    <body>
      <main>
        <h1><i class="fas fa-rocket"></i> Sign Up</h1>
        <form method="post" action="/signup" id="signupForm">
          <div class="input-group">
            <i class="fas fa-user"></i>
            <input name="name" value="${saved.name || ''}" placeholder="Name" required aria-label="Name" />
          </div>
          <div class="input-group">
            <i class="fas fa-envelope"></i>
            <input name="email" type="email" value="${saved.email || ''}" placeholder="Email" required aria-label="Email" />
          </div>
          <div class="input-group">
            <i class="fas fa-lock"></i>
            <input name="password" type="password" placeholder="Password (min 8 chars)" required aria-label="Password" minlength="8" />
          </div>
          <div class="input-group">
            <i class="fas fa-user-tag"></i>
            <select name="accountType" required aria-label="Account Type">
              <option value="student" ${saved.accountType === 'student' ? 'selected' : ''}>Student</option>
              <option value="participant" ${saved.accountType === 'participant' ? 'selected' : ''}>Participant</option>
            </select>
          </div>
          <div class="input-group">
            <i class="fas fa-level-up-alt"></i>
            <input name="mlmLevel" value="${saved.mlmLevel || ''}" placeholder="MLM Level (e.g., beginner)" required aria-label="MLM Level" />
          </div>
          <div class="input-group">
            <i class="fas fa-phone"></i>
            <input name="phone" value="${saved.phone || ''}" placeholder="Phone" required aria-label="Phone" />
          </div>
          <div class="input-group">
            <i class="fas fa-user-friends"></i>
            <input name="leaderName" value="${saved.leaderName || ''}" placeholder="Leader's Name" required aria-label="Leader's Name" />
          </div>
          <button type="submit" id="submitBtn"><i class="fas fa-paper-plane"></i> Create Account</button>
        </form>
        <p><a href="/signin">Already have an account? Sign In</a></p>
        <p><a href="/">Back to Home</a></p>
      </main>
      <script>
        const form = document.getElementById('signupForm');
        const submitBtn = document.getElementById('submitBtn');
        form.addEventListener('submit', () => {
          submitBtn.disabled = true;
          submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Signing Up...';
        });
        document.querySelectorAll('input').forEach(input => {
          input.addEventListener('input', () => {
            const data = { name: document.querySelector('[name=name]').value, email: document.querySelector('[name=email]').value };
            document.cookie = 'signupData=' + JSON.stringify(data) + '; path=/; secure; samesite=strict';
          });
        });
      </script>
    </body>
    </html>
  `);
});

app.post('/signup', async (req, res) => {
  try {
    const { name, email, password, accountType, mlmLevel, phone, leaderName } = req.body;
    if (!name || !email || !password || password.length < 8 || !accountType || !mlmLevel || !phone || !leaderName) {
      return res.status(400).send('<script>alert("All fields are required. Password must be at least 8 characters."); window.location.href="/signup";</script>');
    }

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).send('<script>alert("Email already registered"); window.location.href="/signup";</script>');
    }

    const hashed = await bcrypt.hash(password, 10);
    const token = crypto.randomBytes(32).toString('hex');
    const userId = 'ME' + Date.now() + Math.random().toString(36).substr(2, 5).toUpperCase(); // System-generated ID
    const newUser = new User({ name, email, password: hashed, accountType, mlmLevel, phone, leaderName, userId, status: 'pending', verificationToken: token });
    await newUser.save();

    const mailOptions = {
      from: EMAIL_USER,
      to: email,
      subject: 'Verify your email - MARS EMPIRE',
      html: `<p>Click <a href="${BASE_URL}/verify/${token}">here</a> to verify your account. Your account will be reviewed by an admin before approval.</p>`
    };
    await transporter.sendMail(mailOptions);

    res.send('<script>alert("Signup successful! Check your email to verify. Your account is pending admin approval."); window.location.href="/signin";</script>');
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).send('<script>alert("Server error"); window.location.href="/signup";</script>');
  }
});

// Verify email with logging
app.get('/verify/:token', async (req, res) => {
  console.log('Verifying token:', req.params.token);
  try {
    const user = await User.findOne({ verificationToken: req.params.token });
    if (!user) {
      console.log('User not found for token');
      return res.send('<p>Invalid token. <a href="/signup">Sign up</a></p>');
    }
    user.isVerified = true;
    user.verificationToken = undefined;
    await user.save();
    console.log('User verified:', user.email);
    res.send('<p>Email verified! <a href="/signin">Sign in</a></p>');
  } catch (err) {
    console.error('Verification error:', err);
    res.status(500).send('<p>Server error</p>');
  }
});

// Resend verification
app.get('/resend-verification', (req, res) => {
  res.send(`
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Resend Verification | MARS EMPIRE</title>
      <link rel="stylesheet" href="assets/css/main.css">
    </head>
    <body>
      <main style="max-width:400px;margin:5rem auto;padding:2rem;">
        <h1>Resend Verification</h1>
        <form method="post" action="/resend-verification">
          <input name="email" type="email" placeholder="Email" required />
          <button type="submit">Resend</button>
        </form>
      </main>
    </body>
    </html>
  `);
});

app.post('/resend-verification', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user || user.isVerified) return res.send('<p>No unverified account found.</p>');

    const token = crypto.randomBytes(32).toString('hex');
    user.verificationToken = token;
    await user.save();

    const mailOptions = {
      from: EMAIL_USER,
      to: email,
      subject: 'Verify your email - MARS EMPIRE',
      html: `<p>Click <a href="${BASE_URL}/verify/${token}">here</a> to verify your account.</p>`
    };
    await transporter.sendMail(mailOptions);

    res.send('<p>Verification email sent!</p>');
  } catch (err) {
    console.error('Resend error:', err);
    res.status(500).send('<p>Server error</p>');
  }
});

// Signin with beautified UI
app.get('/signin', (req, res) => {
  const saved = req.cookies?.signinData ? JSON.parse(req.cookies.signinData) : {};
  const redirect = req.query.redirect || '/';
  res.send(`
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <title>Sign In | MARS EMPIRE</title>
      <meta name="description" content="Sign in to access MARS EMPIRE resources.">
      <link rel="stylesheet" href="assets/css/main.css">
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
      <style>
        body { background: linear-gradient(135deg, #1e1e2e, #2a2a3e); color: #ffffff; font-family: 'Source Sans Pro', sans-serif; margin: 0; padding: 0; }
        main { max-width: 400px; margin: 5rem auto; padding: 2rem; background: rgba(255,255,255,0.1); border-radius: 12px; box-shadow: 0 0 20px rgba(0,0,0,0.5); animation: fadeIn 0.5s; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(-20px); } to { opacity: 1; transform: translateY(0); } }
        h1 { text-align: center; color: #4ecdc4; margin-bottom: 1.5rem; }
        form { display: flex; flex-direction: column; }
        .input-group { position: relative; margin-bottom: 1rem; }
        input { padding: 0.75rem 0.75rem 0.75rem 2.5rem; border: 1px solid #ccc; border-radius: 8px; background: #333; color: #fff; font-size: 1rem; transition: border-color 0.3s; }
        input:focus { border-color: #4ecdc4; outline: none; }
        .input-group i { position: absolute; left: 0.75rem; top: 50%; transform: translateY(-50%); color: #ccc; }
        button { padding: 0.75rem; background: linear-gradient(45deg, #4ecdc4, #45b7aa); color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 1rem; transition: background 0.3s; }
        button:hover { background: linear-gradient(45deg, #45b7aa, #3da08e); }
        button:disabled { background: #666; cursor: not-allowed; }
        p { text-align: center; margin-top: 1rem; }
        a { color: #ff6b6b; text-decoration: none; transition: color 0.3s; }
        a:hover { color: #ff5252; }
        .forgot { font-size: 0.9rem; margin-top: 0.5rem; }
      </style>
    </head>
    <body>
      <main>
        <h1><i class="fas fa-sign-in-alt"></i> Sign In</h1>
        <form method="post" action="/signin" id="signinForm">
          <input type="hidden" name="redirect" value="${redirect}" />
          <div class="input-group">
            <i class="fas fa-envelope"></i>
            <input name="email" type="email" value="${saved.email || ''}" placeholder="Email" required aria-label="Email" />
          </div>
          <div class="input-group">
            <i class="fas fa-lock"></i>
            <input name="password" type="password" placeholder="Password" required aria-label="Password" />
          </div>
          <button type="submit" id="submitBtn"><i class="fas fa-sign-in-alt"></i> Sign In</button>
        </form>
        <p class="forgot"><a href="/forgot-password">Forgot password?</a></p>
        <p><a href="/signup">Create an account</a></p>
        <p><a href="/">Back to Home</a></p>
      </main>
      <script>
        const form = document.getElementById('signinForm');
        const submitBtn = document.getElementById('submitBtn');
        form.addEventListener('submit', () => {
          submitBtn.disabled = true;
          submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Signing In...';
        });
        document.querySelectorAll('input').forEach(input => {
          input.addEventListener('input', () => {
            const data = { email: document.querySelector('[name=email]').value };
            document.cookie = 'signinData=' + JSON.stringify(data) + '; path=/; secure; samesite=strict';
          });
        });
      </script>
    </body>
    </html>
  `);
});

app.post('/signin', async (req, res) => {
  try {
    const { email, password, redirect } = req.body;
    if (!email || !password) {
      return res.status(400).send('<script>alert("Missing email or password"); window.location.href="/signin";</script>');
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).send('<script>alert("User not found"); window.location.href="/signin";</script>');
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).send('<script>alert("Invalid password"); window.location.href="/signin";</script>');
    }

    if (!user.isVerified) {
      return res.send('<script>alert("Please verify your email first"); window.location.href="/resend-verification";</script>');
    }

    if (user.status !== 'approved') {
      return res.send('<script>alert("Your account is pending admin approval"); window.location.href="/signin";</script>');
    }

    const token = jwt.sign({ email: user.email, isVerified: user.isVerified }, JWT_SECRET, { expiresIn: '1d' });
    res.cookie('token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // only true online, false locally
    sameSite: 'lax', // allows browser to send cookie with links and form posts
    maxAge: 86400000
  });

    res.redirect(redirect || '/');
  } catch (err) {
    console.error('Signin error:', err);
    res.status(500).send('<script>alert("Server error"); window.location.href="/signin";</script>');
  }
});

// Forgot password
app.get('/forgot-password', (req, res) => {
  res.send(`
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Forgot Password | MARS EMPIRE</title>
      <link rel="stylesheet" href="assets/css/main.css">
    </head>
    <body>
      <main style="max-width:400px;margin:5rem auto;padding:2rem;">
        <h1>Forgot Password</h1>
        <form method="post" action="/forgot-password">
          <input name="email" type="email" placeholder="Email" required />
          <button type="submit">Send Reset Link</button>
        </form>
      </main>
    </body>
    </html>
  `);
});

app.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.send('<p>No account found.</p>');

    const token = crypto.randomBytes(32).toString('hex');
    user.resetToken = token;
    user.resetExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    const mailOptions = {
      from: EMAIL_USER,
      to: email,
      subject: 'Reset your password - MARS EMPIRE',
      html: `<p>Click <a href="${BASE_URL}/reset-password/${token}">here</a> to reset your password.</p>`
    };
    await transporter.sendMail(mailOptions);

    res.send('<p>Reset link sent to your email!</p>');
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).send('<p>Server error</p>');
  }
});

app.get('/reset-password/:token', (req, res) => {
  res.send(`
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Reset Password | MARS EMPIRE</title>
      <link rel="stylesheet" href="assets/css/main.css">
    </head>
    <body>
      <main style="max-width:400px;margin:5rem auto;padding:2rem;">
        <h1>Reset Password</h1>
        <form method="post" action="/reset-password/${req.params.token}">
          <input name="password" type="password" placeholder="New Password" required minlength="8" />
          <button type="submit">Reset</button>
        </form>
      </main>
    </body>
    </html>
  `);
});

app.post('/reset-password/:token', async (req, res) => {
  try {
    const { password } = req.body;
    const user = await User.findOne({ resetToken: req.params.token, resetExpires: { $gt: Date.now() } });
    if (!user) return res.send('<p>Invalid or expired token.</p>');

    user.password = await bcrypt.hash(password, 10);
    user.resetToken = undefined;
    user.resetExpires = undefined;
    await user.save();

    res.send('<p>Password reset! <a href="/signin">Sign in</a></p>');
  } catch (err) {
    console.error('Reset error:', err);
    res.status(500).send('<p>Server error</p>');
  }
});

// Admin dashboard
app.get('/admin', requireAuth, requireVerified, requireAdmin, async (req, res) => {
  const pendingUsers = await User.find({ status: 'pending' }).select('name email userId accountType mlmLevel phone leaderName createdAt');
  const allUsers = await User.find({}).select('name email userId accountType status');
  res.send(`
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Admin Dashboard | MARS EMPIRE</title>
      <link rel="stylesheet" href="assets/css/main.css">
    </head>
    <body>
      <main style="max-width:1200px;margin:3rem auto;padding:1rem;">
        <h1>Admin Dashboard</h1>
        <h2>Pending Approvals</h2>
        <ul>
          ${pendingUsers.map(u => `
            <li>${u.name} (${u.email}) - ${u.accountType} - ${u.mlmLevel} - ${u.phone} - Leader: ${u.leaderName}
              <form method="post" action="/admin/approve/${u._id}" style="display:inline;">
                <button type="submit">Approve</button>
              </form>
              <form method="post" action="/admin/reject/${u._id}" style="display:inline;">
                <button type="submit">Reject</button>
              </form>
            </li>
          `).join('')}
        </ul>
        <h2>All Users</h2>
        <ul>
          ${allUsers.map(u => `<li>${u.name} (${u.email}) - ${u.accountType} - ${u.status}</li>`).join('')}
        </ul>
        <a href="/profile">Back to Profile</a>
      </main>
    </body>
    </html>
  `);
});

app.post('/admin/approve/:id', requireAuth, requireAdmin, async (req, res) => {
  await User.updateOne({ _id: req.params.id }, { status: 'approved' });
  res.redirect('/admin');
});

app.post('/admin/reject/:id', requireAuth, requireAdmin, async (req, res) => {
  await User.updateOne({ _id: req.params.id }, { status: 'rejected' });
  res.redirect('/admin');
});

// Checklists
app.get('/checklists', requireAuth, requireVerified, async (req, res) => {
  const userChecklists = await Checklist.find({ userId: req.user.email });
  const predefined = await Checklist.find({ isPredefined: true });
  res.send(`
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Checklists | MARS EMPIRE</title>
      <link rel="stylesheet" href="assets/css/main.css">
    </head>
    <body>
      <main style="max-width:800px;margin:3rem auto;padding:1rem;">
        <h1>Checklists</h1>
        <h2>Predefined Checklists</h2>
        ${predefined.map(c => `
          <h3>${c.title}</h3>
          <ul>
            ${c.items.map((item, i) => `
              <li>
                <input type="checkbox" ${item.completed ? 'checked' : ''} onchange="updateItem('${c._id}', ${i}, this.checked)">
                ${item.text}
              </li>
            `).join('')}
          </ul>
        `).join('')}
        <h2>Your Checklists</h2>
        ${userChecklists.map(c => `
          <h3>${c.title}</h3>
          <ul>
            ${c.items.map((item, i) => `
              <li>
                <input type="checkbox" ${item.completed ? 'checked' : ''} onchange="updateItem('${c._id}', ${i}, this.checked)">
                ${item.text}
              </li>
            `).join('')}
          </ul>
        `).join('')}
        <form method="post" action="/checklists/create">
          <input name="title" placeholder="New Checklist Title" required />
          <textarea name="items" placeholder="Items (one per line)" required></textarea>
          <button type="submit">Create</button>
        </form>
        <a href="/profile">Back to Profile</a>
      </main>
      <script>
        async function updateItem(id, index, completed) {
          await fetch('/checklists/update', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id, index, completed })
          });
        }
      </script>
    </body>
    </html>
  `);
});

app.post('/checklists/create', requireAuth, async (req, res) => {
  const { title, items } = req.body;
  const itemList = items.split('\n').map(text => ({ text: text.trim(), completed: false }));
  await new Checklist({ title, items: itemList, userId: req.user.email }).save();
  res.redirect('/checklists');
});

app.post('/checklists/update', requireAuth, async (req, res) => {
  const { id, index, completed } = req.body;
  const checklist = await Checklist.findById(id);
  if (checklist.userId === req.user.email || checklist.isPredefined) {
    checklist.items[index].completed = completed;
    await checklist.save();
  }
  res.sendStatus(200);
});

// Tree view
app.get('/tree', requireAuth, requireVerified, async (req, res) => {
  const trees = await Tree.find({ verified: true }).populate('userId leaderId');
  // Simple list for now, can use D3 later
  res.send(`
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>MLM Tree | MARS EMPIRE</title>
      <link rel="stylesheet" href="assets/css/main.css">
    </head>
    <body>
      <main style="max-width:1000px;margin:3rem auto;padding:1rem;">
        <h1>MLM Hierarchy Tree</h1>
        <ul>
          ${trees.map(t => `<li>${t.userId.name} under ${t.leaderId ? t.leaderId.name : 'Top'}</li>`).join('')}
        </ul>
        ${req.user.accountType === 'admin' ? `
          <h2>Pending Connections</h2>
          <ul>
            ${(await Tree.find({ verified: false })).map(t => `
              <li>${t.userId} under ${t.leaderId}
                <form method="post" action="/tree/verify/${t._id}" style="display:inline;">
                  <button type="submit">Verify</button>
                </form>
              </li>
            `).join('')}
          </ul>
        ` : ''}
        <a href="/profile">Back to Profile</a>
      </main>
    </body>
    </html>
  `);
});

app.post('/tree/verify/:id', requireAuth, requireAdmin, async (req, res) => {
  await Tree.updateOne({ _id: req.params.id }, { verified: true });
  res.redirect('/tree');
});

// RULES PAGE
app.get('/rules', requireAuth, requireVerified, (req, res) => {
  res.send(`
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Rules | MARS EMPIRE</title>
      <link rel="stylesheet" href="assets/css/main.css">
    </head>
    <body>
      <main style="max-width:600px;margin:3rem auto;padding:1rem;">
        <h1>Rules and Guidelines</h1>
        <p>Follow these rules to maintain your account in good standing.</p>
        <ul>
          <li>Respect other members and maintain professionalism.</li>
          <li>Do not share your referral links publicly.</li>
          <li>Withdrawals are only processed for verified users.</li>
          <li>Commissions depend on active downlines.</li>
        </ul>
        <a href="/profile">Back to Profile</a>
      </main>
    </body>
    </html>
  `);
});


// PROFILE PAGE
app.get('/profile', requireAuth, requireVerified, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.user.email }).select('-password');

    if (!user) {
      return res.status(404).send('User not found');
    }

    res.send(`
      <!doctype html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Profile | MARS EMPIRE</title>
        <link rel="stylesheet" href="assets/css/main.css">
      </head>
      <body>
        <main style="max-width:600px;margin:3rem auto;padding:1rem;">
          <h1>Welcome, ${user.name}!</h1>
          <p>Email: ${user.email}</p>
          <p>Account Type: ${user.accountType}</p>
          <p>MLM Level: ${user.mlmLevel}</p>
          <p>Phone: ${user.phone}</p>
          <p>Leader: ${user.leaderName}</p>
          <p>Status: ${user.status}</p>
          <a href="/checklists">Checklists</a> |
          <a href="/tree">MLM Tree</a> |
          <a href="/rules">Rules</a>
        </main>
      </body>
      </html>
    `);
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});


app.post('/update-profile', requireAuth, async (req, res) => {
  try {
    const { name, email, phone, leaderName } = req.body;
    await User.updateOne({ email: req.user.email }, { name, email, phone, leaderName });
    res.send('<p>Profile updated! <a href="/profile">Back</a></p>');
  } catch (err) {
    console.error('Update error:', err);
    res.status(500).send('<p>Server error</p>');
  }
});

// Logout
app.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/');
});

// Contact form
app.post('/contact', (req, res) => {
  const { name, email, message } = req.body;
  console.log(`Contact from ${name} (${email}): ${message}`);
  res.send('<script>alert("Message sent!"); window.location.href="/";</script>');
});

// SEO and misc
app.get('/sitemap.xml', (req, res) => {
  const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
  <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url><loc>${BASE_URL}/</loc></url>
    <url><loc>${BASE_URL}/elements</loc></url>
    <url><loc>${BASE_URL}/generic</loc></url>
  </urlset>`;
  res.header('Content-Type', 'application/xml');
  res.send(sitemap);
});

app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.send('User-agent: *\nAllow: /\nSitemap: ' + BASE_URL + '/sitemap.xml');
});

// 404
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, '404.html'));
});

  // Init after server starts
  Checklist.findOne({ isPredefined: true }).then(existing => {
    if (!existing) {
      new Checklist({
        title: 'MLM Basics',
        items: [
          { text: 'Understand MLM structure', completed: false },
          { text: 'Learn about BizMLM products', completed: false },
          { text: 'Set up your profile', completed: false }
        ],
        isPredefined: true
      }).save().then(() => console.log('Predefined checklists added')).catch(err => console.error('Checklist save error:', err));
    }
  }).catch(err => console.error('Checklist find error:', err));
  
  // Ensure admin account exists and is verified
const createAdmin = async () => {
  try {
    const adminEmail = 'alirooghwall999@gmail.com';
    const adminPassword = 'Login@123';

    const hashed = await bcrypt.hash(adminPassword, 10);

    await User.findOneAndUpdate(
      { email: adminEmail },
      {
        $setOnInsert: {
          name: 'Admin',
          password: hashed,
          accountType: 'admin',
          mlmLevel: 'expert',
          phone: '0000000000',
          leaderName: 'None',
          userId: 'ADMIN001',
          status: 'approved',
          isVerified: true,
          createdAt: new Date()
        }
      },
      { upsert: true }
    );

    console.log(`✅ Admin account ensured: ${adminEmail} / ${adminPassword}`);
  } catch (err) {
    console.error('❌ Admin creation error:', err);
  }
};

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);  

// Call this after server starts
createAdmin();

});