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
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const morgan = require('morgan');
const winston = require('winston');
const { body, validationResult } = require('express-validator');

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(helmet());
app.use(morgan('combined'));

// Winston logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple(),
  }));
}
app.set('view engine', 'ejs');

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // limit each IP to 1000 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

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
mongoose.connect(process.env.MONGO_URI)
  .then(() => logger.info('Connected to MongoDB...'))
  .catch((err) => {
    logger.error('❌ MongoDB connection error:', err);
    process.exit(1);
  });

// Models
const User = require('./models/User');

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
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // The user
  leaderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // Their leader
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

// Check auth status
app.get('/check-auth', (req, res) => {
  const token = req.cookies?.token;
  if (!token) return res.json({ loggedIn: false });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ loggedIn: true, user: decoded });
  } catch {
    res.json({ loggedIn: false });
  }
});

// Routes
// Modal endpoints for sign in/sign up forms
app.get('/modal/signin', (req, res) => {
  res.send(`
    <form method="post" action="${BASE_URL}/signin" id="modalSigninForm">
      <div class="input-group">
        <i class="fas fa-envelope"></i>
        <input name="email" type="email" placeholder="Email" required aria-label="Email" />
      </div>
      <div class="input-group">
        <i class="fas fa-lock"></i>
        <input name="password" type="password" placeholder="Password" required aria-label="Password" />
      </div>
      <button type="submit" id="modalSigninBtn" style="pointer-events: auto; cursor: pointer;"><i class="fas fa-sign-in-alt"></i> Sign In</button>
      <p class="forgot"><a href="${BASE_URL}/forgot-password" target="_blank">Forgot password?</a></p>
      <p><a href="${BASE_URL}/signup" target="_blank">Create an account</a></p>
    </form>
    <script>
      document.getElementById('modalSigninForm').onsubmit = async function(e) {
        e.preventDefault();
        const btn = document.getElementById('modalSigninBtn');
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Signing In...';
        const formData = new FormData(this);
        const res = await fetch('${BASE_URL}/signin', { method: 'POST', body: formData });
        const text = await res.text();
        if (text.includes('window.location.href')) {
          window.location.reload();
        } else {
          btn.disabled = false;
          btn.innerHTML = '<i class="fas fa-sign-in-alt"></i> Sign In';
          document.getElementById('signInFormContainer').innerHTML = text;
        }
      };
    </script>
  `);
});

app.get('/modal/signup', (req, res) => {
  res.send(`
    <form method="post" action="${BASE_URL}/signup" id="modalSignupForm">
      <div class="input-group">
        <i class="fas fa-user"></i>
        <input name="name" placeholder="Name" required aria-label="Name" />
      </div>
      <div class="input-group">
        <i class="fas fa-envelope"></i>
        <input name="email" type="email" placeholder="Email" required aria-label="Email" />
      </div>
      <div class="input-group">
        <i class="fas fa-lock"></i>
        <input name="password" type="password" placeholder="Password (min 8 chars)" required aria-label="Password" minlength="8" />
      </div>
      <div class="input-group">
        <i class="fas fa-user-tag"></i>
        <select name="accountType" required aria-label="Account Type">
          <option value="student">Student</option>
          <option value="participant">Participant</option>
        </select>
      </div>
      <div class="input-group">
        <i class="fas fa-level-up-alt"></i>
        <input name="mlmLevel" placeholder="MLM Level (e.g., beginner)" required aria-label="MLM Level" />
      </div>
      <div class="input-group">
        <i class="fas fa-phone"></i>
        <input name="phone" placeholder="Phone" required aria-label="Phone" />
      </div>
      <div class="input-group">
        <i class="fas fa-user-friends"></i>
        <input name="leaderName" placeholder="Leader's Name" required aria-label="Leader's Name" />
      </div>
      <button type="submit" id="modalSignupBtn" style="pointer-events: auto; cursor: pointer;"><i class="fas fa-paper-plane"></i> Create Account</button>
    </form>
    <script>
      document.getElementById('modalSignupForm').onsubmit = async function(e) {
        e.preventDefault();
        const btn = document.getElementById('modalSignupBtn');
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Signing Up...';
        const formData = new FormData(this);
        const res = await fetch('${BASE_URL}/signup', { method: 'POST', body: formData });
        const text = await res.text();
        if (text.includes('window.location.href')) {
          window.location.reload();
        } else {
          btn.disabled = false;
          btn.innerHTML = '<i class="fas fa-paper-plane"></i> Create Account';
          document.getElementById('signUpFormContainer').innerHTML = text;
        }
      };
    </script>
  `);
});
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

app.post('/signup', [
  body('name').trim().isLength({ min: 1 }).withMessage('Name is required'),
  body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
  body('accountType').isIn(['student', 'participant']).withMessage('Invalid account type'),
  body('mlmLevel').trim().isLength({ min: 1 }).withMessage('MLM level is required'),
  body('phone').trim().isLength({ min: 1 }).withMessage('Phone is required'),
  body('leaderName').trim().isLength({ min: 1 }).withMessage('Leader name is required'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).send('<script>alert("' + errors.array().map(e => e.msg).join(', ') + '"); window.location.href="/signup";</script>');
  }

  try {
    const { name, email, password, accountType, mlmLevel, phone, leaderName } = req.body;

    const existing = await User.findOne({ email });
    if (existing) {
      // If user exists and verified, treat as password change request
      if (existing.isVerified) {
        return res.status(400).send('<script>alert("Account already exists. Use forgot password to reset."); window.location.href="/signin";</script>');
      } else {
        // Resend verification if unverified
        const token = crypto.randomBytes(32).toString('hex');
        existing.verificationToken = token;
        await existing.save();
        const mailOptions = {
          from: EMAIL_USER,
          to: email,
          subject: 'Verify your email - MARS EMPIRE',
          html: `<p>Click <a href="${BASE_URL}/verify/${token}">here</a> to verify your account.</p>`
        };
        await transporter.sendMail(mailOptions);
        return res.send('<script>alert("Verification email resent."); window.location.href="/signin";</script>');
      }
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
    logger.error('Signup error:', err);
    res.status(500).send('<script>alert("Server error"); window.location.href="/signup";</script>');
  }
});

// Verify email with logging
app.get('/verify/:token', async (req, res) => {
  logger.info('Verifying token:', req.params.token);
  try {
    const user = await User.findOne({ verificationToken: req.params.token });
    if (!user) {
      logger.warn('User not found for token');
      return res.send('<p>Invalid token. <a href="/signup">Sign up</a></p>');
    }
    user.isVerified = true;
    user.verificationToken = undefined;
    await user.save();
    logger.info('User verified:', user.email);
    res.send('<p>Email verified! <a href="/signin">Sign in</a></p>');
  } catch (err) {
    logger.error('Verification error:', err);
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
    logger.error('Resend error:', err);
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

app.post('/signin', [
  body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
  body('password').isLength({ min: 1 }).withMessage('Password is required'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).send('<script>alert("' + errors.array().map(e => e.msg).join(', ') + '"); window.location.href="/signin";</script>');
  }

  try {
    const { email, password, redirect } = req.body;

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

    const token = jwt.sign({ email: user.email, isVerified: user.isVerified, accountType: user.accountType }, JWT_SECRET, { expiresIn: '1d' });
    res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', maxAge: 86400000 });
    res.redirect(redirect || '/');
  } catch (err) {
    logger.error('Signin error:', err);
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
    logger.error('Forgot password error:', err);
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
    logger.error('Reset error:', err);
    res.status(500).send('<p>Server error</p>');
  }
});

// Admin dashboard

// Admin dashboard with CRUD for users and tree
app.get('/admin', requireAuth, requireVerified, requireAdmin, async (req, res) => {
  const pendingUsers = await User.find({ status: 'pending' }).select('name email userId accountType mlmLevel phone leaderName createdAt _id');
  const allUsers = await User.find({}).select('name email userId accountType status mlmLevel phone leaderName _id');
  const treeConnections = await Tree.find({}).select('userId leaderId verified _id');
  res.send(`
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Admin Dashboard | MARS EMPIRE</title>
      <link rel="stylesheet" href="assets/css/main.css">
      <style>
        .crud-btn { margin-left: 0.5rem; }
        input, select { margin: 0.2rem; }
      </style>
    </head>
    <body>
      <main style="max-width:1200px;margin:3rem auto;padding:1rem;">
        <h1>Admin Dashboard</h1>
        <h2>Pending Approvals</h2>
        <ul>
          ${pendingUsers.map(u => `
            <li>
              <form method="post" action="/admin/edit-user/${u._id}" style="display:inline;">
                <input name="name" value="${u.name}" required />
                <input name="email" value="${u.email}" required />
                <input name="phone" value="${u.phone}" />
                <input name="leaderName" value="${u.leaderName}" />
                <select name="accountType">
                  <option value="student" ${u.accountType==='student'?'selected':''}>Student</option>
                  <option value="participant" ${u.accountType==='participant'?'selected':''}>Participant</option>
                  <option value="admin" ${u.accountType==='admin'?'selected':''}>Admin</option>
                </select>
                <input name="mlmLevel" value="${u.mlmLevel}" />
                <button type="submit" class="crud-btn">Edit</button>
              </form>
              <form method="post" action="/admin/approve/${u._id}" style="display:inline;">
                <button type="submit">Approve</button>
              </form>
              <form method="post" action="/admin/reject/${u._id}" style="display:inline;">
                <button type="submit">Reject</button>
              </form>
              <form method="post" action="/admin/delete-user/${u._id}" style="display:inline;">
                <button type="submit" class="crud-btn" onclick="return confirm('Delete user?')">Delete</button>
              </form>
            </li>
          `).join('')}
        </ul>
        <h2>All Users</h2>
        <ul>
          ${allUsers.map(u => `
            <li>
              <form method="post" action="/admin/edit-user/${u._id}" style="display:inline;">
                <input name="name" value="${u.name}" required />
                <input name="email" value="${u.email}" required />
                <input name="phone" value="${u.phone}" />
                <input name="leaderName" value="${u.leaderName}" />
                <select name="accountType">
                  <option value="student" ${u.accountType==='student'?'selected':''}>Student</option>
                  <option value="participant" ${u.accountType==='participant'?'selected':''}>Participant</option>
                  <option value="admin" ${u.accountType==='admin'?'selected':''}>Admin</option>
                </select>
                <input name="mlmLevel" value="${u.mlmLevel}" />
                <button type="submit" class="crud-btn">Edit</button>
              </form>
              <form method="post" action="/admin/delete-user/${u._id}" style="display:inline;">
                <button type="submit" class="crud-btn" onclick="return confirm('Delete user?')">Delete</button>
              </form>
            </li>
          `).join('')}
        </ul>
        <h2>Tree Connections</h2>
        <ul>
          ${treeConnections.map(t => `
            <li>
              <form method="post" action="/admin/edit-tree/${t._id}" style="display:inline;">
                <input name="userId" value="${t.userId}" required />
                <input name="leaderId" value="${t.leaderId}" />
                <select name="verified">
                  <option value="true" ${t.verified?'selected':''}>Verified</option>
                  <option value="false" ${!t.verified?'selected':''}>Not Verified</option>
                </select>
                <button type="submit" class="crud-btn">Edit</button>
              </form>
              <form method="post" action="/admin/delete-tree/${t._id}" style="display:inline;">
                <button type="submit" class="crud-btn" onclick="return confirm('Delete tree connection?')">Delete</button>
              </form>
            </li>
          `).join('')}
        </ul>
        <a href="/profile">Back to Profile</a>
      </main>
    </body>
    </html>
  `);
});

// Admin edit user
app.post('/admin/edit-user/:id', requireAuth, requireAdmin, async (req, res) => {
  const { name, email, phone, leaderName, accountType, mlmLevel } = req.body;
  await User.updateOne({ _id: req.params.id }, { name, email, phone, leaderName, accountType, mlmLevel });
  res.redirect('/admin');
});

// Admin delete user
app.post('/admin/delete-user/:id', requireAuth, requireAdmin, async (req, res) => {
  await User.deleteOne({ _id: req.params.id });
  res.redirect('/admin');
});

// Admin edit tree connection
app.post('/admin/edit-tree/:id', requireAuth, requireAdmin, async (req, res) => {
  const { userId, leaderId, verified } = req.body;
  await Tree.updateOne({ _id: req.params.id }, { userId, leaderId, verified: verified === 'true' });
  res.redirect('/admin');
});

// Admin delete tree connection
app.post('/admin/delete-tree/:id', requireAuth, requireAdmin, async (req, res) => {
  await Tree.deleteOne({ _id: req.params.id });
  res.redirect('/admin');
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
  res.render('checklists', { userChecklists, predefined, user: req.user });
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

// Tree request for users
app.get('/request-tree', requireAuth, requireVerified, async (req, res) => {
  const leaders = await User.find({ accountType: { $in: ['participant', 'admin'] }, status: 'approved' }).select('name userId');
  res.send(`
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Request Tree Connection | MARS EMPIRE</title>
      <link rel="stylesheet" href="assets/css/main.css">
    </head>
    <body>
      <main style="max-width:600px;margin:3rem auto;padding:1rem;">
        <h1>Request to Join MLM Tree</h1>
        <form method="post" action="/request-tree">
          <label>Select Leader:</label>
          <select name="leaderId" required>
            ${leaders.map(l => `<option value="${l._id}">${l.name} (${l.userId})</option>`).join('')}
          </select>
          <button type="submit">Request</button>
        </form>
        <a href="/profile">Back to Profile</a>
      </main>
    </body>
    </html>
  `);
});

app.post('/request-tree', requireAuth, requireVerified, async (req, res) => {
  const { leaderId } = req.body;
  const user = await User.findOne({ email: req.user.email });
  const existing = await Tree.findOne({ userId: user._id, verified: false });
  if (existing) return res.send('<p>Request already pending.</p>');
  await new Tree({ userId: user._id, leaderId, verified: false }).save();
  res.send('<p>Request submitted! Admin will review.</p>');
});

app.get('/tree', requireAuth, requireVerified, async (req, res) => {
  const trees = await Tree.find({ verified: true }).populate('userId leaderId');
  // Build tree data for D3
  const treeData = { name: 'Top', children: [] };
  const nodeMap = { 'Top': treeData };
  trees.forEach(t => {
    const userName = t.userId ? t.userId.name : t.userId;
    const leaderName = t.leaderId ? t.leaderId.name : t.leaderId || 'Top';
    if (!nodeMap[leaderName]) nodeMap[leaderName] = { name: leaderName, children: [] };
    if (!nodeMap[userName]) nodeMap[userName] = { name: userName, children: [] };
    nodeMap[leaderName].children.push(nodeMap[userName]);
  });
  const treeJson = JSON.stringify(treeData);
  const pendingConnections = req.user.accountType === 'admin' ? await Tree.find({ verified: false }).populate('userId leaderId') : [];
  res.render('tree', { treeJson, user: req.user, pendingConnections });
});

app.post('/tree/verify/:id', requireAuth, requireAdmin, async (req, res) => {
  await Tree.updateOne({ _id: req.params.id }, { verified: true });
  res.redirect('/tree');
});

// Dashboard
app.get('/dashboard', requireAuth, requireVerified, (req, res) => {
  res.render('dashboard', { user: req.user });
});

// Calculator
app.get('/calculator', requireAuth, requireVerified, (req, res) => {
  res.render('calculator', { user: req.user });
});

app.get('/rules', requireAuth, requireVerified, (req, res) => {
  res.render('rules', { user: req.user });
});

// Profile page
app.get('/profile', requireAuth, requireVerified, async (req, res) => {
  const user = await User.findOne({ email: req.user.email }).select('-password');
  res.render('profile', { user });
});

app.post('/update-profile', requireAuth, async (req, res) => {
  try {
    const { name, email, phone, leaderName } = req.body;
    await User.updateOne({ email: req.user.email }, { name, email, phone, leaderName });
    res.send('<p>Profile updated! <a href="/profile">Back</a></p>');
  } catch (err) {
    logger.error('Update error:', err);
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
  logger.info(`Contact from ${name} (${email}): ${message}`);
  res.send('<script>alert("Message sent!"); window.location.href="/";</script>');
});

// SEO and misc
app.get('/sitemap.xml', (req, res) => {
  const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
  <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url><loc>${BASE_URL}/</loc></url>
    <url><loc>${BASE_URL}/elements</loc></url>
    <url><loc>${BASE_URL}/generic</loc></url>
    <url><loc>${BASE_URL}/rules</loc></url>
    <url><loc>${BASE_URL}/tree</loc></url>
    <url><loc>${BASE_URL}/checklists</loc></url>
    <url><loc>${BASE_URL}/dashboard</loc></url>
    <url><loc>${BASE_URL}/calculator</loc></url>
    <url><loc>${BASE_URL}/profile</loc></url>
    <url><loc>${BASE_URL}/admin</loc></url>
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

app.listen(PORT, () => {
  logger.info(`🚀 Server running on port ${PORT}`);
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
      }).save().then(() => logger.info('Predefined checklists added')).catch(err => logger.error('Checklist save error:', err));
    }
  }).catch(err => logger.error('Checklist find error:', err));
  User.findOne({ accountType: 'admin' }).then(admin => {
    if (!admin) {
      bcrypt.hash('admin123', 10).then(hashed => {
        new User({
          name: 'Admin',
          email: 'alirooghwall999@gmail.com',
          password: hashed,
          accountType: 'admin',
          mlmLevel: 'expert',
          phone: '0000000000',
          leaderName: 'None',
          userId: 'ADMIN001',
          status: 'approved',
          isVerified: true
        }).save().then(() => logger.info('Admin user created: alirooghwall999@gmail.com / admin123')).catch(err => logger.error('Admin save error:', err));
      }).catch(err => logger.error('Hash error:', err));
    }
  }).catch(err => logger.error('Admin find error:', err));
});