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
  isVerified: { type: Boolean, default: false },
  verificationToken: String,
  resetToken: String,
  resetExpires: Date,
});
const User = mongoose.model('User', userSchema);

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
    const { name, email, password } = req.body;
    if (!name || !email || !password || password.length < 8) {
      return res.status(400).send('<script>alert("Invalid input. Password must be at least 8 characters."); window.location.href="/signup";</script>');
    }

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).send('<script>alert("Email already registered"); window.location.href="/signup";</script>');
    }

    const hashed = await bcrypt.hash(password, 10);
    const token = crypto.randomBytes(32).toString('hex');
    const newUser = new User({ name, email, password: hashed, verificationToken: token });
    await newUser.save();

    const mailOptions = {
      from: EMAIL_USER,
      to: email,
      subject: 'Verify your email - MARS EMPIRE',
      html: `<p>Click <a href="${BASE_URL}/verify/${token}">here</a> to verify your account.</p>`
    };
    await transporter.sendMail(mailOptions);

    res.send('<script>alert("Signup successful! Check your email to verify."); window.location.href="/signin";</script>');
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

    const token = jwt.sign({ email: user.email, isVerified: user.isVerified }, JWT_SECRET, { expiresIn: '1d' });
    res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'strict', maxAge: 86400000 });
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

// Profile with editing
app.get('/profile', requireAuth, requireVerified, async (req, res) => {
  const user = await User.findOne({ email: req.user.email }).select('-password');
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
        <p>Verified: ${user.isVerified ? 'Yes' : 'No'}</p>
        <form method="post" action="/update-profile">
          <input name="name" value="${user.name}" required />
          <input name="email" value="${user.email}" type="email" required />
          <button type="submit">Update</button>
        </form>
        <a href="/logout">Logout</a>
      </main>
    </body>
    </html>
  `);
});

app.post('/update-profile', requireAuth, async (req, res) => {
  try {
    const { name, email } = req.body;
    await User.updateOne({ email: req.user.email }, { name, email });
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

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));