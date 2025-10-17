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
const EMAIL_USER = process.env.EMAIL_USER; // e.g., yourgmail@gmail.com
const EMAIL_PASS = process.env.EMAIL_PASS; // app password
const BASE_URL = process.env.BASE_URL || https://mars-empire-mlm.onrender.com'; 
const PORT = process.env.PORT || 3000;

// Sanity checks
if (!JWT_SECRET) {
  console.error('❌ JWT_SECRET is not set in .env');
  process.exit(1);
}
if (!process.env.MONGO_URI) {
  console.error('❌ MONGO_URI is not set in .env');
  process.exit(1);
}
if (!EMAIL_USER || !EMAIL_PASS) {
  console.error('❌ EMAIL_USER and EMAIL_PASS are not set in .env');
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

// User model with verification
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  isVerified: { type: Boolean, default: false },
  verificationToken: String,
});
const User = mongoose.model('User', userSchema);

// Middleware to check auth
const requireAuth = (req, res, next) => {
  const token = req.cookies?.token || req.headers.authorization?.split(' ')[1];
  if (!token) return res.redirect('/signin');
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.redirect('/signin');
  }
};

// Middleware to check verification
const requireVerified = (req, res, next) => {
  if (!req.user.isVerified) return res.send('<p>Please verify your email first. <a href="/signin">Back</a></p>');
  next();
};

// Health check for Render
app.get('/health', (req, res) => res.send('OK'));

// GET / - Serve home (limited access)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// GET /elements - Info page (limited access)
app.get('/elements', (req, res) => {
  res.sendFile(path.join(__dirname, 'elements.html'));
});

// Protect other pages
app.get('/generic', requireAuth, requireVerified, (req, res) => {
  res.sendFile(path.join(__dirname, 'generic.html'));
});

// GET /signup - Styled form with pre-fill
app.get('/signup', (req, res) => {
  const saved = req.cookies?.signupData ? JSON.parse(req.cookies.signupData) : {};
  res.send(`
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Sign Up | MARS EMPIRE</title>
      <link rel="stylesheet" href="assets/css/main.css">
      <style>
        body { background: linear-gradient(135deg, #1e1e2e, #2a2a3e); color: #ffffff; font-family: 'Source Sans Pro', sans-serif; }
        main { max-width: 400px; margin: 5rem auto; padding: 2rem; background: rgba(255,255,255,0.1); border-radius: 8px; box-shadow: 0 0 20px rgba(0,0,0,0.5); }
        h1 { text-align: center; color: #ff6b6b; }
        form { display: flex; flex-direction: column; }
        label { margin-bottom: 0.5rem; font-weight: bold; }
        input { padding: 0.5rem; margin-bottom: 1rem; border: 1px solid #ccc; border-radius: 4px; background: #333; color: #fff; }
        button { padding: 0.75rem; background: #ff6b6b; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #ff5252; }
        p { text-align: center; margin-top: 1rem; }
        a { color: #4ecdc4; text-decoration: none; }
      </style>
    </head>
    <body>
      <main>
        <h1>Sign Up</h1>
        <form method="post" action="/signup">
          <label>Name</label>
          <input name="name" value="${saved.name || ''}" required aria-label="Name" />
          <label>Email</label>
          <input name="email" type="email" value="${saved.email || ''}" required aria-label="Email" />
          <label>Password</label>
          <input name="password" type="password" required aria-label="Password" />
          <button type="submit">Create Account</button>
        </form>
        <p><a href="/signin">Already have an account? Sign In</a></p>
        <p><a href="/">Back to Home</a></p>
      </main>
      <script>
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

// POST /signup - Create user, send verification email
app.post('/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).send('<script>alert("Missing fields"); window.location.href="/signup";</script>');
    }

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).send('<script>alert("Email already registered"); window.location.href="/signup";</script>');
    }

    const hashed = await bcrypt.hash(password, 10);
    const token = crypto.randomBytes(32).toString('hex');
    const newUser = new User({ name, email, password: hashed, verificationToken: token });
    await newUser.save();

    // Send verification email
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

// GET /verify/:token - Verify email
app.get('/verify/:token', async (req, res) => {
  try {
    const user = await User.findOne({ verificationToken: req.params.token });
    if (!user) return res.send('<p>Invalid token. <a href="/signup">Sign up</a></p>');

    user.isVerified = true;
    user.verificationToken = undefined;
    await user.save();

    res.send('<p>Email verified! <a href="/signin">Sign in</a></p>');
  } catch (err) {
    console.error('Verification error:', err);
    res.status(500).send('<p>Server error</p>');
  }
});

// GET /signin - Styled form with pre-fill
app.get('/signin', (req, res) => {
  const saved = req.cookies?.signinData ? JSON.parse(req.cookies.signinData) : {};
  res.send(`
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Sign In | MARS EMPIRE</title>
      <link rel="stylesheet" href="assets/css/main.css">
      <style>
        body { background: linear-gradient(135deg, #1e1e2e, #2a2a3e); color: #ffffff; font-family: 'Source Sans Pro', sans-serif; }
        main { max-width: 400px; margin: 5rem auto; padding: 2rem; background: rgba(255,255,255,0.1); border-radius: 8px; box-shadow: 0 0 20px rgba(0,0,0,0.5); }
        h1 { text-align: center; color: #4ecdc4; }
        form { display: flex; flex-direction: column; }
        label { margin-bottom: 0.5rem; font-weight: bold; }
        input { padding: 0.5rem; margin-bottom: 1rem; border: 1px solid #ccc; border-radius: 4px; background: #333; color: #fff; }
        button { padding: 0.75rem; background: #4ecdc4; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #45b7aa; }
        p { text-align: center; margin-top: 1rem; }
        a { color: #ff6b6b; text-decoration: none; }
      </style>
    </head>
    <body>
      <main>
        <h1>Sign In</h1>
        <form method="post" action="/signin">
          <label>Email</label>
          <input name="email" type="email" value="${saved.email || ''}" required aria-label="Email" />
          <label>Password</label>
          <input name="password" type="password" required aria-label="Password" />
          <button type="submit">Sign In</button>
        </form>
        <p><a href="/signup">Create an account</a></p>
        <p><a href="/">Back to Home</a></p>
      </main>
      <script>
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

// POST /signin - Authenticate, set cookie
app.post('/signin', async (req, res) => {
  try {
    const { email, password } = req.body;
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
      return res.send('<script>alert("Please verify your email first"); window.location.href="/signin";</script>');
    }

    const token = jwt.sign({ email: user.email, isVerified: user.isVerified }, JWT_SECRET, { expiresIn: '1d' });
    res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'strict', maxAge: 86400000 });
    res.redirect('/');
  } catch (err) {
    console.error('Signin error:', err);
    res.status(500).send('<script>alert("Server error"); window.location.href="/signin";</script>');
  }
});

// GET /profile - Protected
app.get('/profile', requireAuth, requireVerified, async (req, res) => {
  const user = await User.findOne({ email: req.user.email }).select('-password');
  res.json({ user });
});

// Logout
app.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/');
});

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));