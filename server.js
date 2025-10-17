require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const path = require('path');

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files (CSS, JS, images) from the project root
app.use(express.static(path.join(__dirname)));

const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 3000;

// Sanity checks
if (!process.env.MONGO_URI) {
  console.error('❌ MONGO_URI is not set in .env');
  process.exit(1);
}
if (!JWT_SECRET) {
  console.error('❌ JWT_SECRET is not set in .env');
  process.exit(1);
}

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB...'))
  .catch((err) => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  });

// User model
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
});
const User = mongoose.model('User', userSchema);

// GET / - Serve main page (index.html)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// GET /signup - Styled form
app.get('/signup', (req, res) => {
  res.send(`
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Sign Up | MARS EMPIRE</title>
      <link rel="stylesheet" href="assets/css/main.css">
      <style>
        body { background: #f4f4f4; font-family: Arial, sans-serif; }
        main { max-width: 400px; margin: 5rem auto; padding: 2rem; background: white; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { text-align: center; color: #333; }
        form { display: flex; flex-direction: column; }
        label { margin-bottom: 0.5rem; font-weight: bold; }
        input { padding: 0.5rem; margin-bottom: 1rem; border: 1px solid #ccc; border-radius: 4px; }
        button { padding: 0.75rem; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        p { text-align: center; margin-top: 1rem; }
        a { color: #007bff; text-decoration: none; }
      </style>
    </head>
    <body>
      <main>
        <h1>Sign Up</h1>
        <form method="post" action="/signup">
          <label>Name</label>
          <input name="name" required />
          <label>Email</label>
          <input name="email" type="email" required />
          <label>Password</label>
          <input name="password" type="password" required />
          <button type="submit">Create Account</button>
        </form>
        <p><a href="/signin">Already have an account? Sign In</a></p>
        <p><a href="/">Back to Home</a></p>
      </main>
    </body>
    </html>
  `);
});

// POST /signup - Create user with pop-up success
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
    const newUser = new User({ name, email, password: hashed });
    await newUser.save();

    // Success pop-up and redirect
    res.send('<script>alert("User created successfully!"); window.location.href="/signin";</script>');
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).send('<script>alert("Server error"); window.location.href="/signup";</script>');
  }
});

// GET /signin - Styled form
app.get('/signin', (req, res) => {
  res.send(`
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Sign In | MARS EMPIRE</title>
      <link rel="stylesheet" href="assets/css/main.css">
      <style>
        body { background: #f4f4f4; font-family: Arial, sans-serif; }
        main { max-width: 400px; margin: 5rem auto; padding: 2rem; background: white; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { text-align: center; color: #333; }
        form { display: flex; flex-direction: column; }
        label { margin-bottom: 0.5rem; font-weight: bold; }
        input { padding: 0.5rem; margin-bottom: 1rem; border: 1px solid #ccc; border-radius: 4px; }
        button { padding: 0.75rem; background: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #218838; }
        p { text-align: center; margin-top: 1rem; }
        a { color: #007bff; text-decoration: none; }
      </style>
    </head>
    <body>
      <main>
        <h1>Sign In</h1>
        <form method="post" action="/signin">
          <label>Email</label>
          <input name="email" type="email" required />
          <label>Password</label>
          <input name="password" type="password" required />
          <button type="submit">Sign In</button>
        </form>
        <p><a href="/signup">Create an account</a></p>
        <p><a href="/">Back to Home</a></p>
      </main>
    </body>
    </html>
  `);
});

// POST /signin - Authenticate with styled response
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

    const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '1d' });
    // For demo, show token in alert and redirect home
    res.send(`<script>alert("Signed in! Token: ${token}"); window.location.href="/";</script>`);
  } catch (err) {
    console.error('Signin error:', err);
    res.status(500).send('<script>alert("Server error"); window.location.href="/signin";</script>');
  }
});

app.get('/profile', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: 'No token' });

  const token = auth.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findOne({ email: decoded.email }).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ message: 'Profile loaded', user });
  } catch (err) {
    console.error('Profile error:', err);
    res.status(401).json({ message: 'Invalid token' });
  }
});

app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));