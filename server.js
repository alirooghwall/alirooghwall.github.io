require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const app = express();
app.use(cors());
app.use(bodyParser.json());
// allow HTML forms (application/x-www-form-urlencoded)
app.use(bodyParser.urlencoded({ extended: true }));

const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 3000;

// basic sanity checks
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

// Create a User model
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
});

const User = mongoose.model('User', userSchema);

// GET signup form (for quick browser testing)
app.get('/signup', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!doctype html>
  <html>
  <head><meta charset="utf-8"><title>Sign Up</title></head>
  <body>
    <h1>Sign Up</h1>
    <form method="post" action="/signup">
      <label>Name: <input name="name" required /></label><br/>
      <label>Email: <input name="email" type="email" required /></label><br/>
      <label>Password: <input name="password" type="password" required /></label><br/>
      <button type="submit">Sign Up</button>
    </form>
    <p><a href="/">Back to Home</a></p>
  </body>
  </html>`);
});

// POST /signup - create user
app.post('/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ message: 'Missing fields' });

    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: 'Email already registered' });

    const hashed = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email, password: hashed });
    await newUser.save();

    res.setHeader('contact-Type', 'text/html; charset=utf-8')
    res.send(`<!doctype html>
  <html>
  <head><meta charset="utf-8"><title>Sign Up</title></head>
  <body>
    <h1> 'User created successfully' </h1>
  </body>
  </html>`)

  } catch (err) {
    console.error('❌ Error creating user:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/signin', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: 'User not found' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ message: 'Invalid password' });

  const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '1d' });
  res.json({ message: 'Signed in', token });
});


app.get('/profile', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: 'No token' });

  const token = auth.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findOne({ email: decoded.email });
    res.json({ message: 'Profile loaded', user });
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
});

app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
