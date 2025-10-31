const express = require('express');
const router = express.Router();
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

// Sign Up
router.post('/signup', async (req, res) => {
  try {
    const { name, email, password, accountType } = req.body;
    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ error: 'Email already in use' });
    const hashed = await bcrypt.hash(password, 10);
    const userId = 'ME' + Date.now() + Math.random().toString(36).substr(2, 5).toUpperCase();
    const user = new User({
      name,
      email,
      password: hashed,
      accountType: accountType || 'participant',
      userId,
      status: 'approved',
      isVerified: true
    });
    await user.save();
    res.status(201).json({ message: 'User created successfully' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Sign In
router.post('/signin', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid password' });

    if (!user.isVerified) return res.status(403).json({ error: 'Email not verified' });
    if (user.status !== 'approved') return res.status(403).json({ error: 'Account not approved' });

    const token = jwt.sign(
      { email: user.email, isVerified: user.isVerified, accountType: user.accountType },
      process.env.JWT_SECRET,
      { expiresIn: ['admin', 'master_admin'].includes(user.accountType) ? '2h' : '1d' }
    );
    res.json({ message: 'Signed in successfully', token, user: { name: user.name, email: user.email, accountType: user.accountType } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
