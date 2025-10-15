const express = require('express');
const router = express.Router();
const User = require('../models/User');
const jwt = require('jsonwebtoken');

// Sign Up
router.post('/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const user = new User({ name, email, password });
        await user.save();
        res.status(201).json({ message: "User created successfully" });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// Sign In
router.post('/signin', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if(!user) return res.status(404).json({ error: "User not found" });
        
        const isMatch = await user.comparePassword(password);
        if(!isMatch) return res.status(400).json({ error: "Invalid password" });

        // Generate JWT
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.json({ message: "Signed in successfully", token, user: { name: user.name, email: user.email }});
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;
