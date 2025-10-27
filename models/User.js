const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  accountType: { type: String, enum: ['student', 'participant', 'editor', 'manager', 'admin'], default: 'participant' },
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

// Compare password method
userSchema.methods.comparePassword = function(password){
    return bcrypt.compare(password, this.password);
}

module.exports = mongoose.model('User', userSchema);
