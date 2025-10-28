require('dotenv').config();
console.log('MONGO_URI:', process.env.MONGO_URI);
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const path = require('path');
const nodemailer = require('nodemailer');
const multer = require('multer');
const upload = multer({ 
  dest: 'uploads/', 
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|pdf|doc|docx|txt|mp4|avi|mp3|wav/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb('Error: File type not allowed!');
    }
  }
});
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const morgan = require('morgan');
const cache = require('memory-cache');
const cookieParser = require('cookie-parser');
const winston = require('winston');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const csv = require('csv-parser');
const createCsvWriter = require('csv-writer').createObjectCsvWriter;
const { body, validationResult } = require('express-validator');

// i18n setup
const i18next = require('i18next');
const i18nextMiddleware = require('i18next-http-middleware');
const i18nextFsBackend = require('i18next-fs-backend');

i18next
  .use(i18nextFsBackend)
  .use(i18nextMiddleware.LanguageDetector)
  .init({
    fallbackLng: 'fa',
    lng: 'fa',
    ns: ['translation'],
    defaultNS: 'translation',
    backend: {
      loadPath: path.join(__dirname, 'locales/{{lng}}/{{ns}}.json')
    },
    detection: {
      order: ['querystring', 'cookie', 'header'],
      caches: ['cookie']
    }
  });

// JWT and email config
const JWT_SECRET = process.env.JWT_SECRET;
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;
const BASE_URL = process.env.BASE_URL || 'https://mars-empire-mlm.onrender.com';
const PORT = process.env.PORT || 3000;

const app = express();
app.use(i18nextMiddleware.handle(i18next));
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://fonts.googleapis.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      frameSrc: ["'self'", "https://www.google.com"],
    },
  },
}));
app.use(morgan('combined'));

// Passport config
app.use(passport.initialize());
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: `${BASE_URL}/auth/google/callback`
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails[0].value;
    let user = await User.findOne({ email });
    if (user) {
      return done(null, user);
    }
    // Create new user
    const name = profile.displayName;
    const userId = 'ME' + Date.now() + Math.random().toString(36).substr(2, 5).toUpperCase();
    user = new User({
      name,
      email,
      password: '', // No password for Google users
      accountType: 'participant',
      mlmLevel: 'beginner',
      phone: '',
      leaderName: '',
      userId,
      status: 'approved',
      isVerified: true,
      googleId: profile.id
    });
    await user.save();
    done(null, user);
  } catch (err) {
    done(err, null);
  }
}));

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
  max: 2000, // limit each IP to 2000 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// Serve static files
app.use(express.static(path.join(__dirname)));

// Sanity checks
if (!JWT_SECRET) {
  console.error('❌ JWT_SECRET is not set');
  process.exit(1);
}
if (!process.env.MONGO_URI) {
  console.error('❌ MONGO_URI is not set');
  // process.exit(1);
}
if (!EMAIL_USER || !EMAIL_PASS) {
  console.error('❌ EMAIL_USER and EMAIL_PASS are not set');
  process.exit(1);
}
if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
  console.error('❌ GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are not set');
  process.exit(1);
}

// Email transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: EMAIL_USER, pass: EMAIL_PASS }
});

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
  serverSelectionTimeoutMS: 30000, // Increase timeout to 30 seconds
  socketTimeoutMS: 45000,
  bufferCommands: true,
  maxPoolSize: 10,
})
  .then(() => logger.info('Connected to MongoDB...'))
  .catch((err) => {
    logger.error('❌ MongoDB connection error:', err.message);
    logger.error('Full error details:', err);
    // process.exit(1);
  });

// Models
const User = require('./models/User');
const Rule = require('./models/Rule');
const Article = require('./models/Article');
const Resource = require('./models/Resource');
const ProfileUpdateRequest = require('./models/ProfileUpdateRequest');
const Report = require('./models/Report');
const Notification = require('./models/Notification');
const Log = require('./models/Log');
const Upload = require('./models/Upload');
const Setting = require('./models/Setting');

const emailTemplates = require('./utils/emailTemplates');

const checklistSchema = new mongoose.Schema({
  title: String,
  items: [{ text: String, completed: { type: Boolean, default: false } }],
  userId: String, // Reference to user
  assignedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
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
  if (!['admin', 'master_admin'].includes(req.user.accountType)) return res.status(403).send('<p>Access denied. Admin only.</p>');
  next();
};

// Middleware to check permissions
const requirePermission = (permission) => {
  return (req, res, next) => {
    if (req.user.accountType === 'master_admin' || req.user.permissions.includes(permission)) {
      return next();
    }
    res.status(403).send('<p>Access denied. Insufficient permissions.</p>');
  };
};

// Middleware to check manager or admin
const requireManager = (req, res, next) => {
  if (!['admin', 'manager'].includes(req.user.accountType)) return res.status(403).send('<p>Access denied. Manager or Admin only.</p>');
  next();
};

// Middleware to check editor or higher
const requireEditor = (req, res, next) => {
  if (!['admin', 'manager', 'editor'].includes(req.user.accountType)) return res.status(403).send('<p>Access denied. Editor or higher only.</p>');
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
    <style>input, select { background: #f9f9f9; color: #000; border: 1px solid #ccc; padding: 0.5rem; border-radius: 4px; }</style>
    <form id="modalSigninForm">
      <input type="hidden" name="redirect" value="/" />
      <div class="input-group">
        <i class="fas fa-envelope"></i>
        <input name="email" type="email" placeholder="Email" required aria-label="Email" />
      </div>
      <div class="input-group">
        <i class="fas fa-lock"></i>
        <input name="password" type="password" placeholder="Password" required aria-label="Password" />
      </div>
      <button type="submit" id="modalSigninBtn"><i class="fas fa-sign-in-alt"></i> Sign In</button>
      <hr style="border: none; border-top: 1px solid #ccc; margin: 1rem 0;">
      <button type="button" onclick="window.location.href='https://mars-empire-mlm.onrender.com/auth/google'" style="background: linear-gradient(45deg, #db4437, #c23321);"><i class="fab fa-google"></i> Sign in with Google</button>
      <p class="forgot"><a href="/forgot-password" target="_blank">Forgot password?</a></p>
      <p><a href="/signup" target="_blank">Create an account</a></p>
    </form>
  `);
});

app.get('/modal/signup', (req, res) => {
  res.send(`
    <style>input, select { background: #f9f9f9; color: #000; border: 1px solid #ccc; padding: 0.5rem; border-radius: 4px; }</style>
    <form id="modalSignupForm">
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
      <button type="submit" id="modalSignupBtn"><i class="fas fa-paper-plane"></i> Create Account</button>
    </form>
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
    const msg = errors.array().map(e => e.msg).join(', ');
    return res.send(`<script>alert("${msg}"); window.history.back();</script>`);
  }

  try {
    const { name, email, password, accountType, mlmLevel, phone, leaderName } = req.body;

    const existing = await User.findOne({ email });
    if (existing) {
      // If user exists and verified, treat as password change request
      if (existing.isVerified) {
        return res.send(`<script>alert("Account already exists. Use forgot password to reset."); window.history.back();</script>`);
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
        return res.send(`<script>alert("Verification email resent."); window.history.back();</script>`);
      }
    }

    // Check for duplicate name and phone
    const existingNamePhone = await User.findOne({ name, phone });
    if (existingNamePhone) {
      return res.send(`<script>alert("A user with this name and phone number already exists. Please use different details or contact support."); window.history.back();</script>`);
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
      html: emailTemplates.verification(token)
    };
    await transporter.sendMail(mailOptions);

    res.redirect('/approval-status');
  } catch (err) {
    logger.error('Signup error:', err);
    res.send(`<script>alert("Server error during signup"); window.history.back();</script>`);
  }
});

// Approval status page
app.get('/approval-status', (req, res) => {
  res.send(`
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <title>Approval Status | MARS EMPIRE</title>
      <link rel="stylesheet" href="assets/css/main.css">
      <style>
        body { background: linear-gradient(135deg, #1e1e2e, #2a2a3e); color: #ffffff; font-family: 'Source Sans Pro', sans-serif; margin: 0; padding: 0; }
        main { max-width: 600px; margin: 5rem auto; padding: 2rem; background: rgba(255,255,255,0.1); border-radius: 12px; box-shadow: 0 0 20px rgba(0,0,0,0.5); text-align: center; }
        h1 { color: #4ecdc4; }
        p { font-size: 1.1rem; }
        a { color: #4ecdc4; text-decoration: none; }
        a:hover { color: #45b7aa; }
      </style>
    </head>
    <body>
      <main>
        <h1>Account Created Successfully!</h1>
        <p>Your account has been created and is pending admin approval.</p>
        <p>You will receive an email once your account is approved.</p>
        <p>Please check your email for verification link if you haven't already.</p>
        <p><a href="/signin">Sign In</a> | <a href="/">Back to Home</a></p>
      </main>
    </body>
    </html>
  `);
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
      html: emailTemplates.verification(token)
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
          <hr style="border: none; border-top: 1px solid #ccc; margin: 1rem 0;">
          <button type="button" onclick="window.location.href='https://mars-empire-mlm.onrender.com/auth/google'" style="background: linear-gradient(45deg, #db4437, #c23321);"><i class="fab fa-google"></i> Sign in with Google</button>
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
    const msg = errors.array().map(e => e.msg).join(', ');
    return res.send(`<script>alert("${msg}"); window.history.back();</script>`);
  }

  try {
    const { email, password, redirect } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.send(`<script>alert("User not found"); window.history.back();</script>`);
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.send(`<script>alert("Invalid password"); window.history.back();</script>`);
    }

    if (!user.isVerified) {
      return res.send(`<script>alert("Please verify your email first"); window.history.back();</script>`);
    }

    if (user.status !== 'approved') {
      return res.send(`<script>alert("Your account is pending admin approval"); window.history.back();</script>`);
    }

    const token = jwt.sign({ email: user.email, isVerified: user.isVerified, accountType: user.accountType }, JWT_SECRET, { expiresIn: ['admin', 'master_admin'].includes(user.accountType) ? '2h' : '1d' });
    res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', maxAge: ['admin', 'master_admin'].includes(user.accountType) ? 7200000 : 86400000 });
    res.redirect(redirect || '/dashboard');
  } catch (err) {
    logger.error('Signin error:', err);
    res.send(`<script>alert("Server error"); window.history.back();</script>`);
  }
});

// Google Auth routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/signin' }), async (req, res) => {
  const token = jwt.sign({ email: req.user.email, isVerified: req.user.isVerified, accountType: req.user.accountType }, JWT_SECRET, { expiresIn: ['admin', 'master_admin'].includes(req.user.accountType) ? '2h' : '1d' });
  res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', maxAge: ['admin', 'master_admin'].includes(req.user.accountType) ? 7200000 : 86400000 });
  // Check if user needs to complete profile
  if (!req.user.phone || !req.user.leaderName) {
    return res.redirect('/complete-profile');
  }
  res.redirect('/dashboard');
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
      html: emailTemplates.passwordReset(token)
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

// Admin dashboard with CRUD for users, content, and tree
app.get('/admin', requireAuth, requireVerified, requireAdmin, async (req, res) => {
  const pendingUsers = await User.find({ status: 'pending' }).select('name email userId accountType mlmLevel phone leaderName createdAt _id');
  const allUsers = await User.find({}).select('name email userId accountType status mlmLevel phone leaderName _id');
  const treeConnections = await Tree.find({}).select('userId leaderId verified _id');
  const rules = await Rule.find({});
  const articles = await Article.find({}).populate('author');
  const resources = await Resource.find({});
  res.render('admin', { pendingUsers, allUsers, treeConnections, rules, articles, resources, user: req.user });
});

// Admin edit user
app.post('/admin/edit-user/:id', requireAuth, requireAdmin, async (req, res) => {
  const userToEdit = await User.findById(req.params.id);
  if (userToEdit.accountType === 'admin' && req.user.accountType !== 'master_admin') {
    return res.status(403).send('<p>Cannot edit admin accounts.</p>');
  }
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

app.post('/admin/create-user', requireAdmin, async (req, res) => {
  try {
    const { name, email, password, phone, leaderName, accountType, mlmLevel, permissions } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    const userId = 'ME' + Date.now() + Math.random().toString(36).substr(2, 5).toUpperCase();
    const perms = Array.isArray(permissions) ? permissions : permissions ? [permissions] : [];
    await new User({ name, email, password: hashed, phone, leaderName, accountType, mlmLevel, userId, status: 'approved', isVerified: true, permissions: perms }).save();
    res.redirect('/admin');
  } catch (err) {
    logger.error('Create user error:', err);
    res.status(500).send('<script>alert("Error creating user: ' + err.message + '"); window.history.back();</script>');
  }
});

app.post('/admin/approve/:id', requireAdmin, async (req, res) => {
  await User.updateOne({ _id: req.params.id }, { status: 'approved' });
  res.redirect('/admin');
});

app.post('/admin/reject/:id', requireAdmin, async (req, res) => {
  await User.updateOne({ _id: req.params.id }, { status: 'rejected' });
  res.redirect('/admin');
});

app.post('/admin/approve-profile/:id', requireAdmin, async (req, res) => {
  const request = await ProfileUpdateRequest.findById(req.params.id).populate('userId');
  if (!request || request.status !== 'pending') return res.redirect('/admin');
  await User.updateOne({ _id: request.userId._id }, request.requestedChanges);
  request.status = 'approved';
  await request.save();
  res.redirect('/admin');
});

app.post('/admin/reject-profile/:id', requireAdmin, async (req, res) => {
  await ProfileUpdateRequest.updateOne({ _id: req.params.id }, { status: 'rejected' });
  res.redirect('/admin');
});

// Bulk import users
app.post('/admin/import-users', requireAdmin, upload.single('csvFile'), async (req, res) => {
  if (!req.file) return res.send('No file uploaded.');
  const results = [];
  require('fs').createReadStream(req.file.path)
    .pipe(csv())
    .on('data', (data) => results.push(data))
    .on('end', async () => {
      for (const row of results) {
        const hashed = await bcrypt.hash(row.password || 'default123', 10);
        const userId = 'ME' + Date.now() + Math.random().toString(36).substr(2, 5).toUpperCase();
        await new User({
          name: row.name,
          email: row.email,
          password: hashed,
          accountType: row.accountType || 'participant',
          mlmLevel: row.mlmLevel || 'beginner',
          phone: row.phone || '',
          leaderName: row.leaderName || '',
          userId,
          status: 'approved',
          isVerified: true
        }).save();
      }
      res.redirect('/admin');
    });
});

// Export users
app.get('/admin/export-users', requireAdmin, async (req, res) => {
  const users = await User.find({}).select('name email userId accountType mlmLevel phone leaderName status');
  const csvWriter = createCsvWriter({
    path: 'users.csv',
    header: [
      {id: 'name', title: 'Name'},
      {id: 'email', title: 'Email'},
      {id: 'userId', title: 'UserID'},
      {id: 'accountType', title: 'AccountType'},
      {id: 'mlmLevel', title: 'MLMLevel'},
      {id: 'phone', title: 'Phone'},
      {id: 'leaderName', title: 'LeaderName'},
      {id: 'status', title: 'Status'}
    ]
  });
  await csvWriter.writeRecords(users);
  res.download('users.csv');
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
  res.render('tree', { treeData, user: req.user, pendingConnections });
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

// Leaderboard
app.get('/leaderboard', requireAuth, requireVerified, async (req, res) => {
  const cacheKey = 'leaderboard';
  let data = cache.get(cacheKey);
  if (!data) {
    const topByScore = await User.find({ status: 'approved' }).sort({ score: -1 }).limit(10).select('name score sales recruited');
    const topBySales = await User.find({ status: 'approved' }).sort({ sales: -1 }).limit(10).select('name score sales recruited');
    const topByRecruited = await User.find({ status: 'approved' }).sort({ recruited: -1 }).limit(10).select('name score sales recruited');
    data = { topByScore, topBySales, topByRecruited };
    cache.put(cacheKey, data, 300000); // 5 min
  }
  res.render('leaderboard', { ...data, user: req.user });
});

app.get('/rules', requireAuth, requireVerified, async (req, res) => {
  const rules = await Rule.find({});
  res.render('rules', { rules, user: req.user });
});

app.post('/rules/create', requireEditor, async (req, res) => {
  const { title, content, category } = req.body;
  await new Rule({ title, content, category, createdBy: req.user._id }).save();
  res.redirect('/rules');
});

app.post('/rules/update/:id', requireEditor, async (req, res) => {
  const { title, content, category } = req.body;
  await Rule.updateOne({ _id: req.params.id }, { title, content, category, updatedAt: new Date() });
  res.redirect('/rules');
});

app.post('/rules/delete/:id', requireEditor, async (req, res) => {
  await Rule.deleteOne({ _id: req.params.id });
  res.redirect('/rules');
});

// Articles routes
app.get('/articles', requireAuth, requireVerified, async (req, res) => {
  const articles = await Article.find({ published: true }).populate('author');
  res.render('articles', { articles, user: req.user });
});

app.post('/articles/create', requireEditor, upload.array('files', 10), async (req, res) => {
  const { title, content, category, tags, published } = req.body;
  const attachments = req.files ? req.files.map(f => ({ filename: f.filename, originalName: f.originalname })) : [];
  await new Article({ title, content, category, tags: tags.split(','), published: published === 'on', author: req.user._id, attachments }).save();
  res.redirect('/articles');
});

app.post('/articles/update/:id', requireEditor, async (req, res) => {
  const { title, content, category, tags, published } = req.body;
  await Article.updateOne({ _id: req.params.id }, { title, content, category, tags: tags.split(','), published: published === 'on', updatedAt: new Date() });
  res.redirect('/articles');
});

app.post('/articles/delete/:id', requireEditor, async (req, res) => {
  await Article.deleteOne({ _id: req.params.id });
  res.redirect('/articles');
});

// Resources routes
app.get('/resources', requireAuth, requireVerified, async (req, res) => {
  const accessLevels = req.user.accountType === 'admin' ? ['public', 'participants', 'managers'] : req.user.accountType === 'manager' ? ['public', 'participants'] : ['public'];
  const resources = await Resource.find({ accessLevel: { $in: accessLevels } });
  res.render('resources', { resources, user: req.user });
});

app.post('/resources/create', requireEditor, upload.single('file'), async (req, res) => {
  const { title, description, type, url, category, accessLevel } = req.body;
  const file = req.file ? { filename: req.file.filename, originalName: req.file.originalname } : null;
  await new Resource({ title, description, type, url, category, accessLevel, uploadedBy: req.user._id, file }).save();
  res.redirect('/resources');
});

app.post('/resources/update/:id', requireEditor, async (req, res) => {
  const { title, description, type, url, category, accessLevel } = req.body;
  await Resource.updateOne({ _id: req.params.id }, { title, description, type, url, category, accessLevel });
  res.redirect('/resources');
});

app.post('/resources/delete/:id', requireEditor, async (req, res) => {
  await Resource.deleteOne({ _id: req.params.id });
  res.redirect('/resources');
});

// Reports routes
app.get('/reports', requireAuth, requireVerified, requirePermission('view_reports'), async (req, res) => {
  const reports = await Report.find({}).sort({ createdAt: -1 });
  res.render('reports', { reports, user: req.user });
});

app.post('/reports/create', requireAuth, async (req, res) => {
  const { type, data } = req.body;
  await new Report({ type, data, createdBy: req.user._id }).save();
  res.redirect('/reports');
});

// Notifications routes
app.get('/notifications', requireAuth, requireVerified, async (req, res) => {
  const notifications = await Notification.find({ userId: req.user._id }).sort({ createdAt: -1 });
  res.render('notifications', { notifications, user: req.user });
});

app.post('/notifications/create', requireAdmin, async (req, res) => {
  const { userId, title, message, type } = req.body;
  await new Notification({ userId, title, message, type }).save();
  res.redirect('/notifications');
});

app.post('/notifications/mark-read/:id', requireAuth, async (req, res) => {
  await Notification.updateOne({ _id: req.params.id, userId: req.user._id }, { read: true });
  res.redirect('/notifications');
});

// Logs routes
app.get('/logs', requireAuth, requireVerified, requirePermission('view_logs'), async (req, res) => {
  const logs = await Log.find({}).sort({ timestamp: -1 }).limit(100);
  res.render('logs', { logs, user: req.user });
});

// Upload routes
app.get('/upload', requireAuth, requireVerified, requirePermission('upload_files'), (req, res) => {
  res.render('upload', { user: req.user });
});

app.post('/upload', requireAuth, requirePermission('upload_files'), upload.single('file'), async (req, res) => {
  if (!req.file) return res.send('No file uploaded.');
  const newUpload = new Upload({
    filename: req.file.filename,
    originalName: req.file.originalname,
    mimetype: req.file.mimetype,
    size: req.file.size,
    uploadedBy: req.user._id
  });
  await newUpload.save();
  res.send('File uploaded successfully!');
});

// Settings routes
app.get('/settings', requireAuth, requireVerified, requireAdmin, async (req, res) => {
  const settings = await Setting.find({});
  res.render('settings', { settings, user: req.user });
});

app.post('/settings/create', requireAdmin, async (req, res) => {
  const { key, value } = req.body;
  await new Setting({ key, value }).save();
  res.redirect('/settings');
});

app.post('/settings/update/:id', requireAdmin, async (req, res) => {
  const { value } = req.body;
  await Setting.updateOne({ _id: req.params.id }, { value });
  res.redirect('/settings');
});

app.post('/settings/delete/:id', requireAdmin, async (req, res) => {
  await Setting.deleteOne({ _id: req.params.id });
  res.redirect('/settings');
});

// Profile page
app.get('/profile', requireAuth, requireVerified, async (req, res) => {
  const user = await User.findOne({ email: req.user.email }).select('-password');
  const pendingRequest = await ProfileUpdateRequest.findOne({ userId: user._id, status: 'pending' });
  res.render('profile', { user, pendingRequest });
});

app.post('/profile/request-update', requireAuth, async (req, res) => {
  const { name, email, phone, leaderName, mlmLevel } = req.body;
  const user = await User.findOne({ email: req.user.email });
  const existing = await ProfileUpdateRequest.findOne({ userId: user._id, status: 'pending' });
  if (existing) return res.send('<p>Update request already pending. <a href="/profile">Back</a></p>');
  await new ProfileUpdateRequest({
    userId: user._id,
    requestedChanges: { name, email, phone, leaderName, mlmLevel }
  }).save();
  res.send('<p>Update request submitted for admin approval. <a href="/profile">Back</a></p>');
});

// Complete profile for Google users
app.get('/complete-profile', requireAuth, (req, res) => {
  res.send(`
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <title>Complete Profile | MARS EMPIRE</title>
      <link rel="stylesheet" href="assets/css/main.css">
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
      <style>
        body { background: linear-gradient(135deg, #1e1e2e, #2a2a3e); color: #ffffff; font-family: 'Source Sans Pro', sans-serif; margin: 0; padding: 0; }
        main { max-width: 400px; margin: 5rem auto; padding: 2rem; background: rgba(255,255,255,0.1); border-radius: 12px; box-shadow: 0 0 20px rgba(0,0,0,0.5); }
        h1 { text-align: center; color: #4ecdc4; margin-bottom: 1.5rem; }
        form { display: flex; flex-direction: column; }
        .input-group { position: relative; margin-bottom: 1rem; }
        input, select { padding: 0.75rem 0.75rem 0.75rem 2.5rem; border: 1px solid #ccc; border-radius: 8px; background: #333; color: #fff; font-size: 1rem; width: 100%; box-sizing: border-box; }
        input:focus, select:focus { border-color: #4ecdc4; outline: none; }
        .input-group i { position: absolute; left: 0.75rem; top: 50%; transform: translateY(-50%); color: #ccc; }
        button { padding: 0.75rem; background: linear-gradient(45deg, #4ecdc4, #45b7aa); color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 1rem; }
        button:hover { background: linear-gradient(45deg, #45b7aa, #3da08e); }
      </style>
    </head>
    <body>
      <main>
        <h1><i class="fas fa-user-edit"></i> Complete Your Profile</h1>
        <form method="post" action="/complete-profile">
          <div class="input-group">
            <i class="fas fa-phone"></i>
            <input name="phone" placeholder="Phone" required aria-label="Phone" />
          </div>
          <div class="input-group">
            <i class="fas fa-user-friends"></i>
            <input name="leaderName" placeholder="Leader's Name" required aria-label="Leader's Name" />
          </div>
          <div class="input-group">
            <i class="fas fa-level-up-alt"></i>
            <select name="mlmLevel" required aria-label="MLM Level">
              <option value="beginner">Beginner</option>
              <option value="intermediate">Intermediate</option>
              <option value="advanced">Advanced</option>
              <option value="expert">Expert</option>
            </select>
          </div>
          <button type="submit"><i class="fas fa-save"></i> Complete Profile</button>
        </form>
      </main>
    </body>
    </html>
  `);
});

app.post('/complete-profile', requireAuth, async (req, res) => {
  const { phone, leaderName, mlmLevel } = req.body;
  await User.updateOne({ email: req.user.email }, { phone, leaderName, mlmLevel });
  res.redirect('/dashboard');
});

// Search
app.get('/search', requireAuth, requireVerified, async (req, res) => {
  const query = req.query.q || '';
  const articles = query ? await Article.find({ published: true, $or: [{ title: new RegExp(query, 'i') }, { content: new RegExp(query, 'i') }] }).populate('author') : [];
  const resources = query ? await Resource.find({ $or: [{ title: new RegExp(query, 'i') }, { description: new RegExp(query, 'i') }] }) : [];
  const users = query ? await User.find({ status: 'approved', $or: [{ name: new RegExp(query, 'i') }, { userId: new RegExp(query, 'i') }] }).select('name userId') : [];
  res.render('search', { articles, resources, users, query, user: req.user });
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

// Change language
app.get('/change-lang/:lng', (req, res) => {
  res.cookie('i18next', req.params.lng, { maxAge: 900000, httpOnly: false });
  res.redirect('back');
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
    <url><loc>${BASE_URL}/leaderboard</loc></url>
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

// AI integration routes (placeholders for future AI model)
app.post('/ai/chat', requireAuth, (req, res) => {
  const { message } = req.body;
  // Log interaction
  logger.info(`AI Chat: User ${req.user.email} - ${message}`);
  // Placeholder response
  res.json({ response: 'This is a placeholder response from the AI model.' });
});

app.post('/ai/update-checklist', requireAuth, async (req, res) => {
  const { checklistId, itemIndex, completed } = req.body;
  const checklist = await Checklist.findById(checklistId);
  if (checklist && (checklist.userId === req.user.email || checklist.assignedBy.toString() === req.user._id.toString())) {
    checklist.items[itemIndex].completed = completed;
    await checklist.save();
    logger.info(`Checklist updated via AI: ${req.user.email} - ${checklistId}`);
    res.json({ success: true });
  } else {
    res.status(403).json({ error: 'Not authorized' });
  }
});

app.post('/ai/track-progress', requireAuth, (req, res) => {
  const { progressData } = req.body;
  logger.info(`Progress tracked: User ${req.user.email} - ${JSON.stringify(progressData)}`);
  res.json({ success: true });
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
          email: 'admin@alirooghwall.github.io',
          password: hashed,
          accountType: 'admin',
          mlmLevel: 'expert',
          phone: '0000000000',
          leaderName: 'None',
          userId: 'ADMIN001',
          status: 'approved',
          isVerified: true
        }).save().then(() => logger.info('Admin user created: admin@alirooghwall.github.io / admin123')).catch(err => logger.error('Admin save error:', err));
      }).catch(err => logger.error('Hash error:', err));
    }
  }).catch(err => logger.error('Admin find error:', err));
});