require('dotenv').config();
const mongoose = require('mongoose');

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Connection error:', err));

// Define schemas (same as in server.js)
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  accountType: { type: String, enum: ['student', 'participant', 'editor', 'manager', 'admin', 'master_admin'], default: 'participant' },
  permissions: [{ type: String }],
  mlmLevel: { type: String, default: 'beginner' },
  phone: String,
  leaderName: String,
  userId: { type: String, unique: true },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  isVerified: { type: Boolean, default: false },
  verificationToken: String,
  resetToken: String,
  resetExpires: Date,
  googleId: String,
  score: { type: Number, default: 0 },
  sales: { type: Number, default: 0 },
  recruited: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
});

const ruleSchema = new mongoose.Schema({
  title: String,
  content: String,
  category: String,
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  updatedAt: { type: Date, default: Date.now },
});

const articleSchema = new mongoose.Schema({
  title: String,
  content: String,
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  category: String,
  tags: [String],
  published: { type: Boolean, default: false },
  attachments: [{ filename: String, originalName: String }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const resourceSchema = new mongoose.Schema({
  title: String,
  description: String,
  type: { type: String, enum: ['document', 'video', 'link', 'file'] },
  url: String,
  file: { filename: String, originalName: String },
  uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  category: String,
  accessLevel: { type: String, enum: ['public', 'participants', 'managers'], default: 'public' },
  createdAt: { type: Date, default: Date.now },
});

const profileUpdateRequestSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  requestedChanges: {
    name: String,
    email: String,
    phone: String,
    leaderName: String,
    mlmLevel: String
  },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  createdAt: { type: Date, default: Date.now },
});

const reportSchema = new mongoose.Schema({
  title: String,
  type: { type: String, enum: ['user_activity', 'sales', 'recruitment', 'system'] },
  data: mongoose.Schema.Types.Mixed,
  generatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now },
});

const notificationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  title: String,
  message: String,
  type: { type: String, enum: ['info', 'warning', 'error', 'success'] },
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
});

const logSchema = new mongoose.Schema({
  level: { type: String, enum: ['info', 'warn', 'error'] },
  message: String,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  action: String,
  details: mongoose.Schema.Types.Mixed,
  createdAt: { type: Date, default: Date.now },
});

const uploadSchema = new mongoose.Schema({
  filename: String,
  originalName: String,
  mimetype: String,
  size: Number,
  url: String,
  uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  category: String,
  createdAt: { type: Date, default: Date.now },
});

const settingsSchema = new mongoose.Schema({
  key: { type: String, unique: true },
  value: mongoose.Schema.Types.Mixed,
  description: String,
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  updatedAt: { type: Date, default: Date.now },
});

const checklistSchema = new mongoose.Schema({
  title: String,
  items: [{ text: String, completed: { type: Boolean, default: false } }],
  userId: String,
  assignedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  isPredefined: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
});

const treeSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  leaderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  verified: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
});

// Create models
const User = mongoose.model('User', userSchema);
const Rule = mongoose.model('Rule', ruleSchema);
const Article = mongoose.model('Article', articleSchema);
const Resource = mongoose.model('Resource', resourceSchema);
const ProfileUpdateRequest = mongoose.model('ProfileUpdateRequest', profileUpdateRequestSchema);
const Report = mongoose.model('Report', reportSchema);
const Notification = mongoose.model('Notification', notificationSchema);
const Log = mongoose.model('Log', logSchema);
const Upload = mongoose.model('Upload', uploadSchema);
const Setting = mongoose.model('Setting', settingsSchema);
const Checklist = mongoose.model('Checklist', checklistSchema);
const Tree = mongoose.model('Tree', treeSchema);

// Function to create collections
async function createCollections() {
  try {
    // Force creation by inserting dummy docs and removing them
    const dummyUser = new User({ name: 'dummy', email: 'dummy@example.com', password: 'dummy', userId: 'dummy' });
    await dummyUser.save();
    await User.deleteOne({ email: 'dummy@example.com' });

    const dummyRule = new Rule({ title: 'dummy' });
    await dummyRule.save();
    await Rule.deleteOne({ title: 'dummy' });

    const dummyArticle = new Article({ title: 'dummy' });
    await dummyArticle.save();
    await Article.deleteOne({ title: 'dummy' });

    const dummyResource = new Resource({ title: 'dummy' });
    await dummyResource.save();
    await Resource.deleteOne({ title: 'dummy' });

    const dummyProfileUpdateRequest = new ProfileUpdateRequest({ userId: null });
    await dummyProfileUpdateRequest.save();
    await ProfileUpdateRequest.deleteOne({ userId: null });

    const dummyReport = new Report({ title: 'dummy' });
    await dummyReport.save();
    await Report.deleteOne({ title: 'dummy' });

    const dummyNotification = new Notification({ userId: null, title: 'dummy' });
    await dummyNotification.save();
    await Notification.deleteOne({ title: 'dummy' });

    const dummyLog = new Log({ message: 'dummy' });
    await dummyLog.save();
    await Log.deleteOne({ message: 'dummy' });

    const dummyUpload = new Upload({ filename: 'dummy' });
    await dummyUpload.save();
    await Upload.deleteOne({ filename: 'dummy' });

    const dummySetting = new Setting({ key: 'dummy' });
    await dummySetting.save();
    await Setting.deleteOne({ key: 'dummy' });

    const dummyChecklist = new Checklist({ title: 'dummy' });
    await dummyChecklist.save();
    await Checklist.deleteOne({ title: 'dummy' });

    const dummyTree = new Tree({ userId: null });
    await dummyTree.save();
    await Tree.deleteOne({ userId: null });

    console.log('All collections created successfully!');
  } catch (err) {
    console.error('Error creating collections:', err);
  } finally {
    mongoose.connection.close();
  }
}

createCollections();