const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const PDFDocument = require('pdfkit');
const cookieParser = require('cookie-parser');
const axios = require('axios');
const { OAuth2Client } = require('google-auth-library');
const twilio = require('twilio');
const emailjs = require('@emailjs/nodejs');
const { cleanEnv, str, url, port } = require('envalid');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const morgan = require('morgan');
const { body, validationResult } = require('express-validator');
require('express-async-errors');
const crypto = require('crypto');

// Validate environment variables
const env = cleanEnv(process.env, {
  MONGODB_URI: url(),
  TWILIO_ACCOUNT_SID: str(),
  TWILIO_AUTH_TOKEN: str(),
  TWILIO_PHONE_NUMBER: str(),
  GOOGLE_CLIENT_ID: str(),
  EMAILJS_PUBLIC_KEY: str(),
  EMAILJS_PRIVATE_KEY: str(),
  EMAILJS_SERVICE_ID: str(),
  EMAILJS_TEMPLATE_ID: str(),
  PORT: port({ default: 5001 }),
  FRONTEND_URL: str({ default: 'http://localhost:3000' }) // Add your frontend URL
});

// Initialize Express
const app = express();

// Middleware
app.set('trust proxy', 1); // Trust first proxy for HTTPS
app.use(helmet()); // Secure HTTP headers
app.use(morgan('combined')); // HTTP request logging
app.use(express.json());
app.use(cors({
  origin: env.FRONTEND_URL,
  credentials: true
}));
app.use(cookieParser());

// Rate limiting for sensitive routes
app.use('/login', rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10
}));
app.use('/forgot-password', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5
}));

// Initialize EmailJS
emailjs.init({
  publicKey: env.EMAILJS_PUBLIC_KEY,
  privateKey: env.EMAILJS_PRIVATE_KEY,
});

// MongoDB Connection with Retry
const connectWithRetry = () => {
  mongoose.connect(env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000,
    heartbeatFrequencyMS: 10000,
    maxPoolSize: 10
  })
    .then(() => console.log('Connected to MongoDB Atlas'))
    .catch((err) => {
      console.error('MongoDB connection error:', err);
      setTimeout(connectWithRetry, 5000);
    });
};
connectWithRetry();

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String },
  email: { type: String, required: true, unique: true },
  name: { type: String },
  phoneNumber: { type: String },
  googleId: { type: String, unique: true, sparse: true },
  githubId: { type: String, unique: true, sparse: true },
  avatar: { type: String },
  age: { type: Number, min: 1, max: 120 },
  followUpRequired: { type: Boolean, default: false },
  AppointmentApproved: { type: Boolean, default: false },
  visits: { type: Number, default: 0 },
  resetPasswordToken: { type: String },
  resetPasswordExpires: { type: Date },
  appointments: [{
    date: { type: String, required: true },
    time: { type: String, required: true },
    doctor: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
  }],
  analyses: [{
    transcription: { type: String },
    analysis: {
      Emotions: [String],
      Reasons: String,
      Suggestions: [String],
    },
    createdAt: { type: Date, default: Date.now }
  }],
  session: {
    sessionActive: { type: Boolean, default: false },
    question: { type: String, default: '' },
    sessionEnded: { type: Boolean, default: false },
    responses: [{
      audioPath: { type: String, required: true },
      question: { type: String, required: true },
      language: { type: String, default: 'en' },
      createdAt: { type: Date, default: Date.now }
    }],
    latestAnalysis: {
      transcriptions: [{
        question: String,
        text: String
      }],
      individual_analyses: [{
        Emotions: [String],
        Tones: [String],
        Reasons: String,
        Suggestions: [String]
      }],
      combined_analysis: String,
      createdAt: { type: Date }
    },
    updatedAt: { type: Date, default: Date.now }
  }
});

// Indexes for performance
userSchema.index({ username: 1 });
userSchema.index({ email: 1 });
userSchema.index({ googleId: 1 });
userSchema.index({ githubId: 1 });

const User = mongoose.model('User', userSchema);

// File Upload Configuration
const uploadDir = 'uploads';
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    const filetypes = /mp3|wav|m4a|webm/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    if (extname && mimetype) return cb(null, true);
    cb(new Error('Invalid file type! Only mp3, wav, m4a, and webm are allowed.'));
  }
});

// Mock Analysis Function
const analyzeTranscription = (transcription) => {
  return {
    Emotions: ['happy', 'calm'],
    Reasons: 'The tone suggests positive feelings',
    Suggestions: ['Continue positive activities', 'Maintain routine']
  };
};

// Authentication Middleware
const authMiddleware = async (req, res, next) => {
  try {
    const username = req.cookies.username;
    if (!username) {
      return res.status(401).json({ error: 'Please log in first' });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(500).json({ error: 'Authentication error: ' + error.message });
  }
};

// Twilio Client Setup
const client = twilio(env.TWILIO_ACCOUNT_SID, env.TWILIO_AUTH_TOKEN);

// Forgot Password Route
app.post('/forgot-password', [
  body('email').isEmail().normalizeEmail()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User with this email does not exist' });
    }

    // Generate secure token
    const verificationCode = crypto.randomBytes(20).toString('hex');
    user.resetPasswordToken = verificationCode;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    // Send email with verification code
    await emailjs.send(env.EMAILJS_SERVICE_ID, env.EMAILJS_TEMPLATE_ID, {
      email: email,
      passcode: verificationCode,
    });

    res.status(200).json({ message: 'Verification code sent to email' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

// Reset Password Route
app.post('/reset-password', [
  body('email').isEmail().normalizeEmail(),
  body('code').isString().notEmpty(),
  body('newPassword').isLength({ min: 8 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, code, newPassword } = req.body;

  try {
    const user = await User.findOne({
      email,
      resetPasswordToken: code,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired verification code' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.status(200).json({ message: 'Password has been reset successfully' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

// Register Route
app.post('/register', [
  body('username').trim().isLength({ min: 3 }).escape(),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }),
  body('phoneNumber').optional().isMobilePhone('any'),
  body('age').optional().isInt({ min: 1, max: 120 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password, email, name, phoneNumber, avatar, age } = req.body;

  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      if (existingUser.username === username) return res.status(400).json({ error: 'Username already exists' });
      if (existingUser.email === email) return res.status(400).json({ error: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      username,
      email,
      password: hashedPassword,
      name,
      phoneNumber,
      avatar,
      age,
      followUpRequired: false,
      AppointmentApproved: false,
      appointments: [],
      session: { sessionActive: false, question: '', sessionEnded: false, responses: [], latestAnalysis: null }
    });
    await user.save();

    res.status(201).json({
      message: 'Registration successful',
      username,
      email,
      name,
      phoneNumber,
      avatar,
      age,
      followUpRequired: false,
      AppointmentApproved: false,
      appointments: []
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

// Login Route
app.post('/login', [
  body('username').trim().isLength({ min: 3 }).escape(),
  body('password').isLength({ min: 8 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    res.cookie('username', username, {
      httpOnly: true,
      secure: env.isProd,
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000 // 1 day
    });

    res.status(200).json({
      message: 'Login successful',
      username: user.username,
      email: user.email,
      avatar: user.avatar,
      age: user.age,
      phoneNumber: user.phoneNumber,
      followUpRequired: user.followUpRequired,
      AppointmentApproved: user.AppointmentApproved,
      appointments: user.appointments
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

// Logout Route
app.post('/logout', (req, res) => {
  res.clearCookie('username', { path: '/' });
  res.status(200).json({ message: 'Logout successful' });
});

// Google Login Endpoint
const googleClient = new OAuth2Client(env.GOOGLE_CLIENT_ID);
app.post('/google-login', async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) {
      return res.status(400).json({ error: 'Google token is required' });
    }

    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const { sub: googleId, email, name } = payload;

    let user = await User.findOne({ googleId });
    if (!user) {
      const username = email.split('@')[0] + Math.floor(Math.random() * 1000);
      const existingUser = await User.findOne({ $or: [{ username }, { email }] });
      if (existingUser) {
        if (existingUser.username === username) return res.status(400).json({ error: 'Derived username already exists' });
        if (existingUser.email === email) return res.status(400).json({ error: 'Email already exists' });
      }

      user = new User({
        username,
        email,
        googleId,
        name,
        followUpRequired: false,
        AppointmentApproved: false,
        appointments: [],
        analyses: [],
        age: null,
        session: { sessionActive: false, question: '', sessionEnded: false, responses: [], latestAnalysis: null }
      });
      await user.save();
    }

    res.cookie('username', user.username, {
      httpOnly: true,
      secure: env.isProd,
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000
    });

    res.status(200).json({
      message: 'Google login successful',
      username: user.username,
      email: user.email,
      avatar: user.avatar,
      age: user.age,
      phoneNumber: user.phoneNumber,
      followUpRequired: user.followUpRequired,
      AppointmentApproved: user.AppointmentApproved,
      appointments: user.appointments
    });
  } catch (error) {
    console.error('Google login error:', error);
    res.status(400).json({ error: 'Google login failed' });
  }
});

// Analyze Audio Route
app.post('/analyze_audio', upload.single('file'), [
  body('username').trim().isLength({ min: 3 }).escape()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    return res.status(400).json({ errors: errors.array() });
  }

  const { username } = req.body;
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      fs.unlinkSync(req.file.path);
      return res.status(401).json({ error: 'User not found' });
    }

    const transcription = 'Sample transcription from audio';
    const analysis = analyzeTranscription(transcription);

    user.analyses.push({ transcription, analysis });
    await user.save();

    fs.unlinkSync(req.file.path);

    res.json({
      username,
      email: user.email,
      transcription,
      analysis,
      followUpRequired: user.followUpRequired,
      AppointmentApproved: user.AppointmentApproved,
      appointments: user.appointments
    });
  } catch (error) {
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

// Generate PDF Route
app.post('/generate_pdf', async (req, res) => {
  const { analysis } = req.body;
  if (!analysis) {
    return res.status(400).json({ error: 'Analysis data is required' });
  }

  try {
    const doc = new PDFDocument();
    const filename = `mental_health_report_${Date.now()}.pdf`;
    doc.pipe(fs.createWriteStream(filename));

    doc.fontSize(22).text('Mental Health Analysis Report', { align: 'center' });
    doc.fontSize(10).text(`Date: ${new Date().toLocaleString()}`, { align: 'left' });
    doc.moveDown();

    doc.fontSize(14).text('Emotions Identified:');
    (analysis.Emotions || []).forEach(emotion => doc.text(`• ${emotion}`));
    doc.moveDown();

    doc.fontSize(14).text('Tones Identified:');
    (analysis.Tones || []).forEach(tone => doc.text(`• ${tone}`));
    doc.moveDown();

    doc.fontSize(14).text('Possible Reasons:');
    doc.fontSize(10).text(analysis.Reasons || 'Not provided', { align: 'justify' });
    doc.moveDown();

    doc.fontSize(14).text('Suggestions:');
    (analysis.Suggestions || []).forEach(suggestion => doc.text(`✔ ${suggestion}`));

    doc.end();

    res.download(filename, 'Analysis_Report.pdf', (err) => {
      if (!err) {
        fs.unlinkSync(filename);
      } else {
        console.error('Download error:', err);
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

// Save Analysis Route
app.post('/save_analysis', authMiddleware, async (req, res) => {
  const { username, transcriptions, analyses } = req.body;

  if (!transcriptions || !analyses || transcriptions.length !== analyses.length || transcriptions.length === 0) {
    return res.status(400).json({ error: 'Both transcriptions and analyses are required and must match in length' });
  }

  try {
    const analysesToSave = transcriptions.map((transcription, index) => ({
      transcription,
      analysis: analyses[index],
      createdAt: new Date()
    }));

    const user = await User.findOneAndUpdate(
      { username },
      {
        $push: {
          analyses: { $each: analysesToSave }
        },
        $inc: { visits: 1 }
      },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.status(200).json({ message: 'Analyses saved successfully', visits: user.visits });
  } catch (error) {
    console.error('Error saving analyses:', error);
    res.status(500).json({ error: 'Failed to save analyses' });
  }
});

// Export All Analyses Route
app.post('/users/:username/export-analyses', async (req, res) => {
  const { username } = req.params;

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const doc = new PDFDocument();
    const filename = `all_analyses_${username}_${Date.now()}.pdf`;
    doc.pipe(fs.createWriteStream(filename));

    doc.fontSize(22).text(`All Mental Health Analyses for ${username}`, { align: 'center' });
    doc.fontSize(10).text(`Generated on: ${new Date().toLocaleString()}`, { align: 'left' });
    doc.moveDown();

    user.analyses.forEach((analysis, index) => {
      doc.fontSize(16).text(`Analysis ${index + 1}`, { underline: true });
      doc.moveDown(0.5);

      doc.fontSize(14).text('Transcription:');
      doc.fontSize(10).text(analysis.transcription || 'Not provided', { align: 'left' });
      doc.moveDown();

      doc.fontSize(14).text('Emotions Identified:');
      (analysis.analysis.Emotions || []).forEach(emotion => doc.text(`• ${emotion}`));
      doc.moveDown();

      doc.fontSize(14).text('Possible Reasons:');
      doc.fontSize(10).text(analysis.analysis.Reasons || 'Not provided', { align: 'left' });
      doc.moveDown();

      doc.fontSize(14).text('Suggestions:');
      (analysis.analysis.Suggestions || []).forEach(suggestion => doc.text(`✔ ${suggestion}`));
      doc.moveDown();

      if (index < user.analyses.length - 1) doc.addPage();
    });

    doc.end();

    res.download(filename, `All_Analyses_${username}.pdf`, (err) => {
      if (!err) {
        fs.unlinkSync(filename);
      } else {
        console.error('Export error:', err);
        res.status(500).json({ error: 'Failed to export analyses' });
      }
    });
  } catch (error) {
    console.error('Export error:', error.message);
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

// Delete Analysis Route
app.delete('/users/:username/analyses/:analysisId', async (req, res) => {
  const { username, analysisId } = req.params;
  try {
    const result = await User.updateOne(
      { username },
      { $pull: { analyses: { _id: new mongoose.Types.ObjectId(analysisId) } } }
    );

    if (result.modifiedCount === 0) {
      const user = await User.findOne({ username });
      if (!user) {
        return res.status(404).json({ success: false, message: 'User not found' });
      }
      const analysisExists = user.analyses.some(a => a._id.toString() === analysisId);
      if (!analysisExists) {
        return res.status(404).json({ success: false, message: 'Analysis not found' });
      }
      return res.status(500).json({ success: false, message: 'Failed to delete analysis' });
    }

    res.status(200).json({ success: true, message: 'Analysis deleted successfully' });
  } catch (error) {
    console.error('Error deleting analysis:', error.message);
    res.status(500).json({ success: false, message: 'Server error: ' + error.message });
  }
});

// Get All Users Route
app.get('/users', async (req, res) => {
  try {
    const users = await User.find()
      .select('username email phoneNumber age followUpRequired AppointmentApproved appointments analyses googleId githubId avatar')
      .lean();

    if (!users || users.length === 0) {
      return res.status(404).json({ message: 'No users found' });
    }

    res.status(200).json({
      message: 'Users retrieved successfully',
      count: users.length,
      users
    });
  } catch (error) {
    console.error('Error fetching users:', error.message);
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

// Get User by Username Route
app.get('/users/username', authMiddleware, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username })
      .select('username email phoneNumber age followUpRequired AppointmentApproved appointments analyses avatar');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.status(200).json({
      success: true,
      data: {
        username: user.username,
        email: user.email,
        phoneNumber: user.phoneNumber,
        age: user.age,
        followUpRequired: user.followUpRequired,
        AppointmentApproved: user.AppointmentApproved,
        appointments: user.appointments,
        analyses: user.analyses,
        avatar: user.avatar
      }
    });
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: error.message
    });
  }
});

// Delete User Route
app.delete('/users/:id', async (req, res) => {
  const userId = req.params.id;
  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    await User.deleteOne({ _id: userId });
    res.status(200).json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error.message);
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

// Update Follow-Up Status Route
app.patch('/users/:id', [
  body('followUpRequired').isBoolean()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { id } = req.params;
  const { followUpRequired } = req.body;

  try {
    const user = await User.findByIdAndUpdate(
      id,
      { followUpRequired },
      { new: true, runValidators: true }
    ).select('username email phoneNumber age followUpRequired AppointmentApproved appointments analyses avatar');

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.status(200).json({
      message: 'Follow-up status updated successfully',
      user
    });
  } catch (error) {
    console.error('Error updating follow-up status:', error.message);
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

// Profile Routes
app.get('/api/user/profile', authMiddleware, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username })
      .select('username email name avatar age phoneNumber followUpRequired AppointmentApproved appointments visits -_id');

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.status(200).json({
      username: user.username,
      email: user.email,
      name: user.name || user.username,
      avatar: user.avatar,
      age: user.age,
      phoneNumber: user.phoneNumber,
      followUpRequired: user.followUpRequired,
      AppointmentApproved: user.AppointmentApproved,
      appointments: user.appointments,
      visits: user.visits
    });
  } catch (error) {
    console.error('Error fetching profile:', error);
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

app.put('/api/user/profile', authMiddleware, [
  body('name').trim().isLength({ min: 1 }).escape(),
  body('email').isEmail().normalizeEmail(),
  body('avatar').optional().isURL(),
  body('age').optional().isInt({ min: 1, max: 120 }),
  body('phoneNumber').optional().isMobilePhone('any')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { name, email, avatar, age, phoneNumber } = req.body;

  try {
    const emailInUse = await User.findOne({
      email,
      username: { $ne: req.user.username }
    });
    if (emailInUse) {
      return res.status(400).json({ error: 'Email already in use' });
    }

    if (phoneNumber) {
      const phoneInUse = await User.findOne({
        phoneNumber,
        username: { $ne: req.user.username }
      });
      if (phoneInUse) {
        return res.status(400).json({ error: 'Phone number already in use' });
      }
    }

    const updatedUser = await User.findOneAndUpdate(
      { username: req.user.username },
      { name, email, avatar, age, phoneNumber },
      { new: true, runValidators: true }
    ).select('username email name avatar age phoneNumber followUpRequired AppointmentApproved appointments -_id');

    if (!updatedUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.status(200).json({
      message: 'Profile updated successfully',
      username: updatedUser.username,
      email: updatedUser.email,
      name: updatedUser.name,
      avatar: updatedUser.avatar,
      age: updatedUser.age,
      phoneNumber: updatedUser.phoneNumber,
      followUpRequired: updatedUser.followUpRequired,
      AppointmentApproved: updatedUser.AppointmentApproved,
      appointments: updatedUser.appointments
    });
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

// Send SMS Route
app.post('/api/send-sms', authMiddleware, [
  body('phoneNumber').isMobilePhone('any'),
  body('date').isString().notEmpty(),
  body('time').isString().notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { phoneNumber, date, time } = req.body;

  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user || user.phoneNumber !== phoneNumber.replace('+91', '')) {
      return res.status(403).json({ error: 'Phone number does not match user profile' });
    }

    const messageBody = `Hi, just a reminder: you’re set to see Dr. Prashik on ${date} at ${time}`;

    const message = await client.messages.create({
      body: messageBody,
      from: env.TWILIO_PHONE_NUMBER,
      to: phoneNumber
    });

    console.log('SMS sent:', message.sid);
    res.status(200).json({ message: 'SMS sent successfully', sid: message.sid });
  } catch (error) {
    console.error('Twilio error:', error);
    res.status(500).json({ error: 'Failed to send SMS', details: error.message });
  }
});

// Approve Appointment Route
app.patch('/api/user/approve-appointment', authMiddleware, [
  body('date').isString().notEmpty(),
  body('time').isString().notEmpty(),
  body('doctor').isString().notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { date, time, doctor } = req.body;

  try {
    const user = await User.findOneAndUpdate(
      { username: req.user.username },
      {
        $set: { AppointmentApproved: true },
        $push: {
          appointments: {
            date,
            time,
            doctor,
            createdAt: new Date()
          }
        }
      },
      { new: true, runValidators: true }
    ).select('username email phoneNumber AppointmentApproved followUpRequired appointments');

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.status(200).json({
      message: 'Appointment approved and saved successfully',
      user: {
        username: user.username,
        email: user.email,
        phoneNumber: user.phoneNumber,
        AppointmentApproved: user.AppointmentApproved,
        followUpRequired: user.followUpRequired,
        appointments: user.appointments
      }
    });
  } catch (error) {
    console.error('Error approving appointment:', error);
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

// Session Management Routes
app.get('/api/session/active', authMiddleware, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username })
      .select('session');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.status(200).json({
      active: user.session.sessionActive,
      question: user.session.question,
      sessionEnded: user.session.sessionEnded
    });
  } catch (error) {
    console.error('Error fetching session:', error);
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

app.post('/api/session/start', authMiddleware, [
  body('userId').isMongoId(),
  body('question').isString().notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { userId, question } = req.body;

  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      {
        $set: {
          'session.sessionActive': true,
          'session.question': question,
          'session.sessionEnded': false,
          'session.responses': [],
          'session.latestAnalysis': null,
          'session.updatedAt': new Date()
        }
      },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    console.log(`Session started for user ${userId} with question: ${question}`);
    res.status(200).json({ message: 'Session started' });
  } catch (error) {
    console.error('Error starting session:', error);
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

app.post('/api/session/record_response', authMiddleware, upload.single('file'), [
  body('question').isString().notEmpty(),
  body('language').isString().notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    return res.status(400).json({ errors: errors.array() });
  }

  const { question, language } = req.body;
  if (!req.file) {
    return res.status(400).json({ error: 'Audio file is required' });
  }

  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) {
      fs.unlinkSync(req.file.path);
      return res.status(404).json({ error: 'User not found' });
    }

    if (!user.session.sessionActive || user.session.question !== question) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: 'No active session or invalid question' });
    }

    if (user.session.responses.length > 0) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: 'Response already recorded for this session' });
    }

    const response = {
      audioPath: req.file.path,
      question,
      language,
      createdAt: new Date()
    };

    user.session.responses.push(response);
    await user.save();

    res.status(200).json({ message: 'Response recorded successfully' });
  } catch (error) {
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    console.error('Error recording response:', error);
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

app.get('/api/session/responses/:userId', authMiddleware, async (req, res) => {
  const { userId } = req.params;

  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (!user.session.sessionActive) {
      return res.status(400).json({ error: 'No active session for this user' });
    }

    const responses = user.session.responses.map(response => ({
      audioPath: response.audioPath,
      question: response.question,
      language: response.language,
      createdAt: response.createdAt
    }));

    res.status(200).json({ responses });
  } catch (error) {
    console.error('Error fetching session responses:', error);
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

app.post('/api/session/save_analysis', authMiddleware, [
  body('userId').isMongoId(),
  body('analysis').isObject()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { userId, analysis } = req.body;

  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.session.latestAnalysis = {
      transcriptions: analysis.transcriptions,
      individual_analyses: analysis.individual_analyses,
      combined_analysis: analysis.combined_analysis,
      createdAt: new Date()
    };

    const analysesToSave = analysis.transcriptions.map((transcription, index) => ({
      transcription: transcription.text,
      analysis: analysis.individual_analyses[index],
      createdAt: new Date()
    }));

    user.analyses.push(...analysesToSave);
    user.visits += 1;

    user.session.responses.forEach(response => {
      if (fs.existsSync(response.audioPath)) {
        fs.unlinkSync(response.audioPath);
      }
    });

    user.session.responses = [];
    await user.save();

    res.status(200).json({ message: 'Analysis saved successfully' });
  } catch (error) {
    console.error('Error saving session analysis:', error);
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

app.get('/api/session/latest_analysis', authMiddleware, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username })
      .select('session.latestAnalysis');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.status(200).json({
      analysis: user.session.latestAnalysis
    });
  } catch (error) {
    console.error('Error fetching latest analysis:', error);
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

app.post('/api/session/end', authMiddleware, [
  body('userId').isMongoId()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { userId } = req.body;

  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (!user.session.sessionActive) {
      return res.status(400).json({ error: 'No active session for this user' });
    }

    user.session.responses.forEach(response => {
      if (fs.existsSync(response.audioPath)) {
        fs.unlinkSync(response.audioPath);
      }
    });

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      {
        $set: {
          'session.sessionActive': false,
          'session.question': '',
          'session.sessionEnded': true,
          'session.responses': [],
          'session.updatedAt': new Date()
        }
      },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    console.log(`Session ended for user ${userId}`);
    res.status(200).json({ message: 'Session ended' });
  } catch (error) {
    console.error('Error ending session:', error);
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

// Health Check Endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', uptime: process.uptime() });
});

// Global Error Handler
app.use((err, req, res, next) => {
  if (req.file && fs.existsSync(req.file.path)) {
    fs.unlinkSync(req.file.path);
  }
  console.error('Unhandled error:', err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Start Server
const PORT = env.PORT1;
app.listen(PORT, () => console.log(`Server running on port ${PORT} in ${env.isProd ? 'production' : 'development'} mode`));
