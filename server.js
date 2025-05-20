const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const PDFDocument = require('pdfkit');
const cookieParser = require('cookie-parser');
const axios = require('axios');
const { OAuth2Client } = require('google-auth-library');
const twilio = require('twilio');
const emailjs = require('@emailjs/nodejs');
require('dotenv').config();
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

// Validate required environment variables
const requiredEnvVars = [
  'MONGODB_URI',
  'TWILIO_ACCOUNT_SID',
  'TWILIO_AUTH_TOKEN',
  'TWILIO_PHONE_NUMBER',
  'GOOGLE_CLIENT_ID',
  'EMAILJS_PUBLIC_KEY',
  'EMAILJS_PRIVATE_KEY',
  'EMAILJS_SERVICE_ID',
  'EMAILJS_TEMPLATE_ID',
  'FRONTEND_URL',
  'BACKEND_DOMAIN'
];

const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);
if (missingEnvVars.length > 0) {
  console.error(`Missing required environment variables: ${missingEnvVars.join(', ')}`);
  process.exit(1);
}

const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());

// Trust Render's proxy for secure cookies
app.set('trust proxy', 1);

// Log cookies and headers for debugging
app.use((req, res, next) => {
  console.log('Request URL:', req.url);
  console.log('Cookies:', req.cookies);
  console.log('Headers:', req.headers);
  next();
});

// CORS configuration
app.use(cors({
  origin: process.env.FRONTEND_URL || 'https://speech-park.web.app',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie']
}));

// Initialize EmailJS
emailjs.init({
  publicKey: process.env.EMAILJS_PUBLIC_KEY,
  privateKey: process.env.EMAILJS_PRIVATE_KEY,
});

// MongoDB Atlas Connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => console.log("Connected to MongoDB Atlas"))
  .catch((err) => console.error("MongoDB connection error:", err));

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

const User = mongoose.model("User", userSchema);

// File upload configuration
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
  fileFilter: (req, file, cb) => {
    const filetypes = /mp3|wav|m4a|webm/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    if (extname && mimetype) return cb(null, true);
    cb('Error: Invalid file type!');
  }
});

// Mock analysis function
const analyzeTranscription = (transcription) => {
  return {
    Emotions: ['happy', 'calm'],
    Reasons: 'The tone suggests positive feelings',
    Suggestions: ['Continue positive activities', 'Maintain routine']
  };
};

// Authentication Helper Function
const authenticateUser = async (req, res) => {
  console.log('Authenticating for URL:', req.url);
  console.log('Headers:', req.headers);

  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      console.log('No valid username provided in Authorization header');
      return { error: res.status(401).json({ error: 'Please provide a valid username in Authorization header' }) };
    }

    const username = authHeader.split(' ')[1];
    if (!username) {
      console.log('Username not provided in Authorization header');
      return { error: res.status(401).json({ error: 'Username required' }) };
    }

    const user = await User.findOne({
      username: { $regex: new RegExp(`^${username}$`, 'i') }
    });

    if (!user) {
      console.log(`User not found for username: ${username}`);
      return { error: res.status(401).json({ error: 'User not found' }) };
    }

    req.user = user;
    return { user };
  } catch (error) {
    console.error('Authentication error:', error.message);
    return { error: res.status(401).json({ error: 'Authentication failed' }) };
  }
};

// Twilio Client Setup
const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

// Forgot Password Route
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User with this email does not exist' });
    }

    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    user.resetPasswordToken = verificationCode;
    user.resetPasswordExpires = Date.now() + 3600000;
    await user.save();

    await emailjs.send(process.env.EMAILJS_SERVICE_ID, process.env.EMAILJS_TEMPLATE_ID, {
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
app.post('/reset-password', async (req, res) => {
  const { email, code, newPassword } = req.body;

  if (!email || !code || !newPassword) {
    return res.status(400).json({ error: 'Email, verification code, and new password are required' });
  }

  try {
    const user = await User.findOne({
      email,
      resetPasswordToken: code,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired verification code' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
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
app.post("/register", async (req, res) => {
  const { username, password, email, name, phoneNumber, avatar, age } = req.body;

  if (!username || !password || !email) {
    return res.status(400).json({ error: "Username, password, and email are required" });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: "Invalid email format" });
  }

  if (phoneNumber && !/^\+?[1-9]\d{1,14}$/.test(phoneNumber)) {
    return res.status(400).json({ error: "Invalid phone number format" });
  }

  if (age && (isNaN(age) || age < 1 || age > 120)) {
    return res.status(400).json({ error: "Age must be a number between 1 and 120" });
  }

  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      if (existingUser.username === username) return res.status(400).json({ error: "Username already exists" });
      if (existingUser.email === email) return res.status(400).json({ error: "Email already exists" });
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

    // Set cookie for non-auth purposes
    res.cookie('username', username, {
      httpOnly: false,
      secure: true,
      sameSite: 'Lax',
      path: '/',
      maxAge: 24 * 60 * 60 * 1000
    });

    console.log(`Register successful for ${username}`);
    res.status(201).json({
      message: "Registration successful",
      username, // Client stores username in localStorage
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
    console.error('Register error:', error.message);
    res.status(500).json({ error: "Server error: " + error.message });
  }
});

// Login Route
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password are required" });
  }

  try {
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    // Set cookie for non-auth purposes
    res.cookie('username', username, {
      httpOnly: false,
      secure: true,
      sameSite: 'None',
      path: '/',
      maxAge: 24 * 60 * 60 * 1000
    });

    console.log(`Login successful for ${username}`);
    res.status(200).json({
      message: "Login successful",
      username: user.username, // Client stores username in localStorage
      email: user.email,
      avatar: user.avatar,
      age: user.age,
      phoneNumber: user.phoneNumber,
      followUpRequired: user.followUpRequired,
      AppointmentApproved: user.AppointmentApproved,
      appointments: user.appointments
    });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ error: "Server error: " + error.message });
  }
});

// Logout Route
app.post("/logout", (req, res) => {
  res.clearCookie('username', {
    httpOnly: false,
    secure: true,
    sameSite: 'None',
    path: '/'
  });
  console.log('Logout successful, cookie cleared');
  res.status(200).json({ message: "Logout successful. Please remove the username from localStorage." });
});

// Google Login Endpoint
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
app.post('/google-login', async (req, res) => {
  try {
    const { token } = req.body;
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const { sub: googleId, email, name } = payload;

    let user = await User.findOne({ googleId });
    if (!user) {
      const username = email.split('@')[0] + Math.floor(Math.random() * 1000);
      const existingUser = await User.findOne({ $or: [{ username }, { email }] });
      if (existingUser) {
        if (existingUser.username === username) return res.status(400).json({ error: "Derived username already exists" });
        if (existingUser.email === email) return res.status(400).json({ error: "Email already exists" });
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

    // Set cookie for non-auth purposes
    res.cookie('username', user.username, {
      httpOnly: false,
      secure: true,
      sameSite: 'None',
      path: '/',
      maxAge: 24 * 60 * 60 * 1000
    });

    console.log(`Google login successful for ${user.username}`);
    res.status(200).json({
      message: "Google login successful",
      username: user.username, // Client stores username in localStorage
      email: user.email,
      avatar: user.avatar,
      age: user.age,
      phoneNumber: user.phoneNumber,
      followUpRequired: user.followUpRequired,
      AppointmentApproved: user.AppointmentApproved,
      appointments: user.appointments
    });
  } catch (error) {
    console.error("Google login error:", error);
    res.status(400).json({ error: 'Google login failed' });
  }
});

// Save Analysis Route
app.post('/save_analysis', async (req, res) => {
  const auth = await authenticateUser(req, res);
  if (auth.error) return;

  try {
    const { username, transcriptions, analyses } = req.body;

    if (!username) {
      return res.status(401).json({ error: 'User not authenticated' });
    }

    if (!transcriptions || !analyses || transcriptions.length !== analyses.length || transcriptions.length === 0) {
      return res.status(400).json({ error: 'Both transcriptions and analyses are required and must match in length' });
    }

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
app.post("/users/:username/export-analyses", async (req, res) => {
  const auth = await authenticateUser(req, res);
  if (auth.error) return;

  const { username } = req.params;

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
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
        res.status(500).json({ error: "Failed to export analyses" });
      }
    });
  } catch (error) {
    console.error("Export error:", error.message);
    res.status(500).json({ error: "Server error: " + error.message });
  }
});

// Delete Analysis Route
app.delete("/users/:username/analyses/:analysisId", async (req, res) => {
  const auth = await authenticateUser(req, res);
  if (auth.error) return;

  const { username, analysisId } = req.params;
  try {
    const result = await User.updateOne(
      { username },
      { $pull: { analyses: { _id: new mongoose.Types.ObjectId(analysisId) } } }
    );

    if (result.modifiedCount === 0) {
      const user = await User.findOne({ username });
      if (!user) {
        return res.status(404).json({ success: false, message: "User not found" });
      }
      const analysisExists = user.analyses.some(a => a._id.toString() === analysisId);
      if (!analysisExists) {
        return res.status(404).json({ success: false, message: "Analysis not found" });
      }
      return res.status(500).json({ success: false, message: "Failed to delete analysis" });
    }

    res.status(200).json({ success: true, message: "Analysis deleted successfully" });
  } catch (error) {
    console.error("Error deleting analysis:", error.message);
    res.status(500).json({ success: false, message: "Server error: " + error.message });
  }
});

// Get All Users Route
app.get("/users", async (req, res) => {
  try {
    const users = await User.find()
      .select('username email phoneNumber age followUpRequired AppointmentApproved appointments analyses googleId githubId avatar')
      .lean();

    if (!users || users.length === 0) {
      return res.status(404).json({ message: "No users found" });
    }

    res.status(200).json({
      message: "Users retrieved successfully",
      count: users.length,
      users
    });
  } catch (error) {
    console.error("Error fetching users:", error.message);
    res.status(500).json({ error: "Server error: " + error.message });
  }
});

// Get User by Username Route
app.get("/users/username", async (req, res) => {
  try {
    console.log('Request headers for /users/username:', req.headers);
    console.log('Cookies for /users/username:', req.cookies);
    const username = req.cookies.username;
    console.log('Fetching user with username from cookie:', username);

    if (!username) {
      console.log('No username cookie found in /users/username');
      return res.status(401).json({
        success: false,
        message: "No username found in cookies. Please log in."
      });
    }

    const user = await User.findOne({
      username: { $regex: new RegExp(`^${username}$`, 'i') }
    }).select('username email phoneNumber age followUpRequired AppointmentApproved appointments analyses avatar');

    if (!user) {
      console.log(`User not found for username: ${username}`);
      return res.status(404).json({
        success: false,
        message: "User not found"
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
    console.error('Error fetching user:', error.message);
    res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message
    });
  }
});

// Delete User Route
app.delete("/users/:id", async (req, res) => {
  const auth = await authenticateUser(req, res);
  if (auth.error) return;

  const userId = req.params.id;
  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    await User.deleteOne({ _id: userId });
    res.status(200).json({ message: "User deleted successfully" });
  } catch (error) {
    console.error("Error deleting user:", error.message);
    res.status(500).json({ error: "Server error: " + error.message });
  }
});

// Update Follow-Up Status Route
app.patch("/users/:id", async (req, res) => {
  const auth = await authenticateUser(req, res);
  if (auth.error) return;

  const { id } = req.params;
  const { followUpRequired } = req.body;

  if (typeof followUpRequired !== 'boolean') {
    return res.status(400).json({ error: "followUpRequired must be a boolean" });
  }

  try {
    const user = await User.findByIdAndUpdate(
      id,
      { followUpRequired },
      { new: true, runValidators: true }
    ).select('username email phoneNumber age followUpRequired AppointmentApproved appointments analyses avatar');

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.status(200).json({
      message: "Follow-up status updated successfully",
      user
    });
  } catch (error) {
    console.error("Error updating follow-up status:", error.message);
    res.status(500).json({ error: "Server error: " + error.message });
  }
});

// Profile Routes
// Get User Profile
app.get("/api/user/profile", async (req, res) => {
  const auth = await authenticateUser(req, res);
  if (auth.error) return;

  const user = auth.user;
  try {
    const profile = await User.findOne({ username: user.username })
      .select('username email name avatar age phoneNumber followUpRequired AppointmentApproved appointments visits -_id');

    res.status(200).json({
      username: profile.username,
      email: profile.email,
      name: profile.name || profile.username,
      avatar: profile.avatar,
      age: profile.age,
      phoneNumber: profile.phoneNumber,
      followUpRequired: profile.followUpRequired,
      AppointmentApproved: profile.AppointmentApproved,
      appointments: profile.appointments,
      visits: profile.visits
    });
  } catch (error) {
    console.error("Error fetching profile:", error);
    res.status(500).json({ error: "Server error: " + error.message });
  }
});

// Update User Profile
app.put("/api/user/profile", async (req, res) => {
  const auth = await authenticateUser(req, res);
  if (auth.error) return;

  const user = auth.user;
  const { name, email, avatar, age, phoneNumber } = req.body;

  if (!name || !email) {
    return res.status(400).json({ error: "Name and email are required" });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: "Invalid email format" });
  }

  if (age && (isNaN(age) || age < 1 || age > 120)) {
    return res.status(400).json({ error: "Age must be a number between 1 and 120" });
  }

  if (phoneNumber) {
    const phoneRegex = /^\+?[\d\s-]{10,}$/;
    if (!phoneRegex.test(phoneNumber)) {
      return res.status(400).json({ error: "Invalid phone number format" });
    }
  }

  try {
    const emailInUse = await User.findOne({
      email,
      username: { $ne: user.username }
    });
    if (emailInUse) {
      return res.status(400).json({ error: "Email already in use" });
    }

    if (phoneNumber) {
      const phoneInUse = await User.findOne({
        phoneNumber,
        username: { $ne: user.username }
      });
      if (phoneInUse) {
        return res.status(400).json({ error: "Phone number already in use" });
      }
    }

    const updatedUser = await User.findOneAndUpdate(
      { username: user.username },
      { name, email, avatar, age, phoneNumber },
      { new: true, runValidators: true }
    ).select('username email name avatar age phoneNumber followUpRequired AppointmentApproved appointments -_id');

    res.status(200).json({
      message: "Profile updated successfully",
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
    console.error("Error updating profile:", error);
    res.status(500).json({ error: "Server error: " + error.message });
  }
});

// Send SMS Route
app.post("/api/send-sms", async (req, res) => {
  const auth = await authenticateUser(req, res);
  if (auth.error) return;

  const user = auth.user;
  const { phoneNumber, date, time } = req.body;

  if (!phoneNumber || !date || !time) {
    return res.status(400).json({ error: "Phone number, date, and time are required" });
  }

  const phoneRegex = /^\+[1-9]\d{1,14}$/;
  if (!phoneRegex.test(phoneNumber)) {
    return res.status(400).json({ error: "Invalid phone number format. Must include country code (e.g., +91)" });
  }

  try {
    if (user.phoneNumber !== phoneNumber.replace('+91', '')) {
      return res.status(403).json({ error: "Phone number does not match user profile" });
    }

    const messageBody = `Hi, just a reminder: you’re set to see Dr. Prashik on ${date} at ${time}`;

    const message = await client.messages.create({
      body: messageBody,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: phoneNumber
    });

    console.log('SMS sent:', message.sid);
    res.status(200).json({ message: "SMS sent successfully", sid: message.sid });
  } catch (error) {
    console.error("Twilio error:", error);
    res.status(500).json({ error: "Failed to send SMS", details: error.message });
  }
});

// Approve Appointment Route
app.patch("/api/user/approve-appointment", async (req, res) => {
  const auth = await authenticateUser(req, res);
  if (auth.error) return;

  const user = auth.user;
  const { date, time, doctor } = req.body;

  if (!date || !time || !doctor) {
    return res.status(400).json({ error: "Date, time, and doctor are required" });
  }

  try {
    const updatedUser = await User.findOneAndUpdate(
      { username: user.username },
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

    res.status(200).json({
      message: "Appointment approved and saved successfully",
      user: {
        username: updatedUser.username,
        email: updatedUser.email,
        phoneNumber: updatedUser.phoneNumber,
        AppointmentApproved: updatedUser.AppointmentApproved,
        followUpRequired: updatedUser.followUpRequired,
        appointments: updatedUser.appointments
      }
    });
  } catch (error) {
    console.error("Error approving appointment:", error);
    res.status(500).json({ error: "Server error: " + error.message });
  }
});

// Session Management Routes
// Get Active Session
app.get('/api/session/active', async (req, res) => {
  const auth = await authenticateUser(req, res);
  if (auth.error) return;

  const user = auth.user;
  try {
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

// Start Session
app.post('/api/session/start', async (req, res) => {
  const auth = await authenticateUser(req, res);
  if (auth.error) return;

  const { userId, question } = req.body;

  if (!userId || !question) {
    return res.status(400).json({ error: 'User ID and question are required' });
  }

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

// Record Session Response
app.post('/api/session/record_response', upload.single('file'), async (req, res) => {
  const auth = await authenticateUser(req, res);
  if (auth.error) return;

  const user = auth.user;
  const { question, language } = req.body;

  if (!req.file) {
    return res.status(400).json({ error: 'Audio file is required' });
  }

  if (!question || !language) {
    return res.status(400).json({ error: 'Question and language are required' });
  }

  try {
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
    if (fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    console.error('Error recording response:', error);
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

// Get Session Responses
app.get('/api/session/responses/:userId', async (req, res) => {
  const auth = await authenticateUser(req, res);
  if (auth.error) return;

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

// Save Session Analysis
app.post('/api/session/save_analysis', async (req, res) => {
  const auth = await authenticateUser(req, res);
  if (auth.error) return;

  const { userId, analysis } = req.body;

  if (!userId || !analysis) {
    return res.status(400).json({ error: 'User ID and analysis data are required' });
  }

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

// Get Latest Session Analysis
app.get('/api/session/latest_analysis', async (req, res) => {
  const auth = await authenticateUser(req, res);
  if (auth.error) return;

  const user = auth.user;
  try {
    res.status(200).json({
      analysis: user.session.latestAnalysis
    });
  } catch (error) {
    console.error('Error fetching latest analysis:', error);
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

// End Session
app.post('/api/session/end', async (req, res) => {
  const auth = await authenticateUser(req, res);
  if (auth.error) return;

  const { userId } = req.body;

  if (!userId) {
    return res.status(400).json({ error: 'User ID is required' });
  }

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

const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
