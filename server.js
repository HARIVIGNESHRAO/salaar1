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
const { OAuth2Client } = require('google-auth-library'); // Added for Google token verification

const app = express();

// Middleware
app.use(express.json());
app.use(cors({
  origin: true, // Allow all origins dynamically
  credentials: true // Enable cookies
}));
app.use(cookieParser());

// MongoDB Atlas Connection
mongoose.connect(
  "mongodb+srv://harisonu151:zZYoHOEqz8eiI3qP@salaar.st5tm.mongodb.net/park",
  { useNewUrlParser: true, useUnifiedTopology: true }
)
  .then(() => console.log("Connected to MongoDB Atlas"))
  .catch((err) => console.error("MongoDB connection error:", err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String }, // Optional for social logins
  googleId: { type: String, unique: true, sparse: true }, // For Google users
  githubId: { type: String, unique: true, sparse: true }, // For GitHub users
  analyses: [{
    transcription: String,
    analysis: {
      Emotions: [String],
      Reasons: String,
      Suggestions: [String],
    },
    createdAt: { type: Date, default: Date.now }
  }]
});

const User = mongoose.model("User", userSchema);

// File upload configuration (unchanged)
const uploadDir = 'uploads';
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    const filetypes = /mp3|wav|m4a/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    if (extname && mimetype) {
      return cb(null, true);
    }
    cb('Error: Invalid file type!');
  }
});

// Mock analysis function (unchanged)
const analyzeTranscription = (transcription) => {
  return {
    Emotions: ['happy', 'calm'],
    Reasons: 'The tone suggests positive feelings',
    Suggestions: ['Continue positive activities', 'Maintain routine']
  };
};


app.post("/register", async (req, res) => {
  const { username, password, email } = req.body;


  if (!username || !password || !email) {
    return res.status(400).json({ error: "Username, password, and email are required" });
  }


  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: "Invalid email format" });
  }

  try {

    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      if (existingUser.username === username) {
        return res.status(400).json({ error: "Username already exists" });
      }
      if (existingUser.email === email) {
        return res.status(400).json({ error: "Email already exists" });
      }
    }


    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      username,
      email,
      password: hashedPassword,
      analyses: []
    });
    await user.save();

    res.status(201).json({ message: "Registration successful" });
  } catch (error) {
    res.status(500).json({ error: "Server error: " + error.message });
  }
});

// Login Route (unchanged)
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

    res.status(200).json({ message: "Login successful", username });
  } catch (error) {
    res.status(500).json({ error: "Server error: " + error.message });
  }
});

// Logout Route (unchanged)
app.post("/logout", (req, res) => {
  res.clearCookie('username', { path: '/' });
  res.status(200).json({ message: "Logout successful" });
});

// Google Login Endpoint
const googleClient = new OAuth2Client("423273358250-erqvredg1avk5pr09ugj8uve1rg11m3m.apps.googleusercontent.com");
app.post('/google-login', async (req, res) => {
  try {
    const { token } = req.body;
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: "423273358250-erqvredg1avk5pr09ugj8uve1rg11m3m.apps.googleusercontent.com",
    });
    const payload = ticket.getPayload();
    const { sub: googleId, email, name } = payload;

    // Check if user exists with this Google ID
    let user = await User.findOne({ googleId });
    if (!user) {
      // Check if username (email-based) already exists to avoid duplicates
      const username = email.split('@')[0] + Math.floor(Math.random() * 1000); // Simple unique username
      const existingUser = await User.findOne({ username });
      if (existingUser) {
        return res.status(400).json({ error: "Derived username already exists" });
      }

      // Create new user
      user = new User({
        username,
        googleId,
        analyses: []
      });
      await user.save();
    }

    res.status(200).json({ message: "Google login successful", username: user.username });
  } catch (error) {
    console.error("Google login error:", error);
    res.status(400).json({ error: 'Google login failed' });
  }
});

// GitHub Login Endpoint
app.post('/github-login', async (req, res) => {
  try {
    const { code } = req.body;

    // Exchange code for access token
    const tokenResponse = await axios.post('https://github.com/login/oauth/access_token', {
      client_id: "Ov23liiXOYhc1dxfIBau",
      client_secret: "54fde01a3e0a2d13c548e1ee038de1754ca5b443",
      code,
    }, {
      headers: { Accept: 'application/json' }
    });

    const accessToken = tokenResponse.data.access_token;
    if (!accessToken) {
      return res.status(400).json({ error: 'Failed to get GitHub access token' });
    }

    // Get GitHub user info
    const userResponse = await axios.get('https://api.github.com/user', {
      headers: { Authorization: `token ${accessToken}` }
    });
    const { id: githubId, login: username, name } = userResponse.data;

    // Check if user exists with this GitHub ID
    let user = await User.findOne({ githubId });
    if (!user) {
      // Check if username already exists
      const existingUser = await User.findOne({ username });
      if (existingUser) {
        return res.status(400).json({ error: "GitHub username already exists" });
      }

      // Create new user
      user = new User({
        username,
        githubId,
        analyses: []
      });
      await user.save();
    }

    res.status(200).json({ message: "GitHub login successful", username: user.username });
  } catch (error) {
    console.error("GitHub login error:", error);
    res.status(400).json({ error: 'GitHub login failed' });
  }
});

// Analyze Audio Route (unchanged)
app.post("/analyze_audio", upload.single('file'), async (req, res) => {
  const { username } = req.body;

  if (!req.file) {
    return res.status(400).json({ error: "No file uploaded" });
  }

  if (!username) {
    return res.status(400).json({ error: "Username is required" });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ error: "User not found" });
    }

    const transcription = "Sample transcription from audio";
    const analysis = analyzeTranscription(transcription);

    user.analyses.push({ transcription, analysis });
    await user.save();

    fs.unlinkSync(req.file.path);

    res.json({ username, transcription, analysis });
  } catch (error) {
    if (fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    res.status(500).json({ error: "Server error: " + error.message });
  }
});

// Generate PDF Route (unchanged)
app.post("/generate_pdf", async (req, res) => {
  const { transcription, analysis, username } = req.body;

  if (!analysis || !username) {
    return res.status(400).json({ error: "Missing required data" });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ error: "Invalid username" });
    }

    const doc = new PDFDocument();
    const filename = `mental_health_report_${Date.now()}.pdf`;
    doc.pipe(fs.createWriteStream(filename));

    doc.fontSize(22).text('Mental Health Analysis Report', { align: 'center' });
    doc.fontSize(10).text(`Date: ${new Date().toLocaleString()}`, { align: 'left' });
    doc.moveDown();

    doc.fontSize(14).text('Transcription:');
    doc.fontSize(10).text(transcription || 'Not provided', { align: 'left' });
    doc.moveDown();

    doc.fontSize(14).text('Emotions Identified:');
    (analysis.Emotions || []).forEach(emotion => doc.text(`• ${emotion}`));
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
    res.status(500).json({ error: "Server error: " + error.message });
  }
});

// Save Analysis Route (unchanged)
app.post("/save_analysis", async (req, res) => {
  const { username, transcription, analysis } = req.body;

  if (!username || !transcription || !analysis) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    user.analyses.push({ transcription, analysis });
    await user.save();

    console.log(`Analysis saved for ${username}:`, { transcription, analysis });

    res.json({ message: "Analysis saved successfully" });
  } catch (error) {
    console.error("Error saving analysis:", error.message);
    res.status(500).json({ error: "Server error" });
  }
});

// Get All Users Route (unchanged)
app.get("/users", async (req, res) => {
  try {
    const users = await User.find()
      .select('-password')
      .lean();

    if (!users || users.length === 0) {
      return res.status(404).json({ message: "No users found" });
    }

    res.status(200).json({
      message: "Users retrieved successfully",
      count: users.length,
      users: users
    });
  } catch (error) {
    console.error("Error fetching users:", error.message);
    res.status(500).json({ error: "Server error: " + error.message });
  }
});
app.get("/users/username", async (req, res) => {
  try {
    const username = req.cookies.username;

    if (!username) {
      return res.status(401).json({
        success: false,
        message: "No username found in cookies. Please log in."
      });
    }

    const user = await User.findOne({
      username: { $regex: new RegExp(`^${username}$`, 'i') }
    }).select('-password'); // Exclude password from response

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found"
      });
    }

    res.status(200).json({
      success: true,
      data: user
    });
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message
    });
  }
});

// Start Server
const PORT = 5001;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
