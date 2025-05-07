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
  'FRONTEND_URL'
];

const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);
if (missingEnvVars.length > 0) {
  console.error(`Missing required environment variables: ${missingEnvVars.join(', ')}`);
  process.exit(1);
}

const app = express();

// Middleware
const corsOptions = {
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(express.json());
app.use(cors(corsOptions));
app.use(cookieParser());

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

// Updated User Schema
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

// Authentication Middleware
const authMiddleware = async (req, res, next) => {
  try {
    const username = req.cookies.username;
    if (!username) {
      return res.status(401).json({ error: "Please log in first" });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ error: "User not found" });
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(500).json({ error: "Authentication error: " + error.message });
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

    // Generate verification code
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();

    // Set reset token and expiration (1 hour)
    user.resetPasswordToken = verificationCode;
    user.resetPasswordExpires = Date.now() + 3600000;
    await user.save();

    // Send email with verification code using EmailJS
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

    // Hash new password
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
    return res.status(400).json({ error: "Username, bisogna specificare password ed email" });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: "Formato email non valido" });
  }

  if (phoneNumber && !/^\+?[1-9]\d{1,14}$/.test(phoneNumber)) {
    return res.status(400).json({ error: "Formato numero di telefono non valido" });
  }

  if (age && (isNaN(age) || age < 1 || age > 120)) {
    return res.status(400).json({ error: "L'età deve essere un numero compreso tra 1 e 120" });
  }

  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      if (existingUser.username === username) return res.status(400).json({ error: "Username già esistente" });
      if (existingUser.email === email) return res.status(400).json({ error: "Email già esistente" });
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
      message: "Registrazione completata con successo",
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
    res.status(500).json({ error: "Errore del server: " + error.message });
  }
});

// Login Route
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username e password sono richiesti" });
  }

  try {
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Username o password non validi" });
    }

    res.cookie('username', username, {
      httpOnly: false,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'None',
      path: '/',
      maxAge: 24 * 60 * 60 * 1000
    });

    res.status(200).json({
      message: "Accesso completato con successo",
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
    res.status(500).json({ error: "Errore del server: " + error.message });
  }
});

// Logout Route
app.post("/logout", (req, res) => {
  res.clearCookie('username', { path: '/' });
  res.status(200).json({ message: "Logout completato con successo" });
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
        if (existingUser.username === username) return res.status(400).json({ error: "Username derivato già esistente" });
        if (existingUser.email === email) return res.status(400).json({ error: "Email già esistente" });
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
      httpOnly: false,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'None',
      path: '/',
      maxAge: 24 * 60 * 60 * 1000
    });

    res.status(200).json({
      message: "Accesso con Google completato con successo",
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
    console.error("Errore accesso con Google:", error);
    res.status(400).json({ error: 'Accesso con Google fallito' });
  }
});

app.post("/analyze_audio", upload.single('file'), async (req, res) => {
  const { username } = req.body;

  if (!req.file) {
    return res.status(400).json({ error: "Nessun file caricato" });
  }

  if (!username) {
    return res.status(400).json({ error: "Username richiesto" });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ error: "Utente non trovato" });
    }

    const transcription = "Trascrizione di esempio dall'audio";
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
    if (fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    res.status(500).json({ error: "Errore del server: " + error.message });
  }
});

// Generate PDF Route
app.post("/generate_pdf", async (req, res) => {
  const { analysis } = req.body;

  if (!analysis) {
    return res.status(400).json({ error: "Dati di analisi richiesti" });
  }

  try {
    const doc = new PDFDocument();
    const filename = `mental_health_report_${Date.now()}.pdf`;
    doc.pipe(fs.createWriteStream(filename));

    doc.fontSize(22).text('Rapporto di Analisi della Salute Mentale', { align: 'center' });
    doc.fontSize(10).text(`Data: ${new Date().toLocaleString()}`, { align: 'left' });
    doc.moveDown();

    doc.fontSize(14).text('Emozioni Identificate:');
    (analysis.Emotions || []).forEach(emotion => doc.text(`• ${emotion}`));
    doc.moveDown();

    doc.fontSize(14).text('Toni Identificati:');
    (analysis.Tones || []).forEach(tone => doc.text(`• ${tone}`));
    doc.moveDown();

    doc.fontSize(14).text('Possibili Ragioni:');
    doc.fontSize(10).text(analysis.Reasons || 'Non fornito', { align: 'justify' });
    doc.moveDown();

    doc.fontSize(14).text('Suggerimenti:');
    (analysis.Suggestions || []).forEach(suggestion => doc.text(`✔ ${suggestion}`));

    doc.end();

    res.download(filename, 'Rapporto_Analisi.pdf', (err) => {
      if (!err) {
        fs.unlinkSync(filename);
      } else {
        console.error('Errore download:', err);
      }
    });
  } catch (error) {
    res.status(500).json({ error: "Errore del server: " + error.message });
  }
});

// Save Analysis Route
app.post('/save_analysis', async (req, res) => {
  try {
    const { username, transcriptions, analyses } = req.body;

    if (!username) {
      return res.status(401).json({ error: 'Utente non autenticato' });
    }

    if (!transcriptions || !analyses || transcriptions.length !== analyses.length || transcriptions.length === 0) {
      return res.status(400).json({ error: 'Trascrizioni e analisi sono richieste e devono corrispondere in lunghezza' });
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
      return res.status(404).json({ error: 'Utente non trovato' });
    }

    res.status(200).json({ message: 'Analisi salvate con successo', visits: user.visits });
  } catch (error) {
    console.error('Errore salvataggio analisi:', error);
    res.status(500).json({ error: 'Impossibile salvare le analisi' });
  }
});

// Export All Analyses Route
app.post("/users/:username/export-analyses", async (req, res) => {
  const { username } = req.params;

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: "Utente non trovato" });
    }

    const doc = new PDFDocument();
    const filename = `tutte_analisi_${username}_${Date.now()}.pdf`;
    doc.pipe(fs.createWriteStream(filename));

    doc.fontSize(22).text(`Tutte le Analisi di Salute Mentale per ${username}`, { align: 'center' });
    doc.fontSize(10).text(`Generato il: ${new Date().toLocaleString()}`, { align: 'left' });
    doc.moveDown();

    user.analyses.forEach((analysis, index) => {
      doc.fontSize(16).text(`Analisi ${index + 1}`, { underline: true });
      doc.moveDown(0.5);

      doc.fontSize(14).text('Trascrizione:');
      doc.fontSize(10).text(analysis.transcription || 'Non fornito', { align: 'left' });
      doc.moveDown();

      doc.fontSize(14).text('Emozioni Identificate:');
      (analysis.analysis.Emotions || []).forEach(emotion => doc.text(`• ${emotion}`));
      doc.moveDown();

      doc.fontSize(14).text('Possibili Ragioni:');
      doc.fontSize(10).text(analysis.analysis.Reasons || 'Non fornito', { align: 'left' });
      doc.moveDown();

      doc.fontSize(14).text('Suggerimenti:');
      (analysis.analysis.Suggestions || []).forEach(suggestion => doc.text(`✔ ${suggestion}`));
      doc.moveDown();

      if (index < user.analyses.length - 1) doc.addPage();
    });

    doc.end();

    res.download(filename, `Tutte_Analisi_${username}.pdf`, (err) => {
      if (!err) {
        fs.unlinkSync(filename);
      } else {
        console.error('Errore esportazione:', err);
        res.status(500).json({ error: "Impossibile esportare le analisi" });
      }
    });
  } catch (error) {
    console.error("Errore esportazione:", error.message);
    res.status(500).json({ error: "Errore del server: " + error.message });
  }
});

// Delete Analysis Route
app.delete("/users/:username/analyses/:analysisId", async (req, res) => {
  const { username, analysisId } = req.params;
  try {
    const result = await User.updateOne(
      { username },
      { $pull: { analyses: { _id: new mongoose.Types.ObjectId(analysisId) } } }
    );

    if (result.modifiedCount === 0) {
      const user = await User.findOne({ username });
      if (!user) {
        return res.status(404).json({ success: false, message: "Utente non trovato" });
      }
      const analysisExists = user.analyses.some(a => a._id.toString() === analysisId);
      if (!analysisExists) {
        return res.status(404).json({ success: false, message: "Analisi non trovata" });
      }
      return res.status(500).json({ success: false, message: "Impossibile eliminare l'analisi" });
    }

    res.status(200).json({ success: true, message: "Analisi eliminata con successo" });
  } catch (error) {
    console.error("Errore eliminazione analisi:", error.message);
    res.status(500).json({ success: false, message: "Errore del server: " + error.message });
  }
});

// Get All Users Route
app.get("/users", async (req, res) => {
  try {
    const users = await User.find()
      .select('username email phoneNumber age followUpRequired AppointmentApproved appointments analyses googleId githubId avatar')
      .lean();

    if (!users || users.length === 0) {
      return res.status(404).json({ message: "Nessun utente trovato" });
    }

    res.status(200).json({
      message: "Utenti recuperati con successo",
      count: users.length,
      users
    });
  } catch (error) {
    console.error("Errore recupero utenti:", error.message);
    res.status(500).json({ error: "Errore del server: " + error.message });
  }
});

// Get User by Username Route
app.get("/users/username", async (req, res) => {
  try {
    console.log('Cookies ricevuti:', req.cookies);
    const username = req.cookies.username;

    if (!username) {
      console.log('Nessun cookie username trovato');
      return res.status(401).json({
        success: false,
        message: "Nessun username trovato nei cookies. Effettua il login."
      });
    }

    const user = await User.findOne({
      username: { $regex: new RegExp(`^${username}$`, 'i') }
    }).select('username email phoneNumber age followUpRequired AppointmentApproved appointments analyses avatar');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "Utente non trovato"
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
    console.error('Errore recupero utente:', error);
    res.status(500).json({
      success: false,
      message: "Errore del server",
      error: error.message
    });
  }
});

// Delete User Route
app.delete("/users/:id", async (req, res) => {
  const userId = req.params.id;
  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "Utente non trovato" });
    }
    await User.deleteOne({ _id: userId });
    res.status(200).json({ message: "Utente eliminato con successo" });
  } catch (error) {
    console.error("Errore eliminazione utente:", error.message);
    res.status(500).json({ error: "Errore del server: " + error.message });
  }
});

// Update Follow-Up Status Route
app.patch("/users/:id", async (req, res) => {
  const { id } = req.params;
  const { followUpRequired } = req.body;

  if (typeof followUpRequired !== 'boolean') {
    return res.status(400).json({ error: "followUpRequired deve essere un booleano" });
  }

  try {
    const user = await User.findByIdAndUpdate(
      id,
      { followUpRequired },
      { new: true, runValidators: true }
    ).select('username email phoneNumber age followUpRequired AppointmentApproved appointments analyses avatar');

    if (!user) {
      return res.status(404).json({ error: "Utente non trovato" });
    }

    res.status(200).json({
      message: "Stato di follow-up aggiornato con successo",
      user
    });
  } catch (error) {
    console.error("Errore aggiornamento stato follow-up:", error.message);
    res.status(500).json({ error: "Errore del server: " + error.message });
  }
});

// Profile Routes
// Get User Profile
app.get("/api/user/profile", authMiddleware, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username })
      .select('username email name avatar age phoneNumber followUpRequired AppointmentApproved appointments visits -_id');

    if (!user) {
      return res.status(404).json({ error: "Utente non trovato" });
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
    console.error("Errore recupero profilo:", error);
    res.status(500).json({ error: "Errore del server: " + error.message });
  }
});

// Update User Profile
app.put("/api/user/profile", authMiddleware, async (req, res) => {
  const { name, email, avatar, age, phoneNumber } = req.body;

  if (!name || !email) {
    return res.status(400).json({ error: "Nome ed email sono richiesti" });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: "Formato email non valido" });
  }

  if (age && (isNaN(age) || age < 1 || age > 120)) {
    return res.status(400).json({ error: "L'età deve essere un numero compreso tra 1 e 120" });
  }

  if (phoneNumber) {
    const phoneRegex = /^\+?[\d\s-]{10,}$/;
    if (!phoneRegex.test(phoneNumber)) {
      return res.status(400).json({ error: "Formato numero di telefono non valido" });
    }
  }

  try {
    const emailInUse = await User.findOne({
      email,
      username: { $ne: req.user.username }
    });
    if (emailInUse) {
      return res.status(400).json({ error: "Email già in uso" });
    }

    if (phoneNumber) {
      const phoneInUse = await User.findOne({
        phoneNumber,
        username: { $ne: req.user.username }
      });
      if (phoneInUse) {
        return res.status(400).json({ error: "Numero di telefono già in uso" });
      }
    }

    const updatedUser = await User.findOneAndUpdate(
      { username: req.user.username },
      { name, email, avatar, age, phoneNumber },
      { new: true, runValidators: true }
    ).select('username email name avatar age phoneNumber followUpRequired AppointmentApproved appointments -_id');

    if (!updatedUser) {
      return res.status(404).json({ error: "Utente non trovato" });
    }

    res.status(200).json({
      message: "Profilo aggiornato con successo",
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
    console.error("Errore aggiornamento profilo:", error);
    res.status(500).json({ error: "Errore del server: " + error.message });
  }
});

// Send SMS Route
app.post("/api/send-sms", authMiddleware, async (req, res) => {
  const { phoneNumber, date, time } = req.body;
  if (!phoneNumber || !date || !time) {
    return res.status(400).json({ error: "Numero di telefono, data e ora sono richiesti" });
  }

  const phoneRegex = /^\+[1-9]\d{1,14}$/;
  if (!phoneRegex.test(phoneNumber)) {
    return res.status(400).json({ error: "Formato numero di telefono non valido. Deve includere il prefisso internazionale (es. +39)" });
  }

  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user || user.phoneNumber !== phoneNumber.replace('+39', '')) {
      return res.status(403).json({ error: "Il numero di telefono non corrisponde al profilo utente" });
    }

    const messageBody = `Ciao, un promemoria: hai un appuntamento con il Dr. Prashik il ${date} alle ${time}`;

    const message = await client.messages.create({
      body: messageBody,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: phoneNumber
    });

    console.log('SMS inviato:', message.sid);
    res.status(200).json({ message: "SMS inviato con successo", sid: message.sid });
  } catch (error) {
    console.error("Errore Twilio:", error);
    res.status(500).json({ error: "Impossibile inviare SMS", details: error.message });
  }
});

// Approve Appointment Route
app.patch("/api/user/approve-appointment", authMiddleware, async (req, res) => {
  const { date, time, doctor } = req.body;

  if (!date || !time || !doctor) {
    return res.status(400).json({ error: "Data, ora e medico sono richiesti" });
  }

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
      return res.status(404).json({ error: "Utente non trovato" });
    }

    res.status(200).json({
      message: "Appuntamento approvato e salvato con successo",
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
    console.error("Errore approvazione appuntamento:", error);
    res.status(500).json({ error: "Errore del server: " + error.message });
  }
});

// Session Management Routes
// Get Active Session
app.get('/api/session/active', authMiddleware, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username })
      .select('session');
    if (!user) {
      return res.status(404).json({ error: 'Utente non trovato' });
    }
    res.status(200).json({
      active: user.session.sessionActive,
      question: user.session.question,
      sessionEnded: user.session.sessionEnded
    });
  } catch (error) {
    console.error('Errore recupero sessione:', error);
    res.status(500).json({ error: 'Errore del server: ' + error.message });
  }
});

// Start Session
app.post('/api/session/start', authMiddleware, async (req, res) => {
  const { userId, question } = req.body;

  if (!userId || !question) {
    return res.status(400).json({ error: 'ID utente e domanda sono richiesti' });
  }

  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'Utente non trovato' });
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
      return res.status(404).json({ error: 'Utente non trovato' });
    }

    console.log(`Sessione avviata per l'utente ${userId} con domanda: ${question}`);
    res.status(200).json({ message: 'Sessione avviata' });
  } catch (error) {
    console.error('Erro überall starten der Sitzung:', error);
    res.status(500).json({ error: 'Serverfehler: ' + error.message });
  }
});

// Record Session Response
app.post('/api/session/record_response', authMiddleware, upload.single('file'), async (req, res) => {
  const { question, language } = req.body;

  if (!req.file) {
    return res.status(400).json({ error: 'Datei audio erforderlich' });
  }

  if (!question || !language) {
    return res.status(400).json({ error: 'Frage und Sprache erforderlich' });
  }

  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) {
      fs.unlinkSync(req.file.path);
      return res.status(404).json({ error: 'Benutzer nicht gefunden' });
    }

    if (!user.session.sessionActive || user.session.question !== question) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: 'Keine aktive Sitzung oder ungültige Frage' });
    }

    // Überprüfen, ob bereits eine Antwort existiert
    if (user.session.responses.length > 0) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: 'Antwort für diese Sitzung bereits aufgezeichnet' });
    }

    const response = {
      audioPath: req.file.path,
      question,
      language,
      createdAt: new Date()
    };

    user.session.responses.push(response);
    await user.save();

    res.status(200).json({ message: 'Antwort erfolgreich aufgezeichnet' });
  } catch (error) {
    if (fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    console.error('Fehler bei der Aufzeichnung der Antwort:', error);
    res.status(500).json({ error: 'Serverfehler: ' + error.message });
  }
});

// Get Session Responses
app.get('/api/session/responses/:userId', authMiddleware, async (req, res) => {
  const { userId } = req.params;

  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'Benutzer nicht gefunden' });
    }

    if (!user.session.sessionActive) {
      return res.status(400).json({ error: 'Keine aktive Sitzung für diesen Benutzer' });
    }

    const responses = user.session.responses.map(response => ({
      audioPath: response.audioPath,
      question: response.question,
      language: response.language,
      createdAt: response.createdAt
    }));

    res.status(200).json({ responses });
  } catch (error) {
    console.error('Fehler beim Abrufen der Sitzungsantworten:', error);
    res.status(500).json({ error: 'Serverfehler: ' + error.message });
  }
});

// Save Session Analysis
app.post('/api/session/save_analysis', authMiddleware, async (req, res) => {
  const { userId, analysis } = req.body;

  if (!userId || !analysis) {
    return res.status(400).json({ error: 'Benutzer-ID und Analysedaten erforderlich' });
  }

  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'Benutzer nicht gefunden' });
    }

    // Analyse in der Sitzung speichern
    user.session.latestAnalysis = {
      transcriptions: analysis.transcriptions,
      individual_analyses: analysis.individual_analyses,
      combined_analysis: analysis.combined_analysis,
      createdAt: new Date()
    };

    // Transkripte und Analysen in den Analysen des Benutzers speichern
    const analysesToSave = analysis.transcriptions.map((transcription, index) => ({
      transcription: transcription.text,
      analysis: analysis.individual_analyses[index],
      createdAt: new Date()
    }));

    user.analyses.push(...analysesToSave);
    user.visits += 1;

    // Antwort-Audiodateien bereinigen
    user.session.responses.forEach(response => {
      if (fs.existsSync(response.audioPath)) {
        fs.unlinkSync(response.audioPath);
      }
    });

    user.session.responses = [];
    await user.save();

    res.status(200).json({ message: 'Analyse erfolgreich gespeichert' });
  } catch (error) {
    console.error('Fehler beim Speichern der Sitzungsanalyse:', error);
    res.status(500).json({ error: 'Serverfehler: ' + error.message });
  }
});

// Get Latest Session Analysis
app.get('/api/session/latest_analysis', authMiddleware, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username })
      .select('session.latestAnalysis');
    if (!user) {
      return res.status(404).json({ error: 'Benutzer nicht gefunden' });
    }

    res.status(200).json({
      analysis: user.session.latestAnalysis
    });
  } catch (error) {
    console.error('Fehler beim Abrufen der neuesten Analyse:', error);
    res.status(500).json({ error: 'Serverfehler: ' + error.message });
  }
});

// End Session
app.post('/api/session/end', authMiddleware, async (req, res) => {
  const { userId } = req.body;

  if (!userId) {
    return res.status(400).json({ error: 'Benutzer-ID erforderlich' });
  }

  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'Benutzer nicht gefunden' });
    }

    if (!user.session.sessionActive) {
      return res.status(400).json({ error: 'Keine aktive Sitzung für diesen Benutzer' });
    }

    // Antwort-Audiodateien bereinigen
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
      return res.status(404).json({ error: 'Benutzer nicht gefunden' });
    }

    console.log(`Sitzung für Benutzer ${userId} beendet`);
    res.status(200).json({ message: 'Sitzung beendet' });
  } catch (error) {
    console.error('Fehler beim Beenden der Sitzung:', error);
    res.status(500).json({ error: 'Serverfehler: ' + error.message });
  }
});

const PORT = process.env.PORT1 || 5001;
app.listen(PORT, () => console.log(`Server läuft auf Port ${PORT}`));
