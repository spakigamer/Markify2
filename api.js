import express from 'express';
import bodyParser from 'body-parser';
import session from 'express-session';
import passport from 'passport';
import dotenv from 'dotenv';
import nodemailer from 'nodemailer';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as LocalStrategy } from 'passport-local';
import bcrypt from 'bcrypt';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';

const app = express();
const port = 3000;
dotenv.config();
const saltRounds = 10;

console.log(process.env.MONGO_URI)
// Connect to MongoDB
mongoose.connect(MONGO_URI, { dbName: "markify" });

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  googleId: String,
});

const noteSchema = new mongoose.Schema({
  email: String,
  marktext: String,
  title: String,
  description: String,
});

const User = mongoose.model('User', userSchema);
const Note = mongoose.model('Note', noteSchema);

// Middleware
app.use(cors({
  origin: ['http://localhost:5173', 'http://localhost:3000'],
  methods: 'GET,POST,PUT,DELETE',
  credentials: true,
}));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
  secret: process.env.SECRET_KEY,
  resave: false,
  saveUninitialized: false,
}));
app.use(passport.initialize());
app.use(passport.session());

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Unauthorized, token missing' });
  jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Google Authentication
passport.use('google',new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: 'http://localhost:3000/auth/google/secrets',
}, async (accessToken, refreshToken, profile, cb) => {
  try {
    let user = await User.findOne({ email: profile.emails[0].value });
    if (!user) {
      user = new User({
        name: profile.displayName,
        email: profile.emails[0].value,
        googleId: profile.id,
      });
      await user.save();
    }
    return cb(null, user);
  } catch (err) {
    return cb(err);
  }
}));

passport.serializeUser((user, cb) => cb(null, user.id));
passport.deserializeUser(async (id, cb) => {
  const user = await User.findById(id);
  cb(null, user);
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/secrets', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => {
  const token = jwt.sign({ id: req.user.id, email: req.user.email }, process.env.SECRET_KEY);
  res.redirect(`http://localhost:5173/dashboard?token=${token}`);
});

// Registration
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  const existingUser = await User.findOne({ email });
  if (existingUser) return res.redirect('/login');
  const hashedPassword = await bcrypt.hash(password, saltRounds);
  const user = new User({ name, email, password: hashedPassword });
  await user.save();
  const token = jwt.sign({ id: user.id, email: user.email }, process.env.SECRET_KEY, { expiresIn: '1h' });
  res.json({ token, message: 'Registration successful!' });
});

// Login
app.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) return res.status(500).json({ message: 'Internal Server Error' });
    if (!user) return res.status(401).json({ message: info.message });
    const token = jwt.sign({ id: user.id, email: user.email }, process.env.SECRET_KEY);
    res.json({ token, message: 'Login successful!' });
  })(req, res, next);
});

passport.use('local',new LocalStrategy({ usernameField: 'email', passwordField: 'password' }, async (email, password, cb) => {
  try {
    const user = await User.findOne({ email });
    if (!user) return cb(null, false, { message: 'User not found' });
    const valid = await bcrypt.compare(password, user.password);
    return cb(null, valid ? user : false);
  } catch (err) {
    return cb(err);
  }
}));

// CRUD Operations for Notes
app.post('/add', authenticateToken, async (req, res) => {
  const { marktext, title, description } = req.body;
  const note = new Note({ email: req.user.email, marktext, title, description });
  await note.save();
  res.json({ message: 'ok', note });
});

app.put('/add', authenticateToken, async (req, res) => {
  const { id, marktext, title, description } = req.body;
  const note = await Note.findByIdAndUpdate(id, { marktext, title, description }, { new: true });
  res.json({ message: 'ok', note });
});

app.get('/get-data', authenticateToken, async (req, res) => {
  const notes = await Note.find({ email: req.user.email }, '_id title description');
  res.json({ message: 'ok', data: notes });
});

app.post('/search', authenticateToken, async (req, res) => {
  const note = await Note.findById(req.body._id);
  res.json(note ? { resultsgot: note, message: 'true' } : { message: 'false' });
});

app.listen(port, () => console.log('Port 3000 is active'));
