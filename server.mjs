// ═══════════════════════════════════════════════════════════
//  ALINO — Production Server v5
//  New: Age/Name/College/State fields · 16+ age gate
//       Account lockout (5 failed logins) · Login history
//       Password strength (frontend) · Username suggestions
//       No duplicate post titles · 1 post/hour limit
//       Profanity filter · IP tracking · Bulk delete flagged
// ═══════════════════════════════════════════════════════════
import 'dotenv/config';
// web-push loaded dynamically to prevent crash if not installed
import express    from 'express';
import mongoose   from 'mongoose';
import multer     from 'multer';
import bcrypt     from 'bcryptjs';
import jwt        from 'jsonwebtoken';
import zlib       from 'zlib';
import path       from 'path';
import crypto     from 'crypto';
import nodemailer from 'nodemailer';
import { v2 as cloudinary } from 'cloudinary';
import { promisify }     from 'util';
import rateLimit         from 'express-rate-limit';
import { fileURLToPath } from 'url';
import cors    from 'cors';
import helmet  from 'helmet';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
const gzip   = promisify(zlib.gzip);
const gunzip = promisify(zlib.gunzip);

// ─────────────────────────────────────────
//  APP + CONFIG
// ─────────────────────────────────────────
const app = express();
app.set('trust proxy', 1);

const PORT        = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const APP_URL     = (process.env.APP_URL || '').replace(/\/$/, '');

// Web Push VAPID setup
const VAPID_PUBLIC  = process.env.VAPID_PUBLIC  || '';
const VAPID_PRIVATE = process.env.VAPID_PRIVATE || '';
const VAPID_EMAIL   = process.env.VAPID_EMAIL   || 'mailto:admin@alino.in';
let webpush = null;
(async () => {
  try {
    const wp = await import('web-push');
    webpush = wp.default;
    if (VAPID_PUBLIC && VAPID_PRIVATE) {
      webpush.setVapidDetails(VAPID_EMAIL, VAPID_PUBLIC, VAPID_PRIVATE);
      console.log('✅  Web Push configured');
    } else {
      console.log('ℹ️   Web Push not configured (add VAPID_PUBLIC, VAPID_PRIVATE to Railway)');
    }
  } catch(e) {
    console.log('ℹ️   web-push not available — push notifications disabled');
  }
})();

const JWT_SECRET = process.env.JWT_SECRET || 'AlinoSecretKey2026XyzAbc789Secure!';

const CLOUDINARY_ON = !!(
  process.env.CLOUDINARY_CLOUD_NAME &&
  process.env.CLOUDINARY_API_KEY   &&
  process.env.CLOUDINARY_API_SECRET
);
if (CLOUDINARY_ON) {
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key:    process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
  });
  console.log('✅  Cloudinary enabled');
} else {
  console.log('ℹ️   Cloudinary not configured — images stored in MongoDB');
}

const EMAIL_ON = !!(process.env.EMAIL_USER && process.env.EMAIL_PASS);
const mailer = EMAIL_ON ? nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
}) : null;
if (EMAIL_ON) console.log('✅  Email enabled via Gmail SMTP');
else console.log('ℹ️   Email not configured — users auto-verified');

// ─────────────────────────────────────────
//  SECURITY MIDDLEWARE
// ─────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(__dirname));
app.get('/health', (_req, res) => res.json({ status: 'ok', uptime: Math.floor(process.uptime()) }));

// ─────────────────────────────────────────
//  RATE LIMITERS
// ─────────────────────────────────────────
const authLimiter  = rateLimit({ windowMs: 5*60*1000, max: 10, standardHeaders: true,
  message: { success: false, message: 'Too many attempts — wait 5 minutes.' } });
const writeLimiter = rateLimit({ windowMs: 60*1000, max: 20,
  message: { success: false, message: 'Slow down — you are posting too fast.' } });
const apiLimiter   = rateLimit({ windowMs: 60*1000, max: 120 });
app.use('/api/', apiLimiter);

// ─────────────────────────────────────────
//  DATABASE
// ─────────────────────────────────────────
if (!MONGODB_URI) { console.error('FATAL: MONGODB_URI not set.'); process.exit(1); }
mongoose.connect(MONGODB_URI, { serverSelectionTimeoutMS: 10000, socketTimeoutMS: 45000 })
  .then(() => console.log('✅  MongoDB connected'))
  .catch(err => { console.error('MongoDB error:', err.message); process.exit(1); });
mongoose.connection.on('disconnected', () => console.warn('MongoDB disconnected — reconnecting...'));
mongoose.connection.on('error', err => console.error('MongoDB runtime error:', err.message));

// ─────────────────────────────────────────
//  SCHEMAS
// ─────────────────────────────────────────
const NE_STATES = [
  'Andhra Pradesh','Arunachal Pradesh','Assam','Bihar',
  'Chhattisgarh','Goa','Gujarat','Haryana','Himachal Pradesh',
  'Jharkhand','Karnataka','Kerala','Madhya Pradesh','Maharashtra',
  'Manipur','Meghalaya','Mizoram','Nagaland','Odisha','Punjab',
  'Rajasthan','Sikkim','Tamil Nadu','Telangana','Tripura',
  'Uttar Pradesh','Uttarakhand','West Bengal',
  'Andaman and Nicobar Islands','Chandigarh','Dadra and Nagar Haveli',
  'Daman and Diu','Delhi','Jammu and Kashmir','Ladakh',
  'Lakshadweep','Puducherry','Other'
];

const UserSchema = new mongoose.Schema({
  username:       { type: String, unique: true, required: true, trim: true, minlength: 3, maxlength: 30 },
  email:          { type: String, unique: true, required: true, lowercase: true, trim: true },
  password:       { type: String, required: true },
  fullName:       { type: String, default: '', maxlength: 100, trim: true },
  age:            { type: Number, default: null, min: 16, max: 120 },
  college:        { type: String, default: '', maxlength: 150, trim: true },
  state:          { type: String, default: '', enum: [...NE_STATES, ''] },
  avatar:         { type: Buffer, default: null },
  avatarUrl:      { type: String, default: '' },
  avatarType:     { type: String, default: null },
  bio:            { type: String, default: '', maxlength: 500 },
  role:           { type: String, enum: ['student', 'admin'], default: 'student' },
  reputation:     { type: Number, default: 0 },
  banned:         { type: Boolean, default: false },
  emailVerified:  { type: Boolean, default: true },
  loginAttempts:  { type: Number, default: 0 },
  lockUntil:      { type: Date, default: null },
  registrationIp: { type: String, default: '' },
  loginHistory: [{
    ip:        String,
    userAgent: String,
    success:   Boolean,
    at:        { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
});

const ProjectSchema = new mongoose.Schema({
  title:          { type: String, required: true, maxlength: 100 },
  description:    { type: String, required: true, maxlength: 2000 },
  category:       { type: String, required: true, index: true },
  tags:           [{ type: String, maxlength: 30 }],
  authorId:       { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  authorName:     String,
  files:          [{ name: String, data: Buffer, mimetype: String, size: Number, compressed: { type: Boolean, default: false } }],
  screenshots:    [{ data: Buffer, mimetype: String }],
  screenshotUrls: [String],
  githubUrl:      { type: String, default: '' },
  demoUrl:        { type: String, default: '' },
  thumbnailUrl:   { type: String, default: '' },
  views:          { type: Number, default: 0 },
  score:          { type: Number, default: 0 },
  reported:       { type: Boolean, default: false },
  createdAt:      { type: Date, default: Date.now }
});
ProjectSchema.index({ tags: 1 });
ProjectSchema.index({ title: 'text', description: 'text', tags: 'text' });
ProjectSchema.index({ title: 1 });

const InteractionSchema = new mongoose.Schema({
  projectId: { type: mongoose.Schema.Types.ObjectId, ref: 'Project', index: true },
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  type:      { type: String, enum: ['like', 'bookmark', 'download', 'view'] },
  createdAt: { type: Date, default: Date.now }
});
InteractionSchema.index({ projectId: 1, userId: 1, type: 1 });

const CommentSchema = new mongoose.Schema({
  projectId: { type: mongoose.Schema.Types.ObjectId, ref: 'Project', index: true },
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  username:  String,
  content:   { type: String, required: true, maxlength: 1000 },
  createdAt: { type: Date, default: Date.now }
});

const PushSubscriptionSchema = new mongoose.Schema({
  userId:   { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  endpoint: { type: String, required: true },
  keys:     { p256dh: String, auth: String },
  createdAt:{ type: Date, default: Date.now }
});
PushSubscriptionSchema.index({ userId: 1, endpoint: 1 }, { unique: true });
const PushSub = mongoose.model('PushSub', PushSubscriptionSchema);

const NotificationSchema = new mongoose.Schema({
  userId:       { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  message:      String,
  type:         { type: String, default: 'general' },
  fromUserId:   { type: mongoose.Schema.Types.ObjectId, default: null },
  fromUsername: { type: String, default: '' },
  projectId:    { type: mongoose.Schema.Types.ObjectId, default: null },
  read:         { type: Boolean, default: false },
  createdAt:    { type: Date, default: Date.now }
});

const ReportSchema = new mongoose.Schema({
  projectId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
  reporterId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  reason:     { type: String, maxlength: 500 },
  resolved:   { type: Boolean, default: false },
  createdAt:  { type: Date, default: Date.now }
});

const EmailVerificationSchema = new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  token:     { type: String, required: true, index: true },
  expiresAt: { type: Date, required: true }
});

const PasswordResetSchema = new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  token:     { type: String, required: true, index: true },
  expiresAt: { type: Date, required: true },
  used:      { type: Boolean, default: false }
});


const FollowSchema = new mongoose.Schema({
  followerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  followingId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  createdAt: { type: Date, default: Date.now }
});
FollowSchema.index({ followerId: 1, followingId: 1 }, { unique: true });

const FeaturedPostSchema = new mongoose.Schema({
  projectId: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
  setBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now }
});

const Follow = mongoose.model('Follow', FollowSchema);
const FeaturedPost = mongoose.model('FeaturedPost', FeaturedPostSchema);
const User              = mongoose.model('User',              UserSchema);
const Project           = mongoose.model('Project',           ProjectSchema);
const Interaction       = mongoose.model('Interaction',       InteractionSchema);
const Comment           = mongoose.model('Comment',           CommentSchema);
const Notification      = mongoose.model('Notification',      NotificationSchema);
const Report            = mongoose.model('Report',            ReportSchema);
const EmailVerification = mongoose.model('EmailVerification', EmailVerificationSchema);
const PasswordReset     = mongoose.model('PasswordReset',     PasswordResetSchema);

// ─────────────────────────────────────────
//  SECURITY HELPERS
// ─────────────────────────────────────────
function sanitize(str, maxLen = 2000) {
  if (!str) return '';
  return String(str).replace(/<[^>]*>/g,'').replace(/javascript:/gi,'').replace(/on\w+\s*=/gi,'').trim().slice(0, maxLen);
}
function safeUrl(url) {
  if (!url) return '';
  try { const u = new URL(url); if (u.protocol==='http:'||u.protocol==='https:') return url.slice(0,500); } catch {}
  return '';
}
function escapeRegex(str) { return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
function safeFileName(name) {
  if (!name) return 'file';
  return path.basename(name).replace(/[^a-zA-Z0-9._\-]/g,'_').slice(0,200);
}
function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
}

// ─────────────────────────────────────────
//  ACCOUNT LOCKOUT
// ─────────────────────────────────────────
const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_DURATION_MS   = 5 * 60 * 1000;

function isAccountLocked(user) {
  if (!user.lockUntil) return false;
  return user.lockUntil > new Date();
}

async function handleFailedLogin(user, ip, userAgent) {
  const attempts = (user.loginAttempts || 0) + 1;
  const update = {
    loginAttempts: attempts,
    $push: { loginHistory: { $each: [{ ip, userAgent, success: false, at: new Date() }], $slice: -50 } }
  };
  if (attempts >= MAX_LOGIN_ATTEMPTS) update.lockUntil = new Date(Date.now() + LOCK_DURATION_MS);
  await User.findByIdAndUpdate(user._id, update);
}

async function handleSuccessfulLogin(user, ip, userAgent) {
  await User.findByIdAndUpdate(user._id, {
    loginAttempts: 0, lockUntil: null,
    $push: { loginHistory: { $each: [{ ip, userAgent, success: true, at: new Date() }], $slice: -50 } }
  });
}

// ─────────────────────────────────────────
//  USERNAME SUGGESTIONS
// ─────────────────────────────────────────
async function suggestUsernames(base) {
  const candidates = [
    `${base}_ne`,
    `${base}${new Date().getFullYear()}`,
    `${base}_${Math.floor(Math.random()*900)+100}`,
    `${base}_dev`,
    `the_${base}`,
    `${base}_student`,
  ];
  const suggestions = [];
  for (const c of candidates) {
    if (suggestions.length >= 3) break;
    const clean = c.replace(/[^a-zA-Z0-9_]/g, '_').slice(0, 30);
    const taken = await User.findOne({ username: clean });
    if (!taken) suggestions.push(clean);
  }
  while (suggestions.length < 3) {
    suggestions.push(`${base}_${Math.floor(Math.random()*9000)+1000}`.slice(0,30));
  }
  return suggestions.slice(0, 3);
}

// ─────────────────────────────────────────
//  PROFANITY FILTER
// ─────────────────────────────────────────
const PROFANITY_LIST = [
  'fuck','shit','ass','bitch','cunt','dick','cock','pussy',
  'bastard','whore','slut','asshole','motherfucker','crap',
  'piss','fag','nigger','nigga','retard','bollocks','wanker',
  'twat','prick','arse','shag','bugger'
];
const PROFANITY_REGEX = new RegExp(
  `\\b(${PROFANITY_LIST.map(w => w.split('').join('[^a-z0-9]*')).join('|')})\\b`, 'i'
);
function containsProfanity(text) { return text ? PROFANITY_REGEX.test(text) : false; }
function profanityMessage() { return 'Your post contains inappropriate language. Please keep it professional.'; }

// ─────────────────────────────────────────
//  CONTENT MODERATION
// ─────────────────────────────────────────
const BAD_PATTERNS = [
  /\b(spam|scam|hack|phish|malware|ransomware|exploit|ddos)\b/i,
  /(buy\s+now|click\s+here|free\s+money|make\s+money\s+fast)/i,
  /(.)(\1){9,}/,
  /https?:\/\/[^\s]+\s+https?:\/\/[^\s]+\s+https?:\/\/[^\s]+/i
];
function flaggedContent(text) { return BAD_PATTERNS.some(p => p.test(text)); }
async function moderateContent(projectId, reporterId, reason) {
  try {
    const exists = await Report.findOne({ projectId, reason: 'Auto: '+reason });
    if (!exists) { await Report.create({ projectId, reporterId, reason: 'Auto: '+reason }); await Project.findByIdAndUpdate(projectId, { reported: true }); }
  } catch {}
}

// ─────────────────────────────────────────
//  CLOUDINARY HELPERS
// ─────────────────────────────────────────
async function uploadToCloudinary(buffer, mimetype, folder='alino') {
  if (!CLOUDINARY_ON) return null;
  try {
    const result = await cloudinary.uploader.upload(`data:${mimetype};base64,${buffer.toString('base64')}`, {
      folder, resource_type: 'image', transformation: [{ quality: 'auto', fetch_format: 'auto' }]
    });
    return result.secure_url;
  } catch (err) { console.error('Cloudinary upload failed:', err.message); return null; }
}
async function deleteFromCloudinary(url) {
  if (!CLOUDINARY_ON || !url) return;
  try { const m = url.match(/\/alino\/([^.]+)/); if (m) await cloudinary.uploader.destroy('alino/'+m[1]); } catch {}
}

// ─────────────────────────────────────────
//  EMAIL HELPERS
// ─────────────────────────────────────────
async function sendEmail(to, subject, html) {
  if (!EMAIL_ON) return;
  try { await mailer.sendMail({ from: `"Alino" <${process.env.EMAIL_USER}>`, to, subject, html }); }
  catch (err) { console.error('Email send failed:', err.message); }
}
function verifyEmailHtml(username, verifyUrl) {
  return `<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:500px;margin:40px auto;padding:20px"><div style="text-align:center;margin-bottom:24px"><div style="background:#FF4500;color:white;font-size:1.4rem;font-weight:800;padding:12px 24px;border-radius:8px;display:inline-block">alino</div></div><h2>Verify your email</h2><p>Hi <strong>${username}</strong>! Click below to verify.</p><div style="text-align:center;margin:28px 0"><a href="${verifyUrl}" style="background:#FF4500;color:white;padding:12px 28px;border-radius:6px;text-decoration:none;font-weight:700">Verify My Email →</a></div><p style="color:#888;font-size:.85rem">Expires in 24 hours.</p></body></html>`;
}
function resetPasswordHtml(username, resetUrl) {
  return `<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:500px;margin:40px auto;padding:20px"><div style="text-align:center;margin-bottom:24px"><div style="background:#FF4500;color:white;font-size:1.4rem;font-weight:800;padding:12px 24px;border-radius:8px;display:inline-block">alino</div></div><h2>Reset your password</h2><p>Hi <strong>${username}</strong>!</p><div style="text-align:center;margin:28px 0"><a href="${resetUrl}" style="background:#0079D3;color:white;padding:12px 28px;border-radius:6px;text-decoration:none;font-weight:700">Reset My Password →</a></div><p style="color:#888;font-size:.85rem">Expires in 1 hour.</p></body></html>`;
}

// ─────────────────────────────────────────
//  FILE UPLOAD CONFIG
// ─────────────────────────────────────────
const ALLOWED_MIMETYPES = new Set([
  'image/jpeg','image/png','image/gif','image/webp',
  'application/zip','application/x-zip-compressed',
  'text/html','text/css','text/plain','text/javascript',
  'application/javascript','application/pdf'
]);
const IMAGE_MIMETYPES = new Set(['image/jpeg','image/png','image/gif','image/webp']);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20*1024*1024, files: 8 },
  fileFilter: (_req, file, cb) => {
    if (file.fieldname==='screenshots'||file.fieldname==='avatar') {
      if (!IMAGE_MIMETYPES.has(file.mimetype)) return cb(new Error('Images only'));
    } else {
      if (!ALLOWED_MIMETYPES.has(file.mimetype)&&!file.originalname.endsWith('.zip')) return cb(new Error(`File type not allowed`));
    }
    cb(null, true);
  }
});

const TEXT_TYPES = ['text/','application/javascript','application/json'];
async function compressFile(buf, mime) {
  if (TEXT_TYPES.some(t=>mime.startsWith(t))) return { data: await gzip(buf), compressed: true };
  return { data: buf, compressed: false };
}
async function decompressFile(buf, compressed) { return compressed ? gunzip(buf) : buf; }

// ─────────────────────────────────────────
//  AUTH MIDDLEWARE
// ─────────────────────────────────────────
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ success: false, message: 'Authentication required' });
  try { req.user = jwt.verify(auth.split(' ')[1], JWT_SECRET); next(); }
  catch { res.status(401).json({ success: false, message: 'Invalid or expired token' }); }
}
function authMiddlewareOrQuery(req, res, next) {
  const token = req.query.token || req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'Authentication required' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ success: false, message: 'Invalid or expired token' }); }
}
function adminMiddleware(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin access required' });
  next();
}
function getUserIdFromToken(req) {
  try { const t = req.query.token||req.headers.authorization?.split(' ')[1]; if (!t) return null; return jwt.verify(t, JWT_SECRET).id; } catch { return null; }
}

// ─────────────────────────────────────────
//  SSE
// ─────────────────────────────────────────
const sseClients = new Set();
function broadcast(event) {
  const data = `data: ${JSON.stringify(event)}\n\n`;
  for (const client of sseClients) { try { client.res.write(data); } catch { sseClients.delete(client); } }
}
app.get('/api/events', authMiddlewareOrQuery, (req, res) => {
  res.set({ 'Content-Type':'text/event-stream','Cache-Control':'no-cache','Connection':'keep-alive','X-Accel-Buffering':'no' });
  res.flushHeaders();
  res.write(`data: ${JSON.stringify({ type: 'connected' })}\n\n`);
  const client = { res, userId: req.user.id };
  sseClients.add(client);
  const hb = setInterval(() => { try { res.write(':heartbeat\n\n'); } catch { clearInterval(hb); sseClients.delete(client); } }, 25000);
  req.on('close', () => { clearInterval(hb); sseClients.delete(client); });
});

// ─────────────────────────────────────────
//  SCORE HELPERS
// ─────────────────────────────────────────
async function updateScore(projectId) {
  try {
    const [p,likes,dl] = await Promise.all([Project.findById(projectId,'views'),Interaction.countDocuments({projectId,type:'like'}),Interaction.countDocuments({projectId,type:'download'})]);
    if (p) await Project.findByIdAndUpdate(projectId,{score:(p.views||0)+(dl*2)+(likes*3)});
  } catch {}
}
function updateScoreAsync(pid) { setImmediate(()=>updateScore(pid)); }
async function getUserInteractions(projectId, userId) {
  if (!userId) return { hasLiked: false, hasBookmarked: false };
  const [like,bm] = await Promise.all([Interaction.findOne({projectId,userId,type:'like'}),Interaction.findOne({projectId,userId,type:'bookmark'})]);
  return { hasLiked: !!like, hasBookmarked: !!bm };
}
async function getProjectCounts(projectId) {
  const [likes,dl,bm] = await Promise.all([Interaction.countDocuments({projectId,type:'like'}),Interaction.countDocuments({projectId,type:'download'}),Interaction.countDocuments({projectId,type:'bookmark'})]);
  return { likes, downloads: dl, bookmarks: bm };
}

// ═══════════════════════════════════════════════════════════
//  AUTH ROUTES
// ═══════════════════════════════════════════════════════════

// Check username availability + suggest alternatives
app.get('/api/auth/check-username', async (req, res) => {
  try {
    const username = (req.query.username || '').trim();
    if (!username) return res.status(400).json({ success: false, message: 'Username required' });
    const taken = await User.findOne({ username });
    if (!taken) return res.json({ success: true, data: { available: true } });
    const suggestions = await suggestUsernames(username);
    return res.json({ success: true, data: { available: false, suggestions } });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { username, email, password, fullName, age, college, state } = req.body;
    if (!username || !email || !password)
      return res.status(400).json({ success: false, message: 'Username, email and password are required' });

    const cleanUsername = username.trim();
    const cleanEmail    = email.trim().toLowerCase();
    const cleanFullName = sanitize(fullName || '', 100);
    const cleanCollege  = sanitize(college  || '', 150);
    const cleanState    = NE_STATES.includes(state) ? state : '';
    const parsedAge     = age ? parseInt(age, 10) : null;

    // Age is required and must be 16+
    if (parsedAge === null || isNaN(parsedAge))
      return res.status(400).json({ success: false, message: 'Please enter your age to continue.' });
    if (parsedAge < 16)
      return res.status(400).json({ success: false, message: 'You must be at least 16 years old to join Alino.' });
    if (parsedAge > 120)
      return res.status(400).json({ success: false, message: 'Please enter a valid age.' });

    if (password.length < 6)
      return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });
    // Backend strength check — must have at least one letter and one number or symbol
    if (!/[a-zA-Z]/.test(password) || !/[0-9!@#$%^&*_\-+=]/.test(password))
      return res.status(400).json({ success: false, message: 'Password must contain at least one letter and one number or symbol (e.g. Abc123)' });
    if (cleanUsername.length < 3 || cleanUsername.length > 30)
      return res.status(400).json({ success: false, message: 'Username must be 3–30 characters' });
    if (!/^[a-zA-Z0-9_]+$/.test(cleanUsername))
      return res.status(400).json({ success: false, message: 'Username: letters, numbers and underscores only' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail))
      return res.status(400).json({ success: false, message: 'Please enter a valid email address' });

    // Check username — suggest alternatives if taken
    const existingUsername = await User.findOne({ username: cleanUsername });
    if (existingUsername) {
      const suggestions = await suggestUsernames(cleanUsername);
      return res.status(400).json({
        success: false,
        message: `"${cleanUsername}" is already taken.`,
        suggestions
      });
    }
    const existingEmail = await User.findOne({ email: cleanEmail });
    if (existingEmail)
      return res.status(400).json({ success: false, message: 'That email is already registered.' });

    const hashedPassword = await bcrypt.hash(password, 12);
    const adminEmail     = (process.env.ADMIN_EMAIL || '').toLowerCase().trim();
    const role           = (adminEmail && cleanEmail === adminEmail) ? 'admin' : 'student';
    const emailVerified  = !EMAIL_ON;
    const registrationIp = getClientIp(req);

    const user = await User.create({
      username: cleanUsername, email: cleanEmail, password: hashedPassword,
      fullName: cleanFullName, age: parsedAge, college: cleanCollege, state: cleanState,
      role, emailVerified, registrationIp
    });

    if (EMAIL_ON) {
      const token = crypto.randomBytes(32).toString('hex');
      await EmailVerification.create({ userId: user._id, token, expiresAt: new Date(Date.now()+24*60*60*1000) });
      const verifyUrl = `${APP_URL||'http://localhost:'+PORT}/?verify=${token}`;
      await sendEmail(cleanEmail, 'Verify your Alino email', verifyEmailHtml(cleanUsername, verifyUrl));
    }

    const tokenJwt = jwt.sign({ id: user._id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
    res.status(201).json({ success: true, data: {
      token: tokenJwt,
      user: { id: user._id, username: user.username, email: user.email, role: user.role,
              reputation: 0, emailVerified: user.emailVerified,
              fullName: user.fullName, age: user.age, college: user.college, state: user.state }
    }});
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password required' });

    const ip        = getClientIp(req);
    const userAgent = req.headers['user-agent'] || 'unknown';
    const user      = await User.findOne({ email: email.trim().toLowerCase() });

    if (!user) return res.status(401).json({ success: false, message: 'Invalid email or password' });
    if (user.banned) return res.status(403).json({ success: false, message: 'Account suspended' });

    if (isAccountLocked(user)) {
      const minutesLeft = Math.ceil((user.lockUntil - Date.now()) / 60000);
      return res.status(403).json({ success: false, message: `Account locked. Try again in ${minutesLeft} minute${minutesLeft!==1?'s':''}.` });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      await handleFailedLogin(user, ip, userAgent);
      const left = MAX_LOGIN_ATTEMPTS - ((user.loginAttempts||0) + 1);
      if (left <= 0) return res.status(401).json({ success: false, message: 'Account locked for 30 minutes.' });
      return res.status(401).json({ success: false, message: `Invalid email or password. ${left} attempt${left!==1?'s':''} remaining.` });
    }

    await handleSuccessfulLogin(user, ip, userAgent);
    const token = jwt.sign({ id: user._id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, data: {
      token,
      user: { id: user._id, username: user.username, email: user.email, role: user.role,
              reputation: user.reputation, bio: user.bio, emailVerified: user.emailVerified,
              fullName: user.fullName, age: user.age, college: user.college, state: user.state }
    }});
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password -avatar -loginHistory');
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    res.json({ success: true, data: user });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.get('/api/auth/verify-email/:token', async (req, res) => {
  try {
    const record = await EmailVerification.findOne({ token: req.params.token, expiresAt: { $gt: new Date() } });
    if (!record) return res.status(400).json({ success: false, message: 'Verification link expired or invalid.' });
    await User.findByIdAndUpdate(record.userId, { emailVerified: true });
    await EmailVerification.deleteMany({ userId: record.userId });
    res.json({ success: true, message: 'Email verified! You now have full access.' });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.post('/api/auth/resend-verification', authMiddleware, authLimiter, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    if (user.emailVerified) return res.json({ success: true, message: 'Email is already verified' });
    if (!EMAIL_ON) { await User.findByIdAndUpdate(req.user.id, { emailVerified: true }); return res.json({ success: true, message: 'Email verified!' }); }
    await EmailVerification.deleteMany({ userId: user._id });
    const token = crypto.randomBytes(32).toString('hex');
    await EmailVerification.create({ userId: user._id, token, expiresAt: new Date(Date.now()+24*60*60*1000) });
    const verifyUrl = `${APP_URL||'http://localhost:'+PORT}/?verify=${token}`;
    await sendEmail(user.email, 'Verify your Alino email', verifyEmailHtml(user.username, verifyUrl));
    res.json({ success: true, message: 'Verification email sent!' });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.post('/api/auth/forgot-password', authLimiter, async (req, res) => {
  try {
    const email = (req.body.email||'').trim().toLowerCase();
    if (!email) return res.status(400).json({ success: false, message: 'Email is required' });
    const user = await User.findOne({ email });
    if (!user||!EMAIL_ON) return res.json({ success: true, message: 'If that email exists, a reset link has been sent.' });
    await PasswordReset.deleteMany({ userId: user._id });
    const token = crypto.randomBytes(32).toString('hex');
    await PasswordReset.create({ userId: user._id, token, expiresAt: new Date(Date.now()+60*60*1000) });
    const resetUrl = `${APP_URL||'http://localhost:'+PORT}/?reset=${token}`;
    await sendEmail(user.email, 'Reset your Alino password', resetPasswordHtml(user.username, resetUrl));
    res.json({ success: true, message: 'If that email exists, a reset link has been sent.' });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.post('/api/auth/reset-password', authLimiter, async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token||!password) return res.status(400).json({ success: false, message: 'Token and password required' });
    if (password.length < 6) return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });
    const record = await PasswordReset.findOne({ token, used: false, expiresAt: { $gt: new Date() } });
    if (!record) return res.status(400).json({ success: false, message: 'Reset link expired or already used.' });
    const hp = await bcrypt.hash(password, 12);
    await User.findByIdAndUpdate(record.userId, { password: hp, loginAttempts: 0, lockUntil: null });
    await PasswordReset.findByIdAndUpdate(record._id, { used: true });
    res.json({ success: true, message: 'Password reset successfully! You can now log in.' });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

// ═══════════════════════════════════════════════════════════
//  PROJECT ROUTES
// ═══════════════════════════════════════════════════════════
app.get('/api/projects', async (req, res) => {
  try {
    const page     = Math.max(1, parseInt(req.query.page)||1);
    const limit    = Math.min(50, parseInt(req.query.limit)||15);
    const sort     = req.query.sort || 'trending';
    const search   = sanitize(req.query.search||'', 100);
    const category = sanitize(req.query.category||'', 50);
    const tag      = sanitize(req.query.tag||'', 50);
    const skip     = (page-1)*limit;

    const query = {};
    if (search)   query.$text    = { $search: search };
    if (category) query.category = category;
    if (tag)      query.tags     = tag;

    const sortMap = { trending:{score:-1}, newest:{createdAt:-1}, popular:{views:-1} };
    const sortObj = sortMap[sort]||{createdAt:-1};

    const [projects, total] = await Promise.all([
      Project.find(query,{'files.data':0,'screenshots.data':0}).sort(sortObj).skip(skip).limit(limit),
      Project.countDocuments(query)
    ]);

    const ids = projects.map(p=>p._id);
    const [la,da,ca] = await Promise.all([
      Interaction.aggregate([{$match:{projectId:{$in:ids},type:'like'}},{$group:{_id:'$projectId',count:{$sum:1}}}]),
      Interaction.aggregate([{$match:{projectId:{$in:ids},type:'download'}},{$group:{_id:'$projectId',count:{$sum:1}}}]),
      Comment.aggregate([{$match:{projectId:{$in:ids}}},{$group:{_id:'$projectId',count:{$sum:1}}}])
    ]);
    const lm = Object.fromEntries(la.map(x=>[x._id.toString(),x.count]));
    const dm = Object.fromEntries(da.map(x=>[x._id.toString(),x.count]));
    const cm = Object.fromEntries(ca.map(x=>[x._id.toString(),x.count]));

    const enriched = projects.map(p=>({...p.toObject(),likes:lm[p._id.toString()]||0,downloads:dm[p._id.toString()]||0,comments:cm[p._id.toString()]||0,hasScreenshot:p.screenshots?.length>0||p.screenshotUrls?.length>0,fileCount:p.files?.length||0}));
    res.json({ success: true, data: { projects: enriched, total, page, pages: Math.ceil(total/limit), hasMore: (page*limit)<total }});
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.post('/api/projects', authMiddleware, writeLimiter, upload.fields([{name:'files',maxCount:5},{name:'screenshots',maxCount:3}]), async (req, res) => {
  try {
    const { title, description, category, tags, githubUrl, demoUrl } = req.body;
    if (!title?.trim()||!description?.trim()||!category?.trim())
      return res.status(400).json({ success: false, message: 'Title, description, and category are required' });

    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    const cleanTitle       = sanitize(title, 100);
    const cleanDescription = sanitize(description, 2000);

    // Profanity check
    if (containsProfanity(cleanTitle)||containsProfanity(cleanDescription))
      return res.status(400).json({ success: false, message: profanityMessage() });

    // No duplicate post titles
    const titleExists = await Project.findOne({ title: { $regex: `^${escapeRegex(cleanTitle)}$`, $options: 'i' } });
    if (titleExists)
      return res.status(400).json({ success: false, message: 'A project with this title already exists. Please choose a unique title.' });

    // Idempotency: prevent duplicate submissions within 10 seconds
    const tenSecsAgo = new Date(Date.now() - 10000);
    const recentDuplicate = await Project.findOne({ authorId: user._id, title: cleanTitle, createdAt: { $gte: tenSecsAgo } });
    if (recentDuplicate) return res.status(429).json({ success: false, message: 'Duplicate submission detected. Your project was already posted.' });

    // 1 post per hour per user
    const oneHourAgo  = new Date(Date.now()-60*60*1000);
    const recentPost  = await Project.findOne({ authorId: user._id, createdAt: { $gte: oneHourAgo } });
    if (recentPost) {
      const minLeft = Math.ceil((new Date(recentPost.createdAt.getTime()+60*60*1000)-Date.now())/60000);
      return res.status(429).json({ success: false, message: `You can only post once per hour. Wait ${minLeft} more minute${minLeft!==1?'s':''}.` });
    }

    const processedFiles = [];
    for (const file of (req.files?.files||[])) {
      const {data,compressed} = await compressFile(file.buffer, file.mimetype);
      processedFiles.push({ name: safeFileName(file.originalname), data, mimetype: file.mimetype, size: file.size, compressed });
    }

    const screenshotUrls = [], screenshots = [];
    for (const ss of (req.files?.screenshots||[])) {
      const url = await uploadToCloudinary(ss.buffer, ss.mimetype, 'alino/screenshots');
      if (url) screenshotUrls.push(url); else screenshots.push({ data: ss.buffer, mimetype: ss.mimetype });
    }

    const tagsArr = tags
      ? (Array.isArray(tags)?tags:tags.split(',').map(t=>t.trim()).filter(Boolean)).map(t=>sanitize(t,30)).slice(0,8)
      : [];

    const project = await Project.create({
      title: cleanTitle, description: cleanDescription,
      category: sanitize(category,50), tags: tagsArr,
      authorId: user._id, authorName: user.username,
      files: processedFiles, screenshots, screenshotUrls,
      githubUrl: safeUrl(githubUrl), demoUrl: safeUrl(demoUrl)
    });

    await User.findByIdAndUpdate(req.user.id, { $inc: { reputation: 10 } });
    broadcast({ type:'new_post', post:{ _id:project._id,title:project.title,category:project.category,authorName:user.username,createdAt:project.createdAt } });
    if (flaggedContent(cleanTitle+' '+cleanDescription)) await moderateContent(project._id, user._id, 'content-filter');

    res.status(201).json({ success: true, data: { id: project._id, title: project.title } });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.get('/api/projects/:id', async (req, res) => {
  try {
    const project = await Project.findById(req.params.id, {'files.data':0,'screenshots.data':0});
    if (!project) return res.status(404).json({ success: false, message: 'Project not found' });
    await Project.findByIdAndUpdate(req.params.id, { $inc: { views: 1 } });
    updateScoreAsync(req.params.id);
    const userId = getUserIdFromToken(req);
    const [counts,interactions,comments] = await Promise.all([
      getProjectCounts(project._id),
      getUserInteractions(project._id, userId),
      Comment.find({ projectId: project._id }).sort({ createdAt: -1 }).limit(50)
    ]);
    res.json({ success: true, data: { ...project.toObject(),...counts,...interactions,comments,fileCount:project.files?.length||0,fileNames:project.files?.map(f=>({name:f.name,size:f.size,mimetype:f.mimetype}))||[] }});
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.delete('/api/projects/:id', authMiddleware, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);
    if (!project) return res.status(404).json({ success: false, message: 'Project not found' });
    if (project.authorId.toString()!==req.user.id&&req.user.role!=='admin') return res.status(403).json({ success: false, message: 'Not authorized' });
    for (const url of (project.screenshotUrls||[])) await deleteFromCloudinary(url);
    await Promise.all([Project.findByIdAndDelete(req.params.id),Interaction.deleteMany({projectId:req.params.id}),Comment.deleteMany({projectId:req.params.id}),Report.deleteMany({projectId:req.params.id})]);
    res.json({ success: true, message: 'Project deleted' });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.get('/api/projects/:id/screenshot/:index', async (req, res) => {
  try {
    const project = await Project.findById(req.params.id,'screenshots screenshotUrls');
    const idx = parseInt(req.params.index,10);
    if (isNaN(idx)) return res.status(400).send('Invalid index');
    if (project?.screenshotUrls?.[idx]) return res.redirect(project.screenshotUrls[idx]);
    if (!project?.screenshots?.[idx]) return res.status(404).send('Not found');
    const ss = project.screenshots[idx];
    if (!IMAGE_MIMETYPES.has(ss.mimetype)) return res.status(400).send('Invalid type');
    res.set('Content-Type',ss.mimetype); res.set('Cache-Control','public, max-age=86400'); res.set('X-Content-Type-Options','nosniff');
    res.send(ss.data);
  } catch { res.status(500).send('Error'); }
});

app.get('/api/projects/:id/download/:fileIndex', authMiddlewareOrQuery, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);
    const idx = parseInt(req.params.fileIndex,10);
    if (isNaN(idx)||!project?.files?.[idx]) return res.status(404).json({ success: false, message: 'File not found' });
    const file = project.files[idx];
    const data = await decompressFile(file.data, file.compressed);
    const already = await Interaction.findOne({ projectId: project._id, userId: req.user.id, type: 'download' });
    if (!already) {
      await Interaction.create({ projectId: project._id, userId: req.user.id, type: 'download' });
      updateScoreAsync(project._id);
      await User.findByIdAndUpdate(project.authorId, { $inc: { reputation: 2 } });
      if (project.authorId.toString()!==req.user.id) {
        await Notification.create({ userId: project.authorId, message: `${req.user.username} downloaded your project "${project.title}"`, projectId: project._id });
        broadcast({ type:'notification', userId: project.authorId.toString() });
      }
    }
    res.set('Content-Disposition',`attachment; filename="${safeFileName(file.name)}"`);
    res.set('Content-Type',ALLOWED_MIMETYPES.has(file.mimetype)?file.mimetype:'application/octet-stream');
    res.set('X-Content-Type-Options','nosniff');
    res.send(data);
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.get('/api/projects/:id/pdf', async (req, res) => {
  try {
    const project = await Project.findById(req.params.id,{'files.data':0,'screenshots.data':0});
    if (!project) return res.status(404).send('Not found');
    const [likes,downloads,comments] = await Promise.all([Interaction.countDocuments({projectId:project._id,type:'like'}),Interaction.countDocuments({projectId:project._id,type:'download'}),Comment.find({projectId:project._id}).sort({createdAt:-1}).limit(30)]);
    const esc=s=>String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    const timeAgo=date=>{const s=Math.floor((Date.now()-new Date(date))/1000);if(s<60)return s+'s ago';if(s<3600)return Math.floor(s/60)+'m ago';if(s<86400)return Math.floor(s/3600)+'h ago';return Math.floor(s/86400)+'d ago';};
    const host=`${req.protocol}://${req.get('host')}`;
    const allSS=project.screenshotUrls?.length?project.screenshotUrls:(project.screenshots||[]).map((_,i)=>`${host}/api/projects/${project._id}/screenshot/${i}`);
    const ssHtml=allSS.length?`<div class="screenshots">${allSS.map(u=>`<img src="${esc(u)}" alt="">`).join('')}</div>`:'';
    const tagsHtml=(project.tags||[]).map(t=>`<span class="tag">${esc(t)}</span>`).join('');
    const filesHtml=(project.files||[]).map(f=>`<li>${esc(f.name)} <span class="muted">(${f.size?Math.round(f.size/1024)+'KB':'?'})</span></li>`).join('');
    const commentsHtml=comments.map(c=>`<div class="comment"><div class="comment-meta">u/${esc(c.username)} · ${timeAgo(c.createdAt)}</div><div class="comment-text">${esc(c.content)}</div></div>`).join('');
    const html=`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>${esc(project.title)} — Alino</title><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Segoe UI',sans-serif;color:#1c1c1c;padding:40px;max-width:780px;margin:0 auto;font-size:14px;line-height:1.6}.header{display:flex;align-items:center;gap:12px;padding-bottom:20px;border-bottom:3px solid #FF4500;margin-bottom:24px}.logo{font-size:1.4rem;font-weight:900;color:#FF4500}.badge{padding:3px 10px;border-radius:12px;font-size:.75rem;font-weight:700;background:#fff3f0;color:#FF4500;border:1px solid #ffd0c0}h1{font-size:1.8rem;font-weight:800;margin-bottom:10px}.meta{font-size:.82rem;color:#878a8c;margin-bottom:14px}.stats{display:flex;gap:20px;margin-bottom:16px}.stat{font-size:.85rem;font-weight:700}.stat span{color:#878a8c;font-weight:400}.screenshots{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}.screenshots img{max-width:340px;max-height:240px;border-radius:4px;border:1px solid #edeff1;object-fit:cover}.tags{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:16px}.tag{padding:2px 10px;border-radius:10px;font-size:.75rem;font-weight:700;background:#edeff1;color:#0079d3}.section-title{font-size:.78rem;font-weight:700;text-transform:uppercase;color:#878a8c;margin:20px 0 10px;padding-top:16px;border-top:1px solid #edeff1}.description{font-size:.9rem;line-height:1.7;white-space:pre-wrap}ul.files{list-style:none}.muted{color:#878a8c;font-size:.8rem}.comment{padding:10px 0;border-bottom:1px solid #edeff1}.comment-meta{font-size:.75rem;color:#878a8c;margin-bottom:4px}.comment-text{font-size:.875rem}.footer{margin-top:40px;padding-top:16px;border-top:1px solid #edeff1;font-size:.78rem;color:#878a8c;text-align:center}@media print{.header{-webkit-print-color-adjust:exact;print-color-adjust:exact}}</style></head><body>
<div class="header"><div class="logo">alino</div><span class="badge">${esc(project.category)}</span></div>
<h1>${esc(project.title)}</h1><div class="meta">by u/${esc(project.authorName)} · ${timeAgo(project.createdAt)} · ${project.views||0} views</div>
<div class="stats"><div class="stat">${likes} <span>upvotes</span></div><div class="stat">${downloads} <span>downloads</span></div><div class="stat">${comments.length} <span>comments</span></div></div>
${tagsHtml?`<div class="tags">${tagsHtml}</div>`:''}${ssHtml}
${project.githubUrl||project.demoUrl?`<div style="margin-bottom:16px">${project.githubUrl?`<a href="${esc(project.githubUrl)}" style="color:#0079d3;font-size:.85rem;margin-right:16px">GitHub</a>`:''} ${project.demoUrl?`<a href="${esc(project.demoUrl)}" style="color:#0079d3;font-size:.85rem">Live Demo</a>`:''}</div>`:''}
<div class="section-title">Description</div><div class="description">${esc(project.description)}</div>
${filesHtml?`<div class="section-title">Files</div><ul class="files">${filesHtml}</ul>`:''}
${comments.length?`<div class="section-title">Comments (${comments.length})</div>${commentsHtml}`:''}
<div class="footer">Exported from Alino · ${new Date().toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'})}</div>
<script>window.onload=()=>window.print();</script></body></html>`;
    res.set('Content-Type','text/html'); res.send(html);
  } catch (err) { res.status(500).send('Error: '+err.message); }
});

app.post('/api/projects/:id/like', authMiddleware, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id,'authorId title');
    if (!project) return res.status(404).json({ success: false, message: 'Project not found' });
    const existing = await Interaction.findOne({ projectId: project._id, userId: req.user.id, type: 'like' });
    if (existing) { await existing.deleteOne(); await User.findByIdAndUpdate(project.authorId,{$inc:{reputation:-1}}); return res.json({success:true,data:{liked:false}}); }
    await Interaction.create({ projectId: project._id, userId: req.user.id, type: 'like' });
    updateScoreAsync(project._id);
    await User.findByIdAndUpdate(project.authorId,{$inc:{reputation:1}});
    if (project.authorId.toString()!==req.user.id) {
      const recentNotif = await Notification.findOne({ userId: project.authorId, projectId: project._id, message: { $regex: 'upvoted' }, createdAt: { $gte: new Date(Date.now()-60*60*1000) } });
      if (!recentNotif) await Notification.create({userId:project.authorId,message:`${req.user.username} upvoted your project "${project.title}"`,projectId:project._id});
      broadcast({type:'notification',userId:project.authorId.toString()}); }
    res.json({ success: true, data: { liked: true } });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.post('/api/projects/:id/bookmark', authMiddleware, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id,'authorId title');
    if (!project) return res.status(404).json({ success: false, message: 'Project not found' });
    const existing = await Interaction.findOne({ projectId: project._id, userId: req.user.id, type: 'bookmark' });
    if (existing) { await existing.deleteOne(); return res.json({success:true,data:{bookmarked:false}}); }
    await Interaction.create({ projectId: project._id, userId: req.user.id, type: 'bookmark' });
    res.json({ success: true, data: { bookmarked: true } });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.post('/api/projects/:id/comments', authMiddleware, writeLimiter, async (req, res) => {
  try {
    const cleanContent = sanitize(req.body.content, 1000);
    if (!cleanContent) return res.status(400).json({ success: false, message: 'Comment cannot be empty' });
    if (containsProfanity(cleanContent)) return res.status(400).json({ success: false, message: profanityMessage() });
    const project = await Project.findById(req.params.id,'authorId title');
    if (!project) return res.status(404).json({ success: false, message: 'Project not found' });
    const comment = await Comment.create({ projectId: req.params.id, userId: req.user.id, username: req.user.username, content: cleanContent });
    if (project.authorId.toString()!==req.user.id) {
      await Notification.create({userId:project.authorId,message:`${req.user.username} commented on "${project.title}"`,projectId:project._id});
      const nCount = await Notification.countDocuments({userId:project.authorId});
      if (nCount > 100) { const oldest = await Notification.find({userId:project.authorId}).sort({createdAt:1}).limit(nCount-100).select('_id'); await Notification.deleteMany({_id:{$in:oldest.map(n=>n._id)}}); }
      broadcast({type:'notification',userId:project.authorId.toString()}); }
    if (flaggedContent(cleanContent)) await moderateContent(project._id, req.user.id, 'comment-filter');
    res.status(201).json({ success: true, data: comment });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.delete('/api/projects/:id/comments/:commentId', authMiddleware, async (req, res) => {
  try {
    const comment = await Comment.findById(req.params.commentId);
    if (!comment) return res.status(404).json({ success: false, message: 'Comment not found' });
    if (comment.userId.toString()!==req.user.id&&req.user.role!=='admin') return res.status(403).json({ success: false, message: 'Not authorized' });
    await comment.deleteOne();
    res.json({ success: true, message: 'Comment deleted' });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.post('/api/projects/:id/report', authMiddleware, async (req, res) => {
  try {
    if (!req.body.reason?.trim()) return res.status(400).json({ success: false, message: 'Reason required' });
    const already = await Report.findOne({ projectId: req.params.id, reporterId: req.user.id });
    if (already) return res.status(400).json({ success: false, message: 'Already reported' });
    await Report.create({ projectId: req.params.id, reporterId: req.user.id, reason: sanitize(req.body.reason,500) });
    await Project.findByIdAndUpdate(req.params.id, { reported: true });
    res.json({ success: true, message: 'Project reported. Our team will review it.' });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

// ═══════════════════════════════════════════════════════════
//  USER ROUTES
//  NOTE: /api/users/profile MUST be defined before /api/users/:id
//  so Express doesn't treat the string "profile" as a MongoDB ObjectId
// ═══════════════════════════════════════════════════════════
app.put('/api/users/profile', authMiddleware, upload.single('avatar'), async (req, res) => {
  try {
    const update = {};
    if (req.body.bio      !== undefined) update.bio      = sanitize(req.body.bio,500);
    if (req.body.fullName !== undefined) update.fullName  = sanitize(req.body.fullName,100);
    if (req.body.college  !== undefined) update.college   = sanitize(req.body.college,150);
    if (req.body.state    !== undefined && NE_STATES.includes(req.body.state)) update.state = req.body.state;
    if (req.body.username?.trim()) {
      const cu = req.body.username.trim();
      if (!/^[a-zA-Z0-9_]+$/.test(cu)) return res.status(400).json({ success: false, message: 'Invalid username format' });
      const taken = await User.findOne({ username: cu, _id: { $ne: req.user.id } });
      if (taken) return res.status(400).json({ success: false, message: 'Username already taken' });
      update.username = cu;
    }
    if (req.file) {
      if (!IMAGE_MIMETYPES.has(req.file.mimetype)) return res.status(400).json({ success: false, message: 'Avatar must be an image' });
      const avatarUrl = await uploadToCloudinary(req.file.buffer, req.file.mimetype, 'alino/avatars');
      if (avatarUrl) { const cu = await User.findById(req.user.id,'avatarUrl'); if (cu?.avatarUrl) await deleteFromCloudinary(cu.avatarUrl); update.avatarUrl = avatarUrl; }
      else { update.avatar = req.file.buffer; update.avatarType = req.file.mimetype; }
    }
    const user = await User.findByIdAndUpdate(req.user.id, update, { new: true }).select('-password -avatar -loginHistory');
    res.json({ success: true, data: user });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});


// GET user by id — defined AFTER /api/users/profile so "profile" is never treated as ObjectId
app.get('/api/users/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password -avatar -loginHistory');
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const projects = await Project.find({authorId:req.params.id},{'files.data':0,'screenshots.data':0}).sort({createdAt:-1}).limit(20);
    res.json({ success: true, data: { user, projects } });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.get('/api/users/:id/avatar', async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('avatar avatarType avatarUrl');
    if (!user) return res.status(404).send('No avatar');
    if (user.avatarUrl) return res.redirect(user.avatarUrl);
    if (!user.avatar) return res.status(404).send('No avatar');
    const safeType = IMAGE_MIMETYPES.has(user.avatarType)?user.avatarType:'image/png';
    res.set('Content-Type',safeType); res.set('Cache-Control','public, max-age=3600'); res.set('X-Content-Type-Options','nosniff');
    res.send(user.avatar);
  } catch { res.status(500).send('Error'); }
});

app.get('/api/users/:id/bookmarks', authMiddleware, async (req, res) => {
  try {
    if (req.params.id!==req.user.id&&req.user.role!=='admin') return res.status(403).json({ success: false, message: 'Not authorized' });
    const bms = await Interaction.find({ userId: req.params.id, type: 'bookmark' });
    const projects = await Project.find({ _id: { $in: bms.map(b=>b.projectId) } },{'files.data':0,'screenshots.data':0});
    res.json({ success: true, data: projects });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.get('/api/leaderboard', async (req, res) => {
  try {
    const users = await User.find({banned:false}).select('-password -avatar -loginHistory').sort({reputation:-1}).limit(10);
    res.json({ success: true, data: users });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

// ═══════════════════════════════════════════════════════════
//  NOTIFICATIONS
// ═══════════════════════════════════════════════════════════
app.get('/api/notifications', authMiddleware, async (req, res) => {
  try {
    const notifs = await Notification.find({userId:req.user.id}).sort({createdAt:-1}).limit(30);
    res.json({ success: true, data: { notifications: notifs, unread: notifs.filter(n=>!n.read).length } });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.put('/api/notifications/read', authMiddleware, async (req, res) => {
  try { await Notification.updateMany({userId:req.user.id,read:false},{read:true}); res.json({ success: true }); }
  catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

// ═══════════════════════════════════════════════════════════
//  ADMIN ROUTES
// ═══════════════════════════════════════════════════════════
app.get('/api/admin/stats', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const [users,projects,reports] = await Promise.all([User.countDocuments(),Project.countDocuments(),Report.countDocuments({resolved:false})]);
    res.json({ success: true, data: { users, projects, pendingReports: reports } });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page)||1);
    const limit = Math.min(50, parseInt(req.query.limit)||20);
    const raw   = (req.query.search||'').trim().slice(0,100);
    const query = raw ? { $or:[{username:new RegExp(escapeRegex(raw),'i')},{email:new RegExp(escapeRegex(raw),'i')}] } : {};
    const [users,total] = await Promise.all([
      User.find(query).select('-password -avatar -loginHistory').sort({createdAt:-1}).skip((page-1)*limit).limit(limit),
      User.countDocuments(query)
    ]);
    // Attach registrationIp for admin view
    const withIp = await Promise.all(users.map(async u => {
      const full = await User.findById(u._id).select('registrationIp');
      return { ...u.toObject(), registrationIp: full?.registrationIp||'N/A' };
    }));
    res.json({ success: true, data: { users: withIp, total } });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

// NEW: Full login history for a user
app.get('/api/admin/users/:id/login-history', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('username email loginHistory registrationIp loginAttempts lockUntil');
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const history = [...(user.loginHistory||[])].reverse().slice(0,50);
    res.json({ success: true, data: {
      username: user.username, email: user.email,
      registrationIp: user.registrationIp||'N/A',
      loginAttempts: user.loginAttempts||0,
      isLocked: isAccountLocked(user),
      lockUntil: user.lockUntil,
      loginHistory: history
    }});
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.put('/api/admin/users/:id/ban', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    if (req.params.id===req.user.id) return res.status(400).json({ success: false, message: 'Cannot ban yourself' });
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    user.banned = !user.banned;
    await user.save();
    res.json({ success: true, data: { banned: user.banned, username: user.username } });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.put('/api/admin/users/:id/role', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { role } = req.body;
    if (!['student','admin'].includes(role)) return res.status(400).json({ success: false, message: 'Invalid role' });
    await User.findByIdAndUpdate(req.params.id, { role });
    res.json({ success: true, message: 'Role updated' });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

// Unlock a locked account
app.post('/api/admin/users/:id/unlock', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.params.id, { loginAttempts: 0, lockUntil: null });
    res.json({ success: true, message: 'Account unlocked.' });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.get('/api/admin/projects', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page)||1);
    const limit = Math.min(50, parseInt(req.query.limit)||20);
    const query = req.query.reported==='true' ? { reported: true } : {};
    const [projects,total] = await Promise.all([
      Project.find(query,{'files.data':0,'screenshots.data':0}).sort({createdAt:-1}).skip((page-1)*limit).limit(limit),
      Project.countDocuments(query)
    ]);
    res.json({ success: true, data: { projects, total } });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.get('/api/admin/reports', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const reports = await Report.find({resolved:false}).sort({createdAt:-1}).limit(50);
    res.json({ success: true, data: reports });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.put('/api/admin/reports/:id/resolve', authMiddleware, adminMiddleware, async (req, res) => {
  try { await Report.findByIdAndUpdate(req.params.id, { resolved: true }); res.json({ success: true }); }
  catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

// NEW: Bulk delete all flagged/reported projects
app.delete('/api/admin/projects/bulk-flagged', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const flagged = await Project.find({ reported: true }, '_id screenshotUrls');
    if (!flagged.length) return res.json({ success: true, message: 'No flagged projects to delete.', deleted: 0 });
    for (const p of flagged) for (const url of (p.screenshotUrls||[])) await deleteFromCloudinary(url);
    const ids = flagged.map(p=>p._id);
    await Promise.all([
      Project.deleteMany({_id:{$in:ids}}),
      Interaction.deleteMany({projectId:{$in:ids}}),
      Comment.deleteMany({projectId:{$in:ids}}),
      Report.deleteMany({projectId:{$in:ids}})
    ]);
    res.json({ success: true, message: `Deleted ${flagged.length} flagged project${flagged.length!==1?'s':''}.`, deleted: flagged.length });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

// CATCH-ALL

// ─── FOLLOW ROUTES ────────────────────────────────────────────────────────────
app.post('/api/users/:id/follow', authMiddleware, writeLimiter, async (req, res) => {
  try {
    const followingId = req.params.id;
    const followerId = req.user.id;
    if (followerId === followingId) return res.status(400).json({ success: false, message: "Can't follow yourself" });
    const existing = await Follow.findOne({ followerId, followingId });
    if (existing) {
      await Follow.deleteOne({ followerId, followingId });
      return res.json({ success: true, following: false });
    }
    await Follow.create({ followerId, followingId });
    const recentFollowNotif = await Notification.findOne({ userId: followingId, fromUserId: followerId, type: 'follow', createdAt: { $gte: new Date(Date.now()-24*60*60*1000) } });
    if (!recentFollowNotif) {
      await Notification.create({ userId: followingId, type: 'follow', fromUserId: followerId, fromUsername: req.user.username, message: `u/${req.user.username} started following you` });
      sendPushToUser(followingId, '👤 New Follower!', `u/${req.user.username} started following you`, '/');
    }
    res.json({ success: true, following: true });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/users/:id/follow-status', authMiddleware, async (req, res) => {
  try {
    const following = await Follow.findOne({ followerId: req.user.id, followingId: req.params.id });
    const followerCount = await Follow.countDocuments({ followingId: req.params.id });
    const followingCount = await Follow.countDocuments({ followerId: req.params.id });
    res.json({ success: true, data: { following: !!following, followerCount, followingCount } });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/users/:id/followers', async (req, res) => {
  try {
    const follows = await Follow.find({ followingId: req.params.id }).sort({ createdAt: -1 }).limit(50);
    const ids = follows.map(f => f.followerId);
    const users = await User.find({ _id: { $in: ids } }).select('username avatarUrl reputation college state');
    res.json({ success: true, data: users });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/users/:id/following', async (req, res) => {
  try {
    const follows = await Follow.find({ followerId: req.params.id }).sort({ createdAt: -1 }).limit(50);
    const ids = follows.map(f => f.followingId);
    const users = await User.find({ _id: { $in: ids } }).select('username avatarUrl reputation college state');
    res.json({ success: true, data: users });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ─── SEARCH BY COLLEGE/STATE ──────────────────────────────────────────────────
app.get('/api/search/users', async (req, res) => {
  try {
    const { q, college, state, page = 1 } = req.query;
    const limit = 20;
    const query = { banned: false };
    if (q) {
      const safe = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      query.$or = [{ username: new RegExp(safe, 'i') }, { fullName: new RegExp(safe, 'i') }];
    }
    if (college) {
      const safe = college.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      query.college = new RegExp(safe, 'i');
    }
    if (state) query.state = state;
    const users = await User.find(query).select('username fullName avatarUrl college state reputation bio createdAt').sort({ reputation: -1 }).skip((page-1)*limit).limit(limit);
    const total = await User.countDocuments(query);
    res.json({ success: true, data: users, total, pages: Math.ceil(total/limit) });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ─── BADGES ───────────────────────────────────────────────────────────────────
function getBadges(user, postCount) {
  const badges = [];
  if (postCount >= 1) badges.push({ id: 'first_post', label: 'First Post', emoji: '🚀', desc: 'Shared your first project' });
  if (postCount >= 5) badges.push({ id: 'builder', label: 'Builder', emoji: '🔨', desc: 'Shared 5+ projects' });
  if (postCount >= 10) badges.push({ id: 'prolific', label: 'Prolific', emoji: '⚡', desc: 'Shared 10+ projects' });
  if (user.reputation >= 10) badges.push({ id: 'rising', label: 'Rising Star', emoji: '⭐', desc: 'Earned 10+ reputation' });
  if (user.reputation >= 100) badges.push({ id: 'popular', label: 'Popular', emoji: '🔥', desc: 'Earned 100+ reputation' });
  if (user.reputation >= 500) badges.push({ id: 'legend', label: 'Legend', emoji: '👑', desc: 'Earned 500+ reputation' });
  if (user.role === 'admin') badges.push({ id: 'admin', label: 'Admin', emoji: '🛡️', desc: 'Platform administrator' });
  const daysSinceJoin = (Date.now() - new Date(user.createdAt).getTime()) / (1000*60*60*24);
  if (daysSinceJoin >= 30) badges.push({ id: 'veteran', label: 'Veteran', emoji: '🎖️', desc: 'Member for 30+ days' });
  return badges;
}

app.get('/api/users/:id/badges', async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('username reputation role createdAt');
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const postCount = await Project.countDocuments({ authorId: user._id });
    const badges = getBadges(user, postCount);
    res.json({ success: true, data: badges });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ─── PROJECT OF THE WEEK ──────────────────────────────────────────────────────
app.get('/api/featured', async (req, res) => {
  try {
    const featured = await FeaturedPost.findOne().sort({ createdAt: -1 }).populate('projectId');
    if (!featured || !featured.projectId) return res.json({ success: true, data: null });
    res.json({ success: true, data: featured.projectId });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/admin/featured/:projectId', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const proj = await Project.findById(req.params.projectId, 'title');
    if (!proj) return res.status(404).json({ success: false, message: 'Project not found' });
    await FeaturedPost.deleteMany({});
    await FeaturedPost.create({ projectId: req.params.projectId, setBy: req.user.id });
    res.json({ success: true, message: `"${proj.title}" is now Project of the Week!` });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ─── PUSH NOTIFICATION HELPER ────────────────────────────────────────────────
async function sendPushToUser(userId, title, body, url = '/') {
  if (!VAPID_PUBLIC || !VAPID_PRIVATE) return;
  try {
    const subs = await PushSub.find({ userId });
    const payload = JSON.stringify({ title, body, url, icon: '/icon-192.png', badge: '/icon-192.png' });
    for (const sub of subs) {
      try {
        await webpush.sendNotification({ endpoint: sub.endpoint, keys: { p256dh: sub.keys.p256dh, auth: sub.keys.auth } }, payload);
      } catch(e) {
        if (e.statusCode === 410 || e.statusCode === 404) await PushSub.deleteOne({ _id: sub._id });
      }
    }
  } catch(e) { console.error('Push error:', e.message); }
}

// ─── PUSH ROUTES ──────────────────────────────────────────────────────────────
app.get('/api/push/vapid-key', (req, res) => {
  res.json({ success: true, data: { publicKey: VAPID_PUBLIC || null } });
});

app.post('/api/push/subscribe', authMiddleware, async (req, res) => {
  try {
    const { endpoint, keys } = req.body;
    if (!endpoint || !keys) return res.status(400).json({ success: false, message: 'Invalid subscription' });
    await PushSub.findOneAndUpdate(
      { userId: req.user.id, endpoint },
      { userId: req.user.id, endpoint, keys },
      { upsert: true, new: true }
    );
    res.json({ success: true, message: 'Subscribed to push notifications!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/push/unsubscribe', authMiddleware, async (req, res) => {
  try {
    await PushSub.deleteMany({ userId: req.user.id });
    res.json({ success: true, message: 'Unsubscribed from push notifications' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// AUTO-CREATE ADMIN
async function ensureAdmin() {
  try {
    const ADMIN_EMAIL    = process.env.ADMIN_EMAIL    || 'admin@alino.in';
    const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Alino@Admin2026!';
    const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
    const existing = await User.findOne({ email: ADMIN_EMAIL });
    if (existing) {
      if (existing.role !== 'admin') {
        await User.findByIdAndUpdate(existing._id, { role: 'admin' });
        console.log('✅  Admin role granted to existing account:', ADMIN_EMAIL);
      } else {
        console.log('✅  Admin account OK:', ADMIN_EMAIL);
      }
    } else {
      const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);
      await User.create({
        username: ADMIN_USERNAME, email: ADMIN_EMAIL, password: hash,
        role: 'admin', emailVerified: true, fullName: 'Alino Admin',
        age: 25, college: '', state: 'Tamil Nadu', registrationIp: 'system'
      });
      console.log('✅  Admin account created:', ADMIN_EMAIL);
    }
  } catch(e) { console.error('Admin setup error:', e.message); }
}


// AUTO-CREATE DEMO CONTENT
async function ensureDemoContent() {
  try {
    const postCount = await Project.countDocuments();
    if (postCount >= 5) { console.log("Demo content OK (" + postCount + " posts exist)"); return; }
    const DEMO_USERS = [
      { username:'arjun_dev07',  email:'arjun@alino.in',  fullName:'Arjun Sharma',  age:21, college:'IIT Guwahati',  state:'Assam',   bio:'Full-stack dev. React + Node.js enthusiast.' },
      { username:'priya_coder',  email:'priya@alino.in',  fullName:'Priya Das',     age:20, college:'NIT Silchar',   state:'Assam',   bio:'Flutter & Dart dev | Building apps for students.' },
      { username:'rahul_ml',     email:'rahul@alino.in',  fullName:'Rahul Borah',   age:23, college:'IIT Guwahati',  state:'Assam',   bio:'ML engineer | Agriculture tech.' },
      { username:'sonia_builds', email:'sonia@alino.in',  fullName:'Sonia Devi',    age:22, college:'NIT Silchar',   state:'Manipur', bio:'Building LocalMart | Tech for social good.' },
      { username:'iot_nikhil',   email:'iot@alino.in',    fullName:'Nikhil Tiwari', age:21, college:'GIMT Guwahati', state:'Assam',   bio:'IoT + Hardware hacker.' },
    ];
    const userMap = {};
    for (const u of DEMO_USERS) {
      const hash = await bcrypt.hash('Demo@1234', 10);
      const created = await User.findOneAndUpdate({ email: u.email }, { ...u, password: hash, emailVerified: true, role: 'student', registrationIp: 'demo' }, { upsert: true, new: true });
      userMap[u.username] = created._id;
    }
    const DEMO_POSTS = [
      { username:'rahul_ml', category:'AI/ML', title:'AgroSense — AI Crop Disease Detector for Indian Farmers', tags:['Python','TensorFlow','CNN','Agriculture'], thumbnailUrl:'https://images.unsplash.com/photo-1574943320219-553eb213f72d?w=600&q=80', description:'AgroSense identifies crop diseases from smartphone photos.\n\n• CNN model trained on 45,000+ images\n• 91.3% accuracy\n• Works offline on-device\n• Deployed in 3 villages, 200+ farmers', githubUrl:'https://github.com/example/agrosense', demoUrl:'', score:237, views:1843 },
      { username:'sonia_builds', category:'Web', title:'LocalMart — E-commerce Platform for Local Artisans', tags:['Next.js','TypeScript','Stripe','Manipur'], thumbnailUrl:'https://images.unsplash.com/photo-1607082348824-0a96f2a4b9da?w=600&q=80', description:'Connects Manipuri artisans directly to buyers.\n\n• 23 artisans, 400+ products\n• Stripe + UPI payments\n• WhatsApp order notifications', githubUrl:'https://github.com/example/localmart', demoUrl:'', score:312, views:2241 },
      { username:'priya_coder', category:'Mobile', title:'Smart City Bus Tracker — Real-time GPS for City Routes', tags:['Flutter','Firebase','GPS','Guwahati'], thumbnailUrl:'https://images.unsplash.com/photo-1544620347-c4fd4a3d5957?w=600&q=80', description:'Flutter app for Guwahati city buses covering 12 major routes.\n\n• Real-time GPS on map\n• Push notifications when bus is 5 mins away\n• Offline map support', githubUrl:'https://github.com/example/bus', demoUrl:'', score:98, views:654 },
      { username:'iot_nikhil', category:'Hardware', title:'SmartBin — IoT Waste Sorter — Won IIT Guwahati TechFest', tags:['Raspberry Pi','Arduino','ML','IoT'], thumbnailUrl:'https://images.unsplash.com/photo-1532996122724-e3c354a0b15b?w=600&q=80', description:'Automatically sorts waste using computer vision.\n\n• 88.4% accuracy\n• Servo-controlled compartments\n• 1st Place IIT Guwahati Tech Fest 2024', githubUrl:'https://github.com/example/smartbin', demoUrl:'', score:278, views:1987 },
      { username:'arjun_dev07', category:'Web', title:'India Weather App — Real-time Forecast for All States', tags:['React','OpenWeatherAPI','PWA'], thumbnailUrl:'https://images.unsplash.com/photo-1504608524841-42584120d693?w=600&q=80', description:'PWA delivering real-time weather for all Indian states.\n\n• Live weather + 7-day forecasts\n• Monsoon season alerts\n• Full offline support', githubUrl:'https://github.com/example/weather', demoUrl:'', score:142, views:891 },
    ];
    for (const p of DEMO_POSTS) {
      const authorId = userMap[p.username];
      if (!authorId) continue;
      await Project.findOneAndUpdate({ title: p.title }, { ...p, authorId, authorName: p.username, createdAt: new Date(Date.now() - Math.random()*7*24*3600000) }, { upsert: true, new: true });
    }
    console.log('Demo content created — 5 posts added!');
  } catch(e) { console.error('Demo content error:', e.message); }
}
// START
app.listen(PORT, async () => {
  console.log(`Alino v5 running on port ${PORT} [${process.env.NODE_ENV||'development'}]`);
  await ensureAdmin();
  await ensureDemoContent();
});
process.on('SIGTERM', async () => { await mongoose.connection.close(); process.exit(0); });
process.on('SIGINT',  async () => { await mongoose.connection.close(); process.exit(0); });

// This line intentionally left blank

