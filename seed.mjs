/**
 * ALINO v5 — Seed Script
 * Run once after first deploy to populate DB with demo data + admin account.
 *
 * Usage:
 *   MONGODB_URI=your_uri node seed.mjs
 *
 * Or with .env file: node seed.mjs
 */

import 'dotenv/config';
import mongoose from 'mongoose';
import bcrypt   from 'bcryptjs';

const MONGODB_URI    = process.env.MONGODB_URI;
const ADMIN_EMAIL    = process.env.ADMIN_EMAIL    || 'admin@alino.in';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Alino@Admin2024!';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';

if (!MONGODB_URI) {
  console.error('❌  MONGODB_URI not set in .env');
  process.exit(1);
}

// ── Schemas — must exactly match server.mjs ──────────────────────────────────
const NE_STATES = [
  'Assam','Arunachal Pradesh','Manipur','Meghalaya',
  'Mizoram','Nagaland','Sikkim','Tripura','Other'
];

const UserSchema = new mongoose.Schema({
  username:       { type: String, unique: true, required: true },
  email:          { type: String, unique: true, required: true, lowercase: true },
  password:       { type: String, required: true },
  fullName:       { type: String, default: '' },
  age:            { type: Number, default: null },
  college:        { type: String, default: '' },
  state:          { type: String, default: '' },
  bio:            { type: String, default: '' },
  role:           { type: String, enum: ['student','admin'], default: 'student' },
  reputation:     { type: Number, default: 0 },
  banned:         { type: Boolean, default: false },
  emailVerified:  { type: Boolean, default: true },   // seed users are pre-verified
  loginAttempts:  { type: Number, default: 0 },
  lockUntil:      { type: Date, default: null },
  registrationIp: { type: String, default: 'seed' },
  loginHistory:   { type: Array, default: [] },
  createdAt:      { type: Date, default: Date.now }
});

const ProjectSchema = new mongoose.Schema({
  title:          String,
  description:    String,
  category:       String,
  tags:           [String],
  authorId:       mongoose.Schema.Types.ObjectId,
  authorName:     String,
  files:          { type: Array, default: [] },
  screenshots:    { type: Array, default: [] },
  screenshotUrls: { type: Array, default: [] },
  githubUrl:      { type: String, default: '' },
  demoUrl:        { type: String, default: '' },
  thumbnailUrl:   { type: String, default: '' },
  views:          { type: Number, default: 0 },
  score:          { type: Number, default: 0 },
  reported:       { type: Boolean, default: false },
  createdAt:      { type: Date, default: Date.now }
});

const CommentSchema = new mongoose.Schema({
  projectId: mongoose.Schema.Types.ObjectId,
  userId:    mongoose.Schema.Types.ObjectId,
  username:  String,
  content:   String,
  createdAt: { type: Date, default: Date.now }
});

const InteractionSchema = new mongoose.Schema({
  projectId: mongoose.Schema.Types.ObjectId,
  userId:    mongoose.Schema.Types.ObjectId,
  type:      { type: String, enum: ['like','bookmark','download','view'] },
  createdAt: { type: Date, default: Date.now }
});

const User        = mongoose.model('User',        UserSchema);
const Project     = mongoose.model('Project',     ProjectSchema);
const Comment     = mongoose.model('Comment',     CommentSchema);
const Interaction = mongoose.model('Interaction', InteractionSchema);

// ── Seed users ────────────────────────────────────────────────────────────────
const SEED_USERS = [
  { username:'arjun_dev07',    email:'arjun@alino.in',    password:'Demo@1234', fullName:'Arjun Sharma',    age:21, college:'IIT Guwahati',     state:'Assam',             bio:'Full-stack dev from Guwahati. React + Node.js enthusiast.',            reputation:342 },
  { username:'priya_coder',    email:'priya@alino.in',    password:'Demo@1234', fullName:'Priya Das',       age:20, college:'NIT Silchar',       state:'Assam',             bio:'Flutter & Dart dev | Building apps for NE India problems.',            reputation:287 },
  { username:'rahul_ml',       email:'rahul@alino.in',    password:'Demo@1234', fullName:'Rahul Borah',     age:23, college:'IIT Guwahati',     state:'Assam',             bio:"ML engineer | Agriculture tech | IIT Guwahati '24",                   reputation:589 },
  { username:'game_dev_nk',    email:'nikhil_g@alino.in', password:'Demo@1234', fullName:'Nikhil Gogoi',    age:19, college:'GIMT Guwahati',    state:'Assam',             bio:'Game dev hobbyist. CSE student. Godot evangelist.',                    reputation:214 },
  { username:'sonia_builds',   email:'sonia@alino.in',    password:'Demo@1234', fullName:'Sonia Devi',      age:22, college:'NIT Silchar',       state:'Manipur',           bio:'Building LocalMart | NIT Silchar | Tech for social good',              reputation:712 },
  { username:'iot_nikhil',     email:'iot@alino.in',      password:'Demo@1234', fullName:'Nikhil Tiwari',   age:21, college:'GIMT Guwahati',    state:'Assam',             bio:'IoT + Hardware hacker | Raspberry Pi addict | GIMT Guwahati',         reputation:456 },
  { username:'divya_rn',       email:'divya@alino.in',    password:'Demo@1234', fullName:'Divya Roy',       age:20, college:'Gauhati University',state:'Assam',             bio:'React Native dev | Mental health tech | Guwahati University',         reputation:521 },
  { username:'foodie_dev',     email:'foodie@alino.in',   password:'Demo@1234', fullName:'Amit Khongban',   age:24, college:'NEHU Shillong',     state:'Meghalaya',         bio:'Vue.js + Nuxt | Building FoodMap NE | Shillong',                      reputation:198 },
  { username:'history_buff_ak',email:'quiz@alino.in',     password:'Demo@1234', fullName:'Ankit Kumar',     age:25, college:'Cotton University', state:'Assam',             bio:'Ex-UPSC aspirant turned dev. Free education forever.',                 reputation:376 },
  { username:'alino_creator',  email:'creator@alino.in',  password:'Demo@1234', fullName:'Dev Creator',     age:22, college:'Cotton University', state:'Assam',             bio:'Creator of Alino. Cotton University CS grad.',                        reputation:934 },
];

// ── Seed posts ────────────────────────────────────────────────────────────────
const SEED_POSTS = [
  {
    username:'arjun_dev07',
    title:'NE India Weather App — Real-time forecast for all 8 sister states',
    category:'Web', tags:['React','OpenWeatherAPI','NE India','PWA'],
    description:'A full-stack progressive web app delivering real-time weather data specifically tailored for all 8 Northeast Indian states.\n\nFeatures:\n• Live weather data via OpenWeatherMap API with 7-day forecasts\n• Hourly breakdown with rain probability charts\n• Monsoon season alerts\n• Service Worker for full offline support\n• Responsive for all screen sizes\n\nTech Stack: React 18, Vite, Tailwind CSS, OpenWeatherMap API',
    githubUrl:'https://github.com/example/ne-weather', demoUrl:'https://ne-weather.vercel.app',
    score:142, views:891, createdAt:new Date(Date.now()-3*3600000)
  },
  {
    username:'priya_coder',
    title:'Guwahati Smart Bus Tracker — Real-time GPS for city routes',
    category:'Mobile', tags:['Flutter','Firebase','GPS','Guwahati'],
    description:'After getting frustrated waiting for ASTC buses with no ETA, I built this Flutter app for Guwahati city buses covering 12 major routes.\n\nKey Features:\n• Real-time GPS location of buses on map\n• Push notifications when your bus is 5 minutes away\n• Offline map support (works on 2G!)\n\nTech Stack: Flutter 3.16, Firebase Realtime Database, Google Maps SDK',
    githubUrl:'https://github.com/example/guwahati-bus', demoUrl:'',
    score:98, views:654, createdAt:new Date(Date.now()-6*3600000)
  },
  {
    username:'rahul_ml',
    title:'AgroSense — AI crop disease detector for Assam farmers',
    category:'AI/ML', tags:['Python','TensorFlow','CNN','Agriculture','Assam'],
    description:"AgroSense is an AI-powered mobile tool that identifies crop diseases from smartphone photos for rice, tea, and betel nut crops.\n\n• CNN model trained on 45,000+ disease images\n• 91.3% accuracy on test set\n• Quantized TFLite model runs on-device\n• Assamese language UI\n• Treatment recommendations\n\nDeployed in 3 villages, 200+ farmers.",
    githubUrl:'https://github.com/example/agrosense', demoUrl:'https://agrosense-demo.streamlit.app',
    score:237, views:1843, createdAt:new Date(Date.now()-12*3600000)
  },
  {
    username:'game_dev_nk',
    title:'RetroRun — 2D platformer built in 72h for NE Dev Jam 2024',
    category:'Game', tags:['Godot 4','GDScript','Game Jam','Pixel Art'],
    description:'Made this game solo in 72 hours for NE India Dev Jam 2024! Theme was "Roots".\n\n• 8 hand-crafted levels\n• Pixel art inspired by Kaziranga landscapes\n• Original chiptune soundtrack (BeepBox)\n• Speedrun timer + leaderboard\n\nPlaced 3rd in the jam! Full source available.',
    githubUrl:'https://github.com/example/retrorun', demoUrl:'https://example.itch.io/retrorun',
    score:189, views:1102, createdAt:new Date(Date.now()-24*3600000)
  },
  {
    username:'sonia_builds',
    title:'LocalMart — E-commerce connecting Manipuri artisans to buyers',
    category:'Web', tags:['Next.js','TypeScript','Stripe','Manipur'],
    description:'LocalMart connects Manipuri artisans directly to buyers, cutting out middlemen.\n\n• 23 artisans, 400+ products\n• Monthly transactions growing fast\n• Stripe + UPI payments\n• WhatsApp order notifications\n• Meitei language UI\n\nMy grandmother is one of the artisans.',
    githubUrl:'https://github.com/example/localmart', demoUrl:'https://localmart-manipur.vercel.app',
    score:312, views:2241, createdAt:new Date(Date.now()-2*24*3600000)
  },
  {
    username:'iot_nikhil',
    title:'SmartBin — IoT waste sorter using ML — Won IIT Guwahati TechFest',
    category:'Hardware', tags:['Raspberry Pi','Arduino','ML','IoT','Smart City'],
    description:'SmartBin automatically sorts waste using computer vision at low cost per unit.\n\n• MobileNetV2 inference in 180ms\n• 88.4% classification accuracy\n• Servo-controlled compartments\n• MQTT dashboard\n• STL files for 3D printed chassis included\n\n1st Place, IIT Guwahati Tech Fest 2024',
    githubUrl:'https://github.com/example/smartbin', demoUrl:'',
    score:278, views:1987, createdAt:new Date(Date.now()-3*24*3600000)
  },
  {
    username:'divya_rn',
    title:'MindPal — AI journaling app for student mental health',
    category:'Mobile', tags:['React Native','Expo','SQLite','Mental Health'],
    description:'Private AI-powered journaling for college students.\n\n• Mood tracking + AI prompts\n• 100% offline — local SQLite only\n• Crisis resources always one tap away\n• 120 beta users, 87% report feeling less alone\n\nFree and open source forever.',
    githubUrl:'https://github.com/example/mindpal', demoUrl:'',
    score:356, views:2678, createdAt:new Date(Date.now()-5*24*3600000)
  },
  {
    username:'foodie_dev',
    title:'FoodMap NE — Discover authentic local restaurants and street food',
    category:'Web', tags:['Vue.js','Nuxt','Supabase','Food','NE India'],
    description:'The local food discovery app for NE India — 1,200+ curated restaurants and food stalls.\n\n• All 8 NE states covered\n• Local cuisine filters (Assamese, Meitei, Khasi, Naga...)\n• Student-budget filter\n• Offline maps\n• 3,400 monthly active users — zero marketing!',
    githubUrl:'https://github.com/example/foodmap-ne', demoUrl:'https://foodmapne.com',
    score:203, views:1567, createdAt:new Date(Date.now()-8*24*3600000)
  },
  {
    username:'history_buff_ak',
    title:'QuizNE — Free UPSC quiz platform for Northeast India topics',
    category:'Web', tags:['React','Node.js','PostgreSQL','UPSC','Education'],
    description:'2,400+ MCQs on NE India history, culture, geography for UPSC/State PCS.\n\n• 8,200 registered users\n• 180,000+ quiz attempts\n• 4.8/5 rating\n• 94 UPSC prelims qualifiers credit QuizNE\n\nFree forever.',
    githubUrl:'https://github.com/example/quizne', demoUrl:'https://quizne.in',
    score:167, views:1234, createdAt:new Date(Date.now()-10*24*3600000)
  },
  {
    username:'alino_creator',
    title:'Alino — Student project sharing platform built from scratch',
    category:'Web', tags:['Node.js','MongoDB','Express','Vanilla JS','Community'],
    description:'Alino is a community platform for student builders across NE India.\n\nTech Stack:\n• Backend: Node.js + Express + MongoDB\n• Auth: JWT + bcryptjs\n• Frontend: Vanilla JS (no framework!)\n• Real-time: Server-Sent Events\n• Deployment: Railway + MongoDB Atlas\n\nFeatures: Auth, posts, voting, comments, notifications, admin panel, PDF export, real-time SSE, load more feed, Cloudinary images.',
    githubUrl:'https://github.com/example/alino', demoUrl:'',
    score:421, views:3102, createdAt:new Date(Date.now()-14*24*3600000)
  }
];

// ── Seed comments per post ────────────────────────────────────────────────────
const SEED_COMMENTS = [
  { postTitle:'AgroSense — AI crop disease detector for Assam farmers',         commenter:'sonia_builds',    content:'This is incredible! My uncle is a tea farmer in Jorhat — would this work for tea blight diseases?' },
  { postTitle:'AgroSense — AI crop disease detector for Assam farmers',         commenter:'arjun_dev07',     content:'91.3% accuracy is really impressive for an on-device model. Did you use transfer learning from a pre-trained ResNet?' },
  { postTitle:'LocalMart — E-commerce connecting Manipuri artisans to buyers',  commenter:'divya_rn',        content:'Love this project. The social impact angle is real — would love to collaborate on adding a user review system.' },
  { postTitle:'MindPal — AI journaling app for student mental health',          commenter:'priya_coder',     content:'87% reporting feeling less alone is an incredible stat. This needs to be in every college hostel.' },
  { postTitle:'MindPal — AI journaling app for student mental health',          commenter:'rahul_ml',        content:'Brilliant that it is 100% offline. Privacy is so important for mental health apps. Great design decision.' },
  { postTitle:'SmartBin — IoT waste sorter using ML — Won IIT Guwahati TechFest', commenter:'iot_nikhil',   content:'Happy to share the full CAD files for the chassis if anyone wants to build one. DM me!' },
  { postTitle:'Guwahati Smart Bus Tracker — Real-time GPS for city routes',     commenter:'game_dev_nk',     content:'FINALLY someone built this. The ASTC bus situation is a nightmare. Is there an Android APK available?' },
  { postTitle:'QuizNE — Free UPSC quiz platform for Northeast India topics',    commenter:'alino_creator',   content:'8,200 users with zero marketing is proof that building for a specific community works. Respect.' },
];

// ── Run ───────────────────────────────────────────────────────────────────────
async function seed() {
  console.log('🌱  Connecting to MongoDB...');
  await mongoose.connect(MONGODB_URI);
  console.log('✅  MongoDB connected');

  const existingUsers = await User.countDocuments();
  if (existingUsers > 1) {
    console.log(`ℹ️   Database already has ${existingUsers} users — skipping seed.`);
    console.log('    To reseed: drop the users and projects collections first.');
    await mongoose.disconnect();
    return;
  }

  // ── Admin ──
  const adminHash = await bcrypt.hash(ADMIN_PASSWORD, 12);
  await User.findOneAndUpdate(
    { email: ADMIN_EMAIL },
    {
      username: ADMIN_USERNAME, email: ADMIN_EMAIL, password: adminHash,
      role: 'admin', reputation: 0, emailVerified: true,
      fullName: 'Alino Admin', age: 25, college: '', state: 'Assam',
      registrationIp: 'seed'
    },
    { upsert: true, new: true }
  );
  console.log(`✅  Admin: ${ADMIN_EMAIL} / ${ADMIN_PASSWORD}`);

  // ── Seed users ──
  const userMap = {};
  for (const u of SEED_USERS) {
    const hash = await bcrypt.hash(u.password, 10);
    const created = await User.findOneAndUpdate(
      { username: u.username },
      { ...u, password: hash, emailVerified: true, registrationIp: 'seed' },
      { upsert: true, new: true }
    );
    userMap[u.username] = created._id;
    console.log(`  👤  u/${u.username}  (${u.fullName}, ${u.age}, ${u.state})`);
  }

  // ── Seed posts ──
  const postMap = {};
  for (const p of SEED_POSTS) {
    const authorId = userMap[p.username];
    if (!authorId) { console.warn(`  ⚠   No user for ${p.username}`); continue; }
    const created = await Project.findOneAndUpdate(
      { title: p.title },
      { ...p, authorId, authorName: p.username },
      { upsert: true, new: true }
    );
    postMap[p.title] = { _id: created._id, authorId };
    console.log(`  📝  "${p.title.slice(0, 55)}..."`);
  }

  // ── Seed comments ──
  for (const c of SEED_COMMENTS) {
    const post = postMap[c.postTitle];
    const authorId = userMap[c.commenter];
    if (!post || !authorId) continue;
    await Comment.findOneAndUpdate(
      { projectId: post._id, userId: authorId },
      { projectId: post._id, userId: authorId, username: c.commenter, content: c.content },
      { upsert: true, new: true }
    );
  }
  console.log(`  💬  Seed comments added`);

  // ── Seed likes ──
  const likeMatrix = [
    ['sonia_builds',   'AgroSense — AI crop disease detector for Assam farmers'],
    ['arjun_dev07',    'AgroSense — AI crop disease detector for Assam farmers'],
    ['divya_rn',       'LocalMart — E-commerce connecting Manipuri artisans to buyers'],
    ['priya_coder',    'MindPal — AI journaling app for student mental health'],
    ['rahul_ml',       'MindPal — AI journaling app for student mental health'],
    ['game_dev_nk',    'Guwahati Smart Bus Tracker — Real-time GPS for city routes'],
    ['alino_creator',  'QuizNE — Free UPSC quiz platform for Northeast India topics'],
    ['foodie_dev',     'SmartBin — IoT waste sorter using ML — Won IIT Guwahati TechFest'],
    ['history_buff_ak','Alino — Student project sharing platform built from scratch'],
    ['iot_nikhil',     'Alino — Student project sharing platform built from scratch'],
  ];
  for (const [username, title] of likeMatrix) {
    const userId    = userMap[username];
    const post      = postMap[title];
    if (!userId || !post) continue;
    await Interaction.findOneAndUpdate(
      { projectId: post._id, userId, type: 'like' },
      { projectId: post._id, userId, type: 'like' },
      { upsert: true, new: true }
    );
  }
  console.log(`  ❤️   Seed likes added`);

  console.log('\n✅  Seed complete!');
  console.log('─────────────────────────────────────────────');
  console.log('ADMIN LOGIN:');
  console.log(`  Email:    ${ADMIN_EMAIL}`);
  console.log(`  Password: ${ADMIN_PASSWORD}`);
  console.log('\nDEMO USER LOGIN — all share password: Demo@1234');
  console.log('  arjun_dev07 / priya_coder / rahul_ml / sonia_builds');
  console.log('  iot_nikhil / divya_rn / foodie_dev / history_buff_ak');
  console.log('─────────────────────────────────────────────');

  await mongoose.disconnect();
  console.log('🔌  Disconnected.');
}

seed().catch(err => { console.error('Seed failed:', err.message); process.exit(1); });
