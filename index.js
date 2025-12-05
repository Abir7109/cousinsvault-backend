'use strict';

// Simple Express + MongoDB backend to replace the existing PHP APIs.
// It preserves the same URL paths and JSON response shapes used by the frontend
// (auth, events, gallery, uploads, profiles), but runs as a Node service on Render
// with MongoDB instead of MySQL.

const path = require('path');
const fs = require('fs');
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
require('dotenv').config();

// =====================================================
// CLOUDINARY CONFIG
// =====================================================

const CLOUDINARY_CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME;
const CLOUDINARY_API_KEY = process.env.CLOUDINARY_API_KEY;
const CLOUDINARY_API_SECRET = process.env.CLOUDINARY_API_SECRET;

const cloudinaryEnabled = !!(
  CLOUDINARY_CLOUD_NAME &&
  CLOUDINARY_API_KEY &&
  CLOUDINARY_API_SECRET
);

if (cloudinaryEnabled) {
  cloudinary.config({
    cloud_name: CLOUDINARY_CLOUD_NAME,
    api_key: CLOUDINARY_API_KEY,
    api_secret: CLOUDINARY_API_SECRET,
  });
  console.log('Cloudinary enabled for uploads');
} else {
  console.log('Cloudinary disabled; using local disk storage for uploads');
}

// =====================================================
// BASIC CONFIG
// =====================================================

const app = express();
const PORT = process.env.PORT || 4000;

// CORS – allow any origin (frontend talks to this backend from Vercel)
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan('tiny'));

// Static serving for uploaded files (legacy/local uploads)
const UPLOAD_ROOT = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_ROOT)) {
  fs.mkdirSync(UPLOAD_ROOT, { recursive: true });
}
app.use('/uploads', express.static(UPLOAD_ROOT));

// Cloudinary configuration (for images/videos stored off-disk)
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// =====================================================
// ENV / SECURITY HELPERS
// =====================================================

const JWT_SECRET = process.env.JWT_SECRET || 'change-this-in-production';
const PASSWORD_SALT = process.env.PASSWORD_SALT || 'extra-salt-change-me';

function sanitizeInput(value) {
  if (typeof value !== 'string') return value;
  return value.trim();
}

function sendSuccess(res, data = {}, message = 'Success') {
  res.json({ success: true, message, data });
}

function sendError(res, message, statusCode = 400) {
  res.status(statusCode).json({ success: false, error: message });
}

function generateJWTToken(user) {
  const payload = {
    user_id: user._id.toString(),
    email: user.email,
  };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: process.env.SESSION_TIMEOUT || '24h' });
}

async function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers['authorization'] || '';
    const match = authHeader.match(/Bearer\s+(\S+)/i);
    if (!match) return sendError(res, 'Access token required', 401);

    const token = match[1];
    let payload;
    try {
      payload = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      return sendError(res, 'Invalid or expired token', 401);
    }

    const user = await User.findOne({ _id: payload.user_id, isActive: true }).lean();
    if (!user) return sendError(res, 'User not found or inactive', 401);

    req.user = {
      ...user,
      user_id: user._id.toString(),
    };
    next();
  } catch (err) {
    console.error('requireAuth error', err);
    return sendError(res, 'Authentication failed', 500);
  }
}

// tryRequireAuth – like the PHP helper, but non-fatal
async function tryRequireAuth(req) {
  const authHeader = req.headers['authorization'] || '';
  const match = authHeader.match(/Bearer\s+(\S+)/i);
  if (!match) return null;
  const token = match[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await User.findOne({ _id: payload.user_id, isActive: true }).lean();
    if (!user) return null;
    return { ...user, user_id: user._id.toString() };
  } catch {
    return null;
  }
}

// =====================================================
// MONGODB SETUP & SCHEMAS
// =====================================================

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/cousins_vault';

mongoose
  .connect(MONGODB_URI, { autoIndex: true })
  .then(() => {
    console.log('✅ Connected to MongoDB');
  })
  .catch((err) => {
    console.error('❌ MongoDB connection error:', err.message);
  });

const opts = { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } };

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    username: { type: String, required: true, unique: true },
    password_hash: { type: String, required: true },
    role: { type: String, enum: ['viewer', 'contributor', 'admin'], default: 'contributor' },
    avatar_url: String,
    bio: String,
    phone: String,
    birthday: String,
    email_verified: { type: Boolean, default: true },
    isActive: { type: Boolean, default: true },
    last_login: Date,
  },
  opts,
);

const User = mongoose.model('User', userSchema);

const galleryItemSchema = new mongoose.Schema(
  {
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    title: { type: String, required: true },
    description: String,
    type: { type: String, enum: ['image', 'video'], default: 'image' },
    file_path: { type: String, required: true },
    file_size: Number,
    mime_type: String,
    width: Number,
    height: Number,
    duration: Number,
    thumbnail_path: String,
    tags: [String],
    is_private: { type: Boolean, default: false },
    view_count: { type: Number, default: 0 },
    like_count: { type: Number, default: 0 },
  },
  opts,
);

const GalleryItem = mongoose.model('GalleryItem', galleryItemSchema);

const galleryLikeSchema = new mongoose.Schema(
  {
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    gallery_item_id: { type: mongoose.Schema.Types.ObjectId, ref: 'GalleryItem', required: true },
  },
  opts,
);

galleryLikeSchema.index({ user_id: 1, gallery_item_id: 1 }, { unique: true });

const GalleryLike = mongoose.model('GalleryLike', galleryLikeSchema);

const eventSchema = new mongoose.Schema(
  {
    creator_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    creator_name: String, // for simple events
    title: { type: String, required: true },
    description: String,
    event_type: { type: String, default: 'other' },
    event_date: { type: String, required: true }, // keep as string to mirror PHP
    event_time: String,
    end_date: String,
    end_time: String,
    location: String,
    max_attendees: Number,
    is_private: { type: Boolean, default: false },
    requires_rsvp: { type: Boolean, default: true },
    rsvp_deadline: String,
    color: { type: String, default: '#8FAE7B' },
    is_cancelled: { type: Boolean, default: false },
  },
  opts,
);

const Event = mongoose.model('Event', eventSchema);

const eventRsvpSchema = new mongoose.Schema(
  {
    event_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Event', required: true },
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    rsvp_status: { type: String, enum: ['yes', 'no', 'maybe'], required: true },
    guest_count: { type: Number, default: 1 },
    dietary_requirements: String,
    notes: String,
  },
  opts,
);

eventRsvpSchema.index({ event_id: 1, user_id: 1 }, { unique: false });

const EventRsvp = mongoose.model('EventRsvp', eventRsvpSchema);

const cousinProfileSchema = new mongoose.Schema(
  {
    cousin: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    birthdate: String,
    relation: String,
    location: String,
    passion: String,
    bio: String,
    phone: String,
    email: String,
    theme: { type: String, default: 'sage' },
    profile_photo_path: String,
  },
  opts,
);

const CousinProfile = mongoose.model('CousinProfile', cousinProfileSchema);

const cousinUploadSchema = new mongoose.Schema(
  {
    cousin: { type: String, required: true },
    title: String,
    description: String,
    file_path: { type: String, required: true },
    file_type: String,
  },
  { timestamps: { createdAt: 'upload_date', updatedAt: 'updated_at' } },
);

const CousinUpload = mongoose.model('CousinUpload', cousinUploadSchema);

// Vault stats per cousin, for index page counters
const vaultStatsSchema = new mongoose.Schema(
  {
    cousin: { type: String, unique: true },
    total_photos: { type: Number, default: 0 },
    total_videos: { type: Number, default: 0 },
    total_likes: { type: Number, default: 0 },
  },
  opts,
);

const VaultStats = mongoose.model('VaultStats', vaultStatsSchema);

async function bumpVaultStats(cousin, { photos = 0, videos = 0, likes = 0 } = {}) {
  await VaultStats.findOneAndUpdate(
    { cousin },
    {
      $setOnInsert: { cousin },
      $inc: {
        total_photos: photos,
        total_videos: videos,
        total_likes: likes,
      },
    },
    { upsert: true },
  );
}

// =====================================================
// AUTH ENDPOINT – /api/v1/auth (login/signup/profile/check)
// =====================================================

app.all('/api/v1/auth', async (req, res) => {
  const method = req.method;
  const action = (req.query.action || (method === 'GET' ? 'profile' : 'login')).toString();

  try {
    if (method === 'POST') {
      if (action === 'login') return authLogin(req, res);
      if (action === 'signup') return authSignup(req, res);
      if (action === 'logout') return authLogout(req, res);
      if (action === 'refresh') return authRefresh(req, res);
      return sendError(res, 'Invalid action', 400);
    }

    if (method === 'GET') {
      if (action === 'profile') return authProfile(req, res);
      if (action === 'check') return authCheck(req, res);
      return sendError(res, 'Invalid action', 400);
    }

    if (method === 'PUT') {
      if (action === 'update-profile') return authUpdateProfile(req, res);
      if (action === 'change-password') return authChangePassword(req, res);
      return sendError(res, 'Invalid action', 400);
    }

    return sendError(res, 'Method not allowed', 405);
  } catch (err) {
    console.error('Auth API error', err);
    return sendError(res, 'Internal server error', 500);
  }
});

async function authLogin(req, res) {
  const { email, password } = req.body || {};
  if (!email || !password) return sendError(res, 'Email and password are required', 400);

  const identifier = sanitizeInput(email);

  const user = await User.findOne({
    $or: [{ email: identifier }, { username: identifier }],
    isActive: true,
  });

  if (!user) return sendError(res, 'Invalid credentials', 401);

  const ok = await bcrypt.compare(password + PASSWORD_SALT, user.password_hash);
  if (!ok) return sendError(res, 'Invalid credentials', 401);

  user.last_login = new Date();
  await user.save();

  const token = generateJWTToken(user);

  const safeUser = {
    id: user._id.toString(),
    name: user.name,
    email: user.email,
    username: user.username,
    role: user.role,
    avatar_url: user.avatar_url,
    bio: user.bio,
    created_at: user.created_at,
  };

  sendSuccess(
    res,
    {
      user: safeUser,
      token,
      expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    },
    'Login successful',
  );
}

async function authSignup(req, res) {
  const { name, email, password, username, role } = req.body || {};
  if (!name || !email || !password || !username) {
    return sendError(res, 'name, email, username and password are required', 400);
  }

  const cleanEmail = sanitizeInput(email).toLowerCase();
  const cleanUsername = sanitizeInput(username).toLowerCase();

  const existing = await User.findOne({ $or: [{ email: cleanEmail }, { username: cleanUsername }] });
  if (existing) return sendError(res, 'User with this email or username already exists', 409);

  if (password.length < 6) return sendError(res, 'Password must be at least 6 characters long', 400);

  const allowedRoles = ['viewer', 'contributor', 'admin'];
  const finalRole = allowedRoles.includes(role) ? role : 'contributor';

  const passwordHash = await bcrypt.hash(password + PASSWORD_SALT, 10);

  const user = await User.create({
    name: sanitizeInput(name),
    email: cleanEmail,
    username: cleanUsername,
    password_hash: passwordHash,
    role: finalRole,
    bio: req.body.bio || null,
    email_verified: true,
  });

  const token = generateJWTToken(user);

  const safeUser = {
    id: user._id.toString(),
    name: user.name,
    email: user.email,
    username: user.username,
    role: user.role,
    bio: user.bio,
    created_at: user.created_at,
  };

  sendSuccess(
    res,
    {
      user: safeUser,
      token,
      expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    },
    'Registration successful',
  );
}

async function authProfile(req, res) {
  const user = await tryRequireAuth(req);
  if (!user) return sendError(res, 'Unauthorized', 401);

  // For now, just return raw user document without MySQL joins
  const profile = {
    ...user,
    password_hash: undefined,
  };

  sendSuccess(res, { profile });
}

async function authCheck(req, res) {
  const user = await tryRequireAuth(req);
  if (!user) return sendSuccess(res, { authenticated: false });
  return sendSuccess(res, { authenticated: true, user_id: user.user_id });
}

async function authUpdateProfile(req, res) {
  await requireAuth(req, res, async () => {
    const allowed = ['name', 'bio', 'phone', 'birthday'];
    const updates = {};
    for (const field of allowed) {
      if (field in req.body) updates[field] = sanitizeInput(req.body[field]);
    }
    if (!Object.keys(updates).length) return sendError(res, 'No valid fields to update', 400);

    await User.updateOne({ _id: req.user.user_id }, { $set: updates });
    return sendSuccess(res, {}, 'Profile updated successfully');
  });
}

async function authChangePassword(req, res) {
  await requireAuth(req, res, async () => {
    const { current_password, new_password } = req.body || {};
    if (!current_password || !new_password) {
      return sendError(res, 'Current password and new password are required', 400);
    }
    if (new_password.length < 6) {
      return sendError(res, 'New password must be at least 6 characters long', 400);
    }

    const user = await User.findById(req.user.user_id);
    const ok = await bcrypt.compare(current_password + PASSWORD_SALT, user.password_hash);
    if (!ok) return sendError(res, 'Current password is incorrect', 400);

    user.password_hash = await bcrypt.hash(new_password + PASSWORD_SALT, 10);
    await user.save();
    return sendSuccess(res, {}, 'Password changed successfully');
  });
}

async function authLogout(req, res) {
  // JWT is stateless – front-end just drops token. This keeps behaviour similar to PHP logout.
  await requireAuth(req, res, async () => {
    return sendSuccess(res, {}, 'Logout successful');
  });
}

async function authRefresh(req, res) {
  await requireAuth(req, res, async () => {
    const user = await User.findById(req.user.user_id);
    if (!user) return sendError(res, 'User not found', 404);
    const token = generateJWTToken(user);
    const safeUser = {
      id: user._id.toString(),
      name: user.name,
      email: user.email,
      username: user.username,
      role: user.role,
      avatar_url: user.avatar_url,
      bio: user.bio,
    };
    return sendSuccess(
      res,
      {
        user: safeUser,
        token,
        expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      },
      'Token refreshed',
    );
  });
}

// =====================================================
// GALLERY API – /api/v1/gallery (list/item/upload/like/stats)
// =====================================================

// Multer storage for gallery uploads (use memory so we can send buffers to Cloudinary)
const galleryStorage = multer.memoryStorage();

const uploadGallery = multer({ storage: galleryStorage, limits: { fileSize: 20 * 1024 * 1024 } });

app.all('/api/v1/gallery', async (req, res) => {
  const method = req.method;
  const action = (req.query.action || (method === 'GET' ? 'list' : 'upload')).toString();

  try {
    if (method === 'GET') {
      if (action === 'list') return galleryList(req, res);
      if (action === 'item') return galleryItem(req, res);
      if (action === 'user') return galleryUser(req, res);
      if (action === 'stats') return galleryStats(req, res);
      if (action === 'search') return gallerySearch(req, res);
      return sendError(res, 'Invalid action', 400);
    }

    if (method === 'POST') {
      if (action === 'upload') return uploadGallery.single('file')(req, res, () => galleryUpload(req, res));
      if (action === 'like') return galleryToggleLike(req, res);
      return sendError(res, 'Invalid action', 400);
    }

    if (method === 'PUT') {
      if (action === 'update') return galleryUpdate(req, res);
      return sendError(res, 'Invalid action', 400);
    }

    if (method === 'DELETE') {
      return galleryDelete(req, res);
    }

    return sendError(res, 'Method not allowed', 405);
  } catch (err) {
    console.error('Gallery API error', err);
    return sendError(res, 'Internal server error', 500);
  }
});

function buildFileUrls(baseUrl, file_path, thumbnail_path) {
  const normalize = (p) => {
    if (!p) return null;
    if (/^https?:\/\//i.test(p)) return p;
    return `${baseUrl}/${p.replace(/\\/g, '/')}`;
  };
  const file_url = normalize(file_path);
  const thumb_url = normalize(thumbnail_path) || file_url;
  return { file_url, thumbnail_url: thumb_url };
}

async function galleryList(req, res) {
  const limit = Math.min(50, Math.max(1, parseInt(req.query.limit || '20', 10)));
  const offset = Math.max(0, parseInt(req.query.offset || '0', 10));
  const type = (req.query.type || 'all').toString();
  const author = (req.query.author || 'all').toString();
  const orderBy = ['created_at', 'title', 'like_count', 'view_count'].includes(req.query.order)
    ? req.query.order
    : 'created_at';
  const orderDir = (req.query.dir || 'DESC').toString().toUpperCase() === 'ASC' ? 1 : -1;

  const query = { is_private: false };
  if (type !== 'all') query.type = type;
  if (author !== 'all') {
    const user = await User.findOne({ username: sanitizeInput(author) });
    if (user) query.user_id = user._id;
    else return sendSuccess(res, { items: [], pagination: { total: 0, limit, offset, pages: 0 } });
  }

  const total = await GalleryItem.countDocuments(query);
  const items = await GalleryItem.find(query)
    .sort({ [orderBy === 'created_at' ? 'created_at' : orderBy]: orderDir })
    .skip(offset)
    .limit(limit)
    .lean();

  const currentUser = await tryRequireAuth(req);
  const userId = currentUser ? currentUser.user_id : null;

  let likedMap = {};
  if (userId) {
    const likes = await GalleryLike.find({ user_id: userId, gallery_item_id: { $in: items.map((i) => i._id) } }).lean();
    likedMap = likes.reduce((acc, l) => {
      acc[l.gallery_item_id.toString()] = true;
      return acc;
    }, {});
  }

  const baseUrl = process.env.SITE_URL || (req.protocol + '://' + req.get('host'));

  const enriched = await Promise.all(
    items.map(async (item) => {
      const authorUser = await User.findById(item.user_id).lean();
      const tags = Array.isArray(item.tags) ? item.tags : [];
      const { file_url, thumbnail_url } = buildFileUrls(baseUrl, item.file_path, item.thumbnail_path);
      return {
        ...item,
        id: item._id,
        tags,
        file_url,
        thumbnail_url,
        author_name: authorUser ? authorUser.name : null,
        author_username: authorUser ? authorUser.username : null,
        author_avatar: authorUser ? authorUser.avatar_url : null,
        user_liked: !!likedMap[item._id.toString()],
      };
    }),
  );

  sendSuccess(res, {
    items: enriched,
    pagination: {
      total,
      limit,
      offset,
      pages: Math.ceil(total / limit) || 1,
    },
  });
}

async function galleryItem(req, res) {
  const id = req.query.id;
  if (!id) return sendError(res, 'Item ID is required', 400);

  const item = await GalleryItem.findById(id).lean();
  if (!item) return sendError(res, 'Gallery item not found', 404);

  const currentUser = await tryRequireAuth(req);
  if (item.is_private && (!currentUser || currentUser.user_id !== item.user_id.toString())) {
    return sendError(res, 'Access denied', 403);
  }

  await GalleryItem.updateOne({ _id: item._id }, { $inc: { view_count: 1 } });

  const authorUser = await User.findById(item.user_id).lean();
  const baseUrl = process.env.SITE_URL || (req.protocol + '://' + req.get('host'));
  const { file_url, thumbnail_url } = buildFileUrls(baseUrl, item.file_path, item.thumbnail_path);

  let user_liked = false;
  if (currentUser) {
    const like = await GalleryLike.findOne({ user_id: currentUser.user_id, gallery_item_id: item._id });
    user_liked = !!like;
  }

  const tags = Array.isArray(item.tags) ? item.tags : [];

  sendSuccess(res, {
    item: {
      ...item,
      id: item._id,
      tags,
      file_url,
      thumbnail_url,
      author_name: authorUser ? authorUser.name : null,
      author_username: authorUser ? authorUser.username : null,
      author_avatar: authorUser ? authorUser.avatar_url : null,
      user_liked,
    },
  });
}

async function galleryUser(req, res) {
  const username = sanitizeInput(req.query.username || '');
  if (!username) return sendError(res, 'Username is required', 400);

  const user = await User.findOne({ username }).lean();
  if (!user) return sendError(res, 'User not found', 404);

  const currentUser = await tryRequireAuth(req);
  const query = { user_id: user._id };
  if (!currentUser || currentUser.user_id !== user._id.toString()) {
    query.is_private = false;
  }

  const items = await GalleryItem.find(query).sort({ created_at: -1 }).lean();
  const baseUrl = process.env.SITE_URL || (req.protocol + '://' + req.get('host'));

  const enriched = items.map((item) => {
    const tags = Array.isArray(item.tags) ? item.tags : [];
    const { file_url, thumbnail_url } = buildFileUrls(baseUrl, item.file_path, item.thumbnail_path);
    return { ...item, id: item._id, tags, file_url, thumbnail_url, author_name: user.name, author_username: user.username };
  });

  sendSuccess(res, { items: enriched });
}

async function galleryStats(req, res) {
  const agg = await GalleryItem.aggregate([
    { $match: { is_private: false } },
    {
      $group: {
        _id: null,
        total_items: { $sum: 1 },
        total_images: { $sum: { $cond: [{ $eq: ['$type', 'image'] }, 1, 0] } },
        total_videos: { $sum: { $cond: [{ $eq: ['$type', 'video'] }, 1, 0] } },
        total_views: { $sum: '$view_count' },
        total_likes: { $sum: '$like_count' },
      },
    },
  ]);

  const stats = agg[0] || {
    total_items: 0,
    total_images: 0,
    total_videos: 0,
    total_views: 0,
    total_likes: 0,
  };

  sendSuccess(res, { stats });
}

async function gallerySearch(req, res) {
  const q = sanitizeInput(req.query.q || '');
  if (q.length < 2) return sendError(res, 'Search query must be at least 2 characters', 400);

  const regex = new RegExp(q, 'i');
  const items = await GalleryItem.find({
    is_private: false,
    $or: [{ title: regex }, { description: regex }, { tags: regex }],
  })
    .limit(50)
    .lean();

  const baseUrl = process.env.SITE_URL || (req.protocol + '://' + req.get('host'));

  const enriched = items.map((item) => {
    const tags = Array.isArray(item.tags) ? item.tags : [];
    const { file_url, thumbnail_url } = buildFileUrls(baseUrl, item.file_path, item.thumbnail_path);
    return { ...item, id: item._id, tags, file_url, thumbnail_url };
  });

  sendSuccess(res, { items: enriched });
}

async function uploadToCloudinary(file) {
  const isVideo = file.mimetype.startsWith('video/');
  const folder = isVideo ? 'cousinsvault/videos' : 'cousinsvault/images';
  const resource_type = isVideo ? 'video' : 'image';

  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder, resource_type },
      (err, result) => {
        if (err) return reject(err);
        resolve(result);
      },
    );
    stream.end(file.buffer);
  });
}

async function galleryUpload(req, res) {
  await requireAuth(req, res, async () => {
    if (!['contributor', 'admin'].includes(req.user.role)) {
      return sendError(res, 'Insufficient permissions', 403);
    }

    const file = req.file;
    if (!file) return sendError(res, 'No file uploaded', 400);

    const title = sanitizeInput(req.body.title || '');
    if (!title) return sendError(res, 'Title is required', 400);

    const description = sanitizeInput(req.body.description || '');
    const tagsRaw = req.body.tags || '';
    let tags = [];
    if (Array.isArray(tagsRaw)) tags = tagsRaw.map(sanitizeInput);
    else if (typeof tagsRaw === 'string' && tagsRaw.trim()) tags = tagsRaw.split(',').map((t) => sanitizeInput(t));

    const isVideo = file.mimetype.startsWith('video/');

    let uploadResult;
    try {
      uploadResult = await uploadToCloudinary(file);
    } catch (err) {
      console.error('Cloudinary upload error', err);
      return sendError(res, 'Failed to upload media', 500);
    }

    const galleryItem = await GalleryItem.create({
      user_id: req.user.user_id,
      title,
      description,
      type: isVideo ? 'video' : 'image',
      file_path: uploadResult.secure_url, // store full Cloudinary URL
      file_size: uploadResult.bytes || file.size,
      mime_type: file.mimetype,
      width: uploadResult.width || null,
      height: uploadResult.height || null,
      duration: uploadResult.duration || null,
      thumbnail_path: uploadResult.secure_url,
      tags,
      is_private: !!req.body.is_private,
    });

    // Also record per-cousin upload and bump stats for the Vault view.
    // Prefer an explicit cousin from the request body (Vault modal),
    // but fall back to the authenticated username.
    let cousin = (req.body.cousin || req.user.username || '').toLowerCase();
    const allowedCousins = ['rubab', 'rahi', 'abir'];
    if (!allowedCousins.includes(cousin)) cousin = null;

    if (cousin) {
      try {
        await CousinUpload.create({
          cousin,
          title,
          description,
          file_path: galleryItem.file_path,
          file_type: galleryItem.mime_type,
        });
        await bumpVaultStats(cousin, {
          photos: isVideo ? 0 : 1,
          videos: isVideo ? 1 : 0,
          likes: 0,
        });
      } catch (err) {
        console.error('Failed to record CousinUpload / bump stats', err);
      }
    }

    const baseUrl = process.env.SITE_URL || (req.protocol + '://' + req.get('host'));
    const { file_url } = buildFileUrls(baseUrl, galleryItem.file_path, galleryItem.thumbnail_path);

    sendSuccess(res, {
      id: galleryItem._id,
      file_url,
      title: galleryItem.title,
    }, 'File uploaded successfully');
  });
}

async function galleryToggleLike(req, res) {
  await requireAuth(req, res, async () => {
    const { item_id } = req.body || {};
    if (!item_id) return sendError(res, 'Item ID is required', 400);

    const item = await GalleryItem.findById(item_id);
    if (!item) return sendError(res, 'Gallery item not found', 404);

    const existing = await GalleryLike.findOne({ user_id: req.user.user_id, gallery_item_id: item._id });

    let action;
    if (existing) {
      await existing.deleteOne();
      item.like_count = Math.max(0, (item.like_count || 0) - 1);
      action = 'unliked';
    } else {
      await GalleryLike.create({ user_id: req.user.user_id, gallery_item_id: item._id });
      item.like_count = (item.like_count || 0) + 1;
      action = 'liked';
    }
    await item.save();

    sendSuccess(res, { action, like_count: item.like_count }, 'Like toggled successfully');
  });
}

async function galleryUpdate(req, res) {
  await requireAuth(req, res, async () => {
    const { id } = req.body || {};
    if (!id) return sendError(res, 'Item ID is required', 400);

    const item = await GalleryItem.findById(id);
    if (!item) return sendError(res, 'Gallery item not found', 404);

    if (item.user_id.toString() !== req.user.user_id && req.user.role !== 'admin') {
      return sendError(res, 'Insufficient permissions', 403);
    }

    const updates = {};
    if ('title' in req.body) updates.title = sanitizeInput(req.body.title);
    if ('description' in req.body) updates.description = sanitizeInput(req.body.description);
    if ('is_private' in req.body) updates.is_private = !!req.body.is_private;
    if ('tags' in req.body) {
      const raw = req.body.tags;
      let t = [];
      if (Array.isArray(raw)) t = raw.map(sanitizeInput);
      else if (typeof raw === 'string') t = raw.split(',').map(sanitizeInput);
      updates.tags = t;
    }

    await GalleryItem.updateOne({ _id: id }, { $set: updates });
    sendSuccess(res, {}, 'Gallery item updated successfully');
  });
}

async function galleryDelete(req, res) {
  await requireAuth(req, res, async () => {
    const id = req.query.id;
    if (!id) return sendError(res, 'Item ID is required', 400);

    const item = await GalleryItem.findById(id);
    if (!item) return sendError(res, 'Gallery item not found', 404);

    if (item.user_id.toString() !== req.user.user_id && req.user.role !== 'admin') {
      return sendError(res, 'Insufficient permissions', 403);
    }

    // Delete file from disk if it exists
    const fullPath = path.join(process.cwd(), item.file_path);
    if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);

    await GalleryLike.deleteMany({ gallery_item_id: item._id });
    await item.deleteOne();

    sendSuccess(res, {}, 'Gallery item deleted successfully');
  });
}

// =====================================================
// EVENTS API – /api/v1/events + /api/v1/events_simple.php
// =====================================================

app.all('/api/v1/events', async (req, res) => {
  const method = req.method;
  const action = (req.query.action || 'list').toString();

  try {
    if (method === 'GET') {
      if (action === 'list') return eventsList(req, res);
      if (action === 'event') return eventsGet(req, res);
      if (action === 'calendar') return eventsCalendar(req, res);
      if (action === 'upcoming') return eventsUpcoming(req, res);
      if (action === 'user') return eventsUser(req, res);
      if (action === 'rsvps') return eventsRsvps(req, res);
      if (action === 'stats') return eventsStats(req, res);
      return sendError(res, 'Invalid action', 400);
    }

    if (method === 'POST') {
      if (action === 'create') return eventsCreate(req, res);
      if (action === 'rsvp') return eventsSubmitRsvp(req, res);
      return sendError(res, 'Invalid action', 400);
    }

    if (method === 'PUT') {
      if (action === 'update') return eventsUpdate(req, res);
      return sendError(res, 'Invalid action', 400);
    }

    if (method === 'DELETE') {
      return eventsDelete(req, res);
    }

    return sendError(res, 'Method not allowed', 405);
  } catch (err) {
    console.error('Events API error', err);
    return sendError(res, 'Internal server error', 500);
  }
});

// Lightweight endpoint compatible with events_simple.php
app.all('/api/v1/events_simple.php', async (req, res) => {
  const method = req.method;
  try {
    if (method === 'GET') {
      const events = await Event.find({}).sort({ event_date: 1, event_time: 1 }).lean();
      return res.json({ success: true, data: events });
    }
    if (method === 'POST') {
      const payload = req.body || {};
      const title = sanitizeInput(payload.title || '');
      const event_date = sanitizeInput(payload.event_date || '');
      const event_type = sanitizeInput(payload.event_type || 'other');
      if (!title || !event_date) {
        return res.status(400).json({ success: false, error: 'title and event_date are required' });
      }
      const event = await Event.create({
        creator_name: payload.creator_name || 'Anonymous',
        title,
        description: payload.description || null,
        event_type,
        event_date,
        event_time: payload.event_time || null,
        location: payload.location || null,
      });
      return res.json({ success: true, data: { id: event._id.toString() } });
    }
    res.status(405).json({ success: false, error: 'Method not allowed' });
  } catch (err) {
    console.error('events_simple error', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

async function eventsList(req, res) {
  const limit = Math.min(50, Math.max(1, parseInt(req.query.limit || '20', 10)));
  const offset = Math.max(0, parseInt(req.query.offset || '0', 10));
  const type = (req.query.type || 'all').toString();
  const month = req.query.month ? parseInt(req.query.month, 10) : null;
  const year = req.query.year ? parseInt(req.query.year, 10) : null;

  const query = { is_cancelled: false };
  if (type !== 'all') query.event_type = type;
  if (year) {
    query.event_date = new RegExp(`^${year}-${month ? String(month).padStart(2, '0') : ''}`.replace(/-$/, ''), '');
  }

  const total = await Event.countDocuments(query);
  const events = await Event.find(query)
    .sort({ event_date: 1, event_time: 1 })
    .skip(offset)
    .limit(limit)
    .lean();

  const enriched = events.map((e) => ({
    ...e,
    id: e._id,
    event_datetime: e.event_date + (e.event_time ? ` ${e.event_time}` : ''),
    end_datetime: e.end_date ? e.end_date + (e.end_time ? ` ${e.end_time}` : '') : null,
  }));

  sendSuccess(res, {
    events: enriched,
    pagination: { total, limit, offset, pages: Math.ceil(total / limit) || 1 },
  });
}

async function eventsGet(req, res) {
  const id = req.query.id;
  if (!id) return sendError(res, 'Event ID is required', 400);

  const event = await Event.findById(id).lean();
  if (!event) return sendError(res, 'Event not found', 404);

  const rsvps = await EventRsvp.find({ event_id: event._id }).lean();
  const user = await tryRequireAuth(req);
  let user_rsvp = null;
  if (user) {
    const ur = rsvps.find((r) => r.user_id && r.user_id.toString() === user.user_id);
    user_rsvp = ur ? ur.rsvp_status : null;
  }

  sendSuccess(res, {
    event: {
      ...event,
      id: event._id,
      event_datetime: event.event_date + (event.event_time ? ` ${event.event_time}` : ''),
      end_datetime: event.end_date ? event.end_date + (event.end_time ? ` ${event.end_time}` : '') : null,
      rsvps,
      user_rsvp,
    },
  });
}

async function eventsCalendar(req, res) {
  const month = parseInt(req.query.month || String(new Date().getMonth() + 1), 10);
  const year = parseInt(req.query.year || String(new Date().getFullYear()), 10);
  const prefix = `${year}-${String(month).padStart(2, '0')}`;

  const events = await Event.find({ is_cancelled: false, event_date: new RegExp(`^${prefix}`) })
    .sort({ event_date: 1, event_time: 1 })
    .lean();

  const calendar = {};
  events.forEach((e) => {
    if (!calendar[e.event_date]) calendar[e.event_date] = [];
    calendar[e.event_date].push({
      id: e._id,
      title: e.title,
      type: e.event_type,
      time: e.event_time,
      color: e.color,
      creator: e.creator_name || null,
    });
  });

  sendSuccess(res, { calendar });
}

async function eventsUpcoming(req, res) {
  const limit = Math.min(10, Math.max(1, parseInt(req.query.limit || '5', 10)));
  const today = new Date().toISOString().slice(0, 10);

  const events = await Event.find({ is_cancelled: false, event_date: { $gte: today } })
    .sort({ event_date: 1, event_time: 1 })
    .limit(limit)
    .lean();

  const enriched = events.map((e) => ({
    ...e,
    id: e._id,
    event_datetime: e.event_date + (e.event_time ? ` ${e.event_time}` : ''),
  }));

  sendSuccess(res, { events: enriched });
}

async function eventsUser(req, res) {
  await requireAuth(req, res, async () => {
    const type = (req.query.type || 'created').toString();
    let events;
    if (type === 'created') {
      events = await Event.find({ creator_id: req.user.user_id }).sort({ event_date: -1 }).lean();
    } else {
      const rsvps = await EventRsvp.find({ user_id: req.user.user_id }).lean();
      const ids = rsvps.map((r) => r.event_id);
      events = await Event.find({ _id: { $in: ids } }).sort({ event_date: -1 }).lean();
    }

    const enriched = events.map((e) => ({
      ...e,
      id: e._id,
      event_datetime: e.event_date + (e.event_time ? ` ${e.event_time}` : ''),
    }));

    sendSuccess(res, { events: enriched });
  });
}

async function eventsRsvps(req, res) {
  const eventId = req.query.event_id;
  if (!eventId) return sendError(res, 'Event ID is required', 400);

  const event = await Event.findById(eventId).lean();
  if (!event) return sendError(res, 'Event not found', 404);

  const rsvps = await EventRsvp.find({ event_id: event._id }).lean();

  const grouped = { yes: [], maybe: [], no: [] };
  for (const r of rsvps) {
    const user = r.user_id ? await User.findById(r.user_id).lean() : null;
    grouped[r.rsvp_status].push({
      ...r,
      user_name: user ? user.name : null,
      username: user ? user.username : null,
      user_avatar: user ? user.avatar_url : null,
    });
  }

  sendSuccess(res, { rsvps: grouped });
}

async function eventsStats(req, res) {
  const total_events = await Event.countDocuments({ is_cancelled: false });
  const today = new Date().toISOString().slice(0, 10);
  const upcoming_events = await Event.countDocuments({ is_cancelled: false, event_date: { $gte: today } });
  const birthday_events = await Event.countDocuments({ is_cancelled: false, event_type: 'birthday' });
  const reunion_events = await Event.countDocuments({ is_cancelled: false, event_type: 'reunion' });

  sendSuccess(res, {
    stats: {
      total_events,
      upcoming_events,
      birthday_events,
      reunion_events,
      this_month: total_events, // simple placeholder
    },
  });
}

async function eventsCreate(req, res) {
  const user = await tryRequireAuth(req);
  if (user && !['contributor', 'admin'].includes(user.role)) {
    return sendError(res, 'Insufficient permissions', 403);
  }

  const body = req.body || {};
  const required = ['title', 'event_date', 'event_type'];
  for (const f of required) if (!body[f]) return sendError(res, `${f} is required`, 400);

  const title = sanitizeInput(body.title);
  const description = sanitizeInput(body.description || '');
  const event_type = sanitizeInput(body.event_type);

  const event = await Event.create({
    creator_id: user ? user.user_id : null,
    creator_name: user ? user.name || user.username : body.creator_name || 'Anonymous',
    title,
    description,
    event_type,
    event_date: body.event_date,
    event_time: body.event_time || null,
    end_date: body.end_date || null,
    end_time: body.end_time || null,
    location: sanitizeInput(body.location || ''),
    max_attendees: body.max_attendees ? parseInt(body.max_attendees, 10) : null,
    is_private: !!body.is_private,
    requires_rsvp: body.requires_rsvp !== undefined ? !!body.requires_rsvp : true,
    rsvp_deadline: body.rsvp_deadline || null,
    color: sanitizeInput(body.color || '#8FAE7B'),
  });

  sendSuccess(
    res,
    {
      id: event._id,
      title: event.title,
      event_date: event.event_date,
      creator_name: event.creator_name,
    },
    'Event created successfully',
  );
}

async function eventsSubmitRsvp(req, res) {
  const user = await tryRequireAuth(req);
  const body = req.body || {};
  const event_id = body.event_id;
  const rsvp_status = body.rsvp_status;
  const guest_count = Math.max(1, parseInt(body.guest_count || '1', 10));

  if (!event_id) return sendError(res, 'Event ID is required', 400);
  if (!['yes', 'no', 'maybe'].includes(rsvp_status)) return sendError(res, 'Invalid RSVP status', 400);

  const event = await Event.findById(event_id).lean();
  if (!event || event.is_cancelled) return sendError(res, 'Event not found', 404);

  const base = {
    event_id,
    rsvp_status,
    guest_count,
    dietary_requirements: sanitizeInput(body.dietary_requirements || ''),
    notes: sanitizeInput(body.notes || ''),
  };

  if (user) base.user_id = user.user_id;

  const existing = user ? await EventRsvp.findOne({ event_id, user_id: user.user_id }) : null;
  if (existing) {
    existing.rsvp_status = rsvp_status;
    existing.guest_count = guest_count;
    existing.dietary_requirements = base.dietary_requirements;
    existing.notes = base.notes;
    await existing.save();
  } else {
    await EventRsvp.create(base);
  }

  sendSuccess(res, { rsvp_status }, existing ? 'RSVP updated successfully' : 'RSVP submitted successfully');
}

async function eventsUpdate(req, res) {
  await requireAuth(req, res, async () => {
    const { id } = req.body || {};
    if (!id) return sendError(res, 'Event ID is required', 400);

    const event = await Event.findById(id);
    if (!event) return sendError(res, 'Event not found', 404);

    if (!event.creator_id || (event.creator_id.toString() !== req.user.user_id && req.user.role !== 'admin')) {
      return sendError(res, 'Insufficient permissions', 403);
    }

    const fields = [
      'title',
      'description',
      'event_date',
      'event_time',
      'end_date',
      'end_time',
      'location',
      'max_attendees',
      'is_private',
      'color',
    ];

    for (const f of fields) {
      if (f in req.body) {
        if (f === 'max_attendees') event[f] = req.body[f] ? parseInt(req.body[f], 10) : null;
        else if (f === 'is_private') event[f] = !!req.body[f];
        else event[f] = sanitizeInput(req.body[f]);
      }
    }

    await event.save();
    sendSuccess(res, {}, 'Event updated successfully');
  });
}

async function eventsDelete(req, res) {
  await requireAuth(req, res, async () => {
    const id = req.query.id;
    if (!id) return sendError(res, 'Event ID is required', 400);

    const event = await Event.findById(id);
    if (!event) return sendError(res, 'Event not found', 404);

    if (!event.creator_id || (event.creator_id.toString() !== req.user.user_id && req.user.role !== 'admin')) {
      return sendError(res, 'Insufficient permissions', 403);
    }

    event.is_cancelled = true;
    await event.save();
    sendSuccess(res, {}, 'Event cancelled successfully');
  });
}

// =====================================================
// PROFILES & COUSIN UPLOADS – get_profiles.php / get_uploads.php / save_profile.php
// =====================================================

// GET PROFILES (get_profiles.php replacement)
app.get('/get_profiles.php', async (req, res) => {
  try {
    const cousin = sanitizeInput(req.query.cousin || 'all');
    let profiles;
    if (cousin === 'all') profiles = await CousinProfile.find({}).sort({ cousin: 1 }).lean();
    else profiles = await CousinProfile.find({ cousin }).lean();

    const baseUrl = process.env.SITE_URL || (req.protocol + '://' + req.get('host'));
    profiles = profiles.map((p) => ({
      ...p,
      photo_url: p.profile_photo_path ? `${baseUrl}/${p.profile_photo_path}` : null,
    }));

    if (cousin !== 'all' && profiles.length === 1) {
      return res.json({ success: true, data: profiles[0] });
    }
    return res.json({ success: true, data: profiles, count: profiles.length });
  } catch (err) {
    console.error('get_profiles error', err);
    res.status(500).json({ success: false, error: 'Failed to retrieve profiles' });
  }
});

// GET UPLOADS (get_uploads.php replacement)
app.get('/get_uploads.php', async (req, res) => {
  try {
    const cousin = sanitizeInput(req.query.cousin || 'all');
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit || '50', 10)));
    const offset = Math.max(0, parseInt(req.query.offset || '0', 10));
    const orderBy = ['id', 'upload_date', 'title', 'cousin'].includes(req.query.order)
      ? req.query.order
      : 'upload_date';
    const orderDir = (req.query.dir || 'DESC').toString().toUpperCase() === 'ASC' ? 1 : -1;

    const query = {};
    if (cousin !== 'all') query.cousin = cousin;

    const total = await CousinUpload.countDocuments(query);
    const uploads = await CousinUpload.find(query)
      .sort({ [orderBy === 'id' ? '_id' : orderBy]: orderDir })
      .skip(offset)
      .limit(limit)
      .lean();

    const baseUrl = process.env.SITE_URL || (req.protocol + '://' + req.get('host'));
    const decorated = uploads.map((u) => {
      const isExternal = /^https?:\/\//i.test(u.file_path || '');
      const file_url = isExternal ? u.file_path : `${baseUrl}/${(u.file_path || '').replace(/\\/g, '/')}`;
      return {
        ...u,
        file_url,
        is_image: u.file_type && u.file_type.startsWith('image/'),
        is_video: u.file_type && u.file_type.startsWith('video/'),
      };
    });

    res.json({
      success: true,
      data: {
        uploads: decorated,
        total,
        limit,
        offset,
        count: decorated.length,
      },
    });
  } catch (err) {
    console.error('get_uploads error', err);
    res.status(500).json({ success: false, error: 'Failed to retrieve uploads' });
  }
});

// SAVE PROFILE (save_profile.php replacement – JSON only, expects base64 photo string)
app.post('/save_profile.php', async (req, res) => {
  try {
    const data = req.body || {};
    if (!data.cousin || !data.name) throw new Error('Cousin ID and name are required');

    const cousin = sanitizeInput(data.cousin);
    const name = sanitizeInput(data.name);

    let photoPath = data.profile_photo_path || null;
    if (data.photo && typeof data.photo === 'string' && data.photo.startsWith('data:image')) {
      photoPath = await saveBase64Image(data.photo, cousin);
    }

    const update = {
      cousin,
      name,
      birthdate: data.birthdate || null,
      relation: data.relation || null,
      location: data.location || null,
      passion: data.passion || null,
      bio: data.bio || null,
      phone: data.phone || null,
      email: data.email || null,
      theme: data.theme || 'sage',
    };

    if (photoPath) update.profile_photo_path = photoPath;

    const profile = await CousinProfile.findOneAndUpdate({ cousin }, update, { new: true, upsert: true });

    const baseUrl = process.env.SITE_URL || (req.protocol + '://' + req.get('host'));
    const withUrl = {
      ...profile.toObject(),
      photo_url: profile.profile_photo_path ? `${baseUrl}/${profile.profile_photo_path}` : null,
    };

    res.json({ success: true, message: 'Profile saved successfully', data: withUrl });
  } catch (err) {
    console.error('save_profile error', err);
    res.status(500).json({ success: false, error: 'Failed to save profile' });
  }
});

async function saveBase64Image(base64String, cousin) {
  try {
    const parts = base64String.split(',');
    if (parts.length !== 2) throw new Error('Invalid base64 format');
    const meta = parts[0];
    const encoded = parts[1];

    const match = meta.match(/data:image\/(.*?);/);
    const ext = (match && match[1]) || 'png';

    const buf = Buffer.from(encoded, 'base64');
    const dir = path.join(UPLOAD_ROOT, 'profiles');
    fs.mkdirSync(dir, { recursive: true });

    const filename = `${cousin}_profile_${Date.now()}.${ext}`;
    const filepath = path.join(dir, filename);
    fs.writeFileSync(filepath, buf);

    // return relative from project root so URLs stay consistent
    return path.relative(process.cwd(), filepath).replace(/\\/g, '/');
  } catch (err) {
    console.error('Image save error', err);
    return null;
  }
}

// =====================================================
// HEALTH CHECK
// =====================================================

app.get('/health', (req, res) => {
  res.json({ ok: true, status: 'Cousins Vault backend running', mongo: mongoose.connection.readyState });
});

// =====================================================
// START SERVER
// =====================================================

app.listen(PORT, () => {
  console.log(`🚀 Cousins Vault backend listening on port ${PORT}`);
});
