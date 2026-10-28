require('dotenv').config();
const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const session = require('express-session');
const SQLiteStoreFactory = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const crypto = require('crypto');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = Number(process.env.PORT || 3000);
const isProd = process.env.NODE_ENV === 'production';
if (isProd && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)) {
  throw new Error('Set SESSION_SECRET to a random string of at least 32 characters in production.');
}
const sessionSecret = process.env.SESSION_SECRET || 'dev-only-change-this-secret-before-deploying-123456';
const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, 'ssb.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT NOT NULL UNIQUE COLLATE NOCASE,
 display_name TEXT NOT NULL,
 bio TEXT NOT NULL DEFAULT '',
 avatar_url TEXT NOT NULL DEFAULT '',
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
 banned INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS messages (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 sender_id INTEGER NOT NULL REFERENCES users(id),
 recipient_id INTEGER REFERENCES users(id),
 channel TEXT NOT NULL DEFAULT 'general',
 group_id INTEGER,
 body TEXT NOT NULL,
 media_url TEXT NOT NULL DEFAULT '',
 media_type TEXT NOT NULL DEFAULT 'text',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS conversations (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 slug TEXT NOT NULL UNIQUE,
 type TEXT NOT NULL CHECK(type IN ('group','channel')),
 description TEXT NOT NULL DEFAULT '',
 avatar_url TEXT NOT NULL DEFAULT '',
 owner_id INTEGER NOT NULL REFERENCES users(id),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 live INTEGER NOT NULL DEFAULT 0,
 live_host_id INTEGER REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS conversation_members (
 conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 role TEXT NOT NULL DEFAULT 'member',
 joined_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(conversation_id,user_id)
);
CREATE TABLE IF NOT EXISTS live_comments (
 id INTEGER PRIMARY KEY AUTOINCREMENT, conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
 user_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS channel_posts (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 author_id INTEGER NOT NULL REFERENCES users(id),
 body TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS message_reactions (
 message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 emoji TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(message_id,user_id,emoji)
);
CREATE TABLE IF NOT EXISTS message_reads (
 message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 read_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(message_id,user_id)
);
CREATE TABLE IF NOT EXISTS user_blocks (
 blocker_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 blocked_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(blocker_id,blocked_id)
);
CREATE TABLE IF NOT EXISTS user_reports (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 reporter_id INTEGER NOT NULL REFERENCES users(id),
 target_user_id INTEGER REFERENCES users(id),
 message_id INTEGER REFERENCES messages(id),
 reason TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'open',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_logs (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 actor_id INTEGER,
 action TEXT NOT NULL,
 details TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);
// Backward-compatible migrations for databases created by earlier SSB versions.
function ensureColumn(table, column, definition) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name);
  if (!cols.includes(column)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
}
ensureColumn('users','bio',"TEXT NOT NULL DEFAULT ''");
ensureColumn('users','avatar_url',"TEXT NOT NULL DEFAULT ''");
ensureColumn('messages','group_id','INTEGER');
ensureColumn('messages','media_url',"TEXT NOT NULL DEFAULT ''");
ensureColumn('messages','media_type',"TEXT NOT NULL DEFAULT 'text'");
ensureColumn('messages','is_pinned','INTEGER NOT NULL DEFAULT 0');
db.exec(`CREATE TABLE IF NOT EXISTS saved_messages (user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE, saved_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(user_id,message_id));`);
ensureColumn('conversations','live_host_id','INTEGER');
ensureColumn('conversations','avatar_url',"TEXT NOT NULL DEFAULT ''");
ensureColumn('conversations','avatar_url',"TEXT NOT NULL DEFAULT ''");
const uploadDir = path.join(__dirname, 'public', 'uploads');
fs.mkdirSync(uploadDir, { recursive: true });
const storage = multer.diskStorage({ destination: uploadDir, filename: (req,file,cb) => { const ext = path.extname(file.originalname).toLowerCase().slice(0,10); cb(null, crypto.randomBytes(18).toString('hex') + ext); } });
const upload = multer({ storage, limits: { fileSize: 20 * 1024 * 1024 }, fileFilter: (req,file,cb) => { const mime=file.mimetype.split(';')[0].trim().toLowerCase(); const ext=path.extname(file.originalname).toLowerCase(); const allowedExt=new Set(['.png','.jpg','.jpeg','.gif','.webp','.mp3','.m4a','.aac','.ogg','.oga','.opus','.webm','.wav','.mp4','.mov','.pdf','.zip','.doc','.docx','.xls','.xlsx','.ppt','.pptx','.csv','.txt']); const knownMime=/^(image\/(png|jpeg|gif|webp)|audio\/(mpeg|mp4|aac|ogg|oga|opus|webm|wav|x-wav|3gpp|x-m4a)|video\/(mp4|webm|ogg|quicktime)|application\/(pdf|zip|x-zip-compressed|msword|vnd\.ms-excel|vnd\.ms-powerpoint|vnd\.openxmlformats-officedocument\.(wordprocessingml\.document|spreadsheetml\.sheet|presentationml\.presentation)|octet-stream|vnd\.oasis\.opendocument\.text)|text\/(plain|csv))$/.test(mime); const ok=knownMime || (mime==='application/octet-stream' && allowedExt.has(ext)); cb(ok ? null : new Error('این نوع فایل پشتیبانی نمی‌شود؛ عکس، صوت، ویدئو، PDF، ZIP، Word، Excel، PowerPoint، CSV یا TXT انتخاب کن.'), ok); } });
const count = db.prepare('SELECT COUNT(*) AS n FROM users WHERE role = ?').get('admin').n;
if (!count && process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD) {
  if (process.env.ADMIN_PASSWORD.length < 12) throw new Error('ADMIN_PASSWORD must be at least 12 characters.');
  const hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);
  db.prepare('INSERT OR IGNORE INTO users(username,display_name,password_hash,role) VALUES(?,?,?,?)')
    .run(process.env.ADMIN_USERNAME, 'مدیر SSB', hash, 'admin');
  console.log('Initial admin account created from environment variables.');
}

app.set('trust proxy', isProd ? 1 : false);
app.use(helmet({ contentSecurityPolicy: {
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", 'https://cdn.socket.io'],
    styleSrc: ["'self'", "'unsafe-inline'"],
    connectSrc: ["'self'", 'ws:', 'wss:', 'stun:'],
    imgSrc: ["'self'", 'data:', 'blob:'], mediaSrc: ["'self'", 'blob:'],
    objectSrc: ["'none'"], frameAncestors: ["'none'"]
  }
}}));
app.use(express.json({ limit: '32kb' }));
app.use(express.urlencoded({ extended: false, limit: '16kb' }));
const sessionMiddleware = session({
  name: 'ssb.sid',
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  store: new SQLiteStoreFactory({ db: 'sessions.sqlite', dir: dataDir }),
  cookie: { httpOnly: true, sameSite: 'lax', secure: isProd, maxAge: 1000 * 60 * 60 * 24 * 7 }
});
app.use(sessionMiddleware);
io.engine.use(sessionMiddleware);
io.engine.use((req, res, next) => {
  if (!req.session?.userId) return next(new Error('Authentication required'));
  next();
});
app.use(express.static(path.join(__dirname, 'public')));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });
const registerLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 8, standardHeaders: true, legacyHeaders: false });
function logAction(actorId, action, details='') {
  db.prepare('INSERT INTO audit_logs(actor_id,action,details) VALUES(?,?,?)').run(actorId || null, action, String(details).slice(0, 500));
}
function currentUser(req) {
  if (!req.session.userId) return null;
  return db.prepare('SELECT id,username,display_name,bio,avatar_url,role,banned,created_at FROM users WHERE id=?').get(req.session.userId) || null;
}
function requireAuth(req, res, next) {
  const user = currentUser(req);
  if (!user || user.banned) {
    if (req.session) req.session.destroy(() => {});
    return res.status(401).json({ error: 'ابتدا وارد حساب شوید.' });
  }
  req.user = user; next();
}
function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'دسترسی مدیر لازم است.' });
  next();
}
const clean = (s, max=2000) => String(s ?? '').trim().slice(0, max);
const slugify = s => clean(s,40).toLowerCase().normalize('NFKD').replace(/[^a-z0-9\u0600-\u06ff]+/g,'-').replace(/^-+|-+$/g,'').slice(0,36) || 'room';

app.get('/api/health', (req,res) => res.json({ ok: true, service: 'SSB Messenger' }));
app.post('/api/register', registerLimiter, (req,res) => {
  const username = clean(req.body.username, 24).toLowerCase();
  const displayName = clean(req.body.displayName, 40);
  const password = String(req.body.password || '');
  if (!/^[a-z0-9_]{3,24}$/.test(username)) return res.status(400).json({error:'نام کاربری باید ۳ تا ۲۴ حرف انگلیسی، عدد یا زیرخط باشد.'});
  if (displayName.length < 2) return res.status(400).json({error:'نام نمایشی حداقل ۲ حرف باشد.'});
  if (password.length < 10 || password.length > 128) return res.status(400).json({error:'رمز عبور باید ۱۰ تا ۱۲۸ کاراکتر باشد.'});
  try {
    const hash = bcrypt.hashSync(password, 12);
    const info = db.prepare('INSERT INTO users(username,display_name,password_hash) VALUES(?,?,?)').run(username, displayName, hash);
    req.session.regenerate(err => {
      if (err) return res.status(500).json({error:'خطا در ساخت نشست.'});
      req.session.userId = Number(info.lastInsertRowid);
      res.json({ok:true});
    });
  } catch(e) { res.status(409).json({error:'این نام کاربری قبلاً گرفته شده است.'}); }
});
app.post('/api/login', loginLimiter, (req,res) => {
  const username = clean(req.body.username, 24).toLowerCase();
  const password = String(req.body.password || '');
  const user = db.prepare('SELECT * FROM users WHERE username=?').get(username);
  if (!user || user.banned || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({error:'نام کاربری یا رمز عبور نادرست است.'});
  }
  req.session.regenerate(err => {
    if (err) return res.status(500).json({error:'خطا در ورود.'});
    req.session.userId = user.id;
    logAction(user.id, 'login');
    res.json({ok:true});
  });
});
app.post('/api/logout', (req,res) => req.session.destroy(() => { res.clearCookie('ssb.sid'); res.json({ok:true}); }));
app.get('/api/me', (req,res) => {
  const user = currentUser(req);
  if (!user || user.banned) return res.status(401).json({error:'وارد نشده‌اید.'});
  res.json({user});
});
app.get('/api/users', requireAuth, (req,res) => {
  const q=clean(req.query.q,80);
  if(q.length<2) return res.json({users:[]});
  const users=db.prepare(`SELECT id,username,display_name,bio,avatar_url,role FROM users
    WHERE banned=0 AND id<>? AND (username LIKE ? OR display_name LIKE ?)
    ORDER BY CASE WHEN username=? THEN 0 ELSE 1 END,display_name LIMIT 50`)
    .all(req.user.id,'%'+q+'%','%'+q+'%',q);
  res.json({users});
});

// Recent chat previews used by the responsive conversation list.
app.get('/api/chat-previews', requireAuth, (req,res) => {
  const uid = req.user.id;
  const direct = db.prepare(`SELECT u.id AS user_id,u.display_name,u.avatar_url,m.body,m.media_type,m.created_at,
      (SELECT COUNT(*) FROM messages um LEFT JOIN message_reads mr ON mr.message_id=um.id AND mr.user_id=?
       WHERE um.sender_id=u.id AND um.recipient_id=? AND mr.message_id IS NULL) AS unread
    FROM users u JOIN messages m ON m.id=(SELECT MAX(m2.id) FROM messages m2
      WHERE m2.recipient_id IS NOT NULL AND ((m2.sender_id=? AND m2.recipient_id=u.id) OR (m2.sender_id=u.id AND m2.recipient_id=?)))
    WHERE u.id<>? AND u.banned=0 ORDER BY m.id DESC`).all(uid,uid,uid,uid,uid);
  const general = db.prepare(`SELECT body,media_type,created_at,(SELECT COUNT(*) FROM messages x LEFT JOIN message_reads mr ON mr.message_id=x.id AND mr.user_id=? WHERE x.channel='general' AND x.recipient_id IS NULL AND x.group_id IS NULL AND x.sender_id<>? AND mr.message_id IS NULL) AS unread
    FROM messages WHERE channel='general' AND recipient_id IS NULL AND group_id IS NULL ORDER BY id DESC LIMIT 1`).get(uid,uid) || null;
  const rooms = db.prepare(`SELECT c.id AS conversation_id,
      (SELECT m.body FROM messages m WHERE m.group_id=c.id ORDER BY m.id DESC LIMIT 1) AS body,
      (SELECT m.media_type FROM messages m WHERE m.group_id=c.id ORDER BY m.id DESC LIMIT 1) AS media_type,
      (SELECT m.created_at FROM messages m WHERE m.group_id=c.id ORDER BY m.id DESC LIMIT 1) AS created_at,
      (SELECT COUNT(*) FROM messages m LEFT JOIN message_reads mr ON mr.message_id=m.id AND mr.user_id=? WHERE m.group_id=c.id AND m.sender_id<>? AND mr.message_id IS NULL) AS unread
    FROM conversations c`).all(uid,uid);
  res.json({direct,general,rooms});
});
app.get('/api/search/messages', requireAuth, (req,res) => {
  const q=clean(req.query.q,100); if(q.length<2) return res.json({messages:[]});
  const rows=db.prepare(`SELECT m.id,m.sender_id,m.recipient_id,m.channel,m.group_id,m.body,m.media_type,m.created_at,u.username,u.display_name AS sender_name
    FROM messages m JOIN users u ON u.id=m.sender_id
    WHERE m.body LIKE ? AND (m.recipient_id IS NULL OR m.sender_id=? OR m.recipient_id=?)
    ORDER BY m.id DESC LIMIT 100`).all('%'+q+'%',req.user.id,req.user.id);
  res.json({messages:rows});
});
app.post('/api/messages/:id/reactions', requireAuth, (req,res) => {
  const id=Number(req.params.id), emoji=clean(req.body.emoji,8);
  if(!Number.isInteger(id)||!['❤️','😂','👍','😮','😢','🔥','👏','💜'].includes(emoji)) return res.status(400).json({error:'واکنش نامعتبر است.'});
  const m=db.prepare('SELECT * FROM messages WHERE id=?').get(id); if(!m) return res.status(404).json({error:'پیام پیدا نشد.'});
  const existing=db.prepare('SELECT 1 FROM message_reactions WHERE message_id=? AND user_id=? AND emoji=?').get(id,req.user.id,emoji);
  if(existing) db.prepare('DELETE FROM message_reactions WHERE message_id=? AND user_id=? AND emoji=?').run(id,req.user.id,emoji);
  else db.prepare('INSERT INTO message_reactions(message_id,user_id,emoji) VALUES(?,?,?)').run(id,req.user.id,emoji);
  const reactions=db.prepare('SELECT emoji,COUNT(*) AS count FROM message_reactions WHERE message_id=? GROUP BY emoji').all(id);
  const payload={messageId:id,reactions};
  if(m.group_id) io.to('conversation:'+m.group_id).emit('message-reactions',payload);
  else if(m.recipient_id){ for(const uid of [m.sender_id,m.recipient_id]) for(const sock of (userSockets.get(uid)||[])) sock.emit('message-reactions',payload); }
  else io.to(`channel:${m.channel}`).emit('message-reactions',payload);
  res.json(payload);
});
app.post('/api/messages/:id/read', requireAuth, (req,res) => {
  const id=Number(req.params.id), m=db.prepare('SELECT * FROM messages WHERE id=?').get(id);
  if(!m) return res.status(404).json({error:'پیام پیدا نشد.'});
  if(m.sender_id!==req.user.id) db.prepare('INSERT OR IGNORE INTO message_reads(message_id,user_id) VALUES(?,?)').run(id,req.user.id);
  res.json({ok:true});
});
app.post('/api/users/:id/block', requireAuth, (req,res) => {
  const id=Number(req.params.id); if(!Number.isInteger(id)||id===req.user.id||!db.prepare('SELECT id FROM users WHERE id=?').get(id)) return res.status(400).json({error:'کاربر نامعتبر است.'});
  if(req.body.blocked===false) db.prepare('DELETE FROM user_blocks WHERE blocker_id=? AND blocked_id=?').run(req.user.id,id);
  else db.prepare('INSERT OR IGNORE INTO user_blocks(blocker_id,blocked_id) VALUES(?,?)').run(req.user.id,id);
  res.json({ok:true,blocked:req.body.blocked!==false});
});
app.post('/api/reports', requireAuth, (req,res) => {
  const target=req.body.targetUserId?Number(req.body.targetUserId):null, message=req.body.messageId?Number(req.body.messageId):null, reason=clean(req.body.reason,500);
  if(!reason||(!target&&!message)) return res.status(400).json({error:'دلیل و کاربر یا پیام گزارش‌شده لازم است.'});
  db.prepare('INSERT INTO user_reports(reporter_id,target_user_id,message_id,reason) VALUES(?,?,?,?)').run(req.user.id,target,message,reason);
  logAction(req.user.id,'report_submitted',`user:${target||''},message:${message||''}`); res.json({ok:true});
});
app.get('/api/admin/reports', requireAuth, requireAdmin, (req,res) => res.json({reports:db.prepare(`SELECT r.*,u.username AS reporter,m.body AS message_body,t.username AS target FROM user_reports r JOIN users u ON u.id=r.reporter_id LEFT JOIN messages m ON m.id=r.message_id LEFT JOIN users t ON t.id=r.target_user_id ORDER BY r.id DESC LIMIT 200`).all()}));

app.get('/api/messages', requireAuth, (req,res) => {
  const channel = clean(req.query.channel || 'general', 32);
  const recipient = Number(req.query.recipient || 0);
  let rows;
  if (recipient > 0) {
    rows = db.prepare(`SELECT m.id,m.sender_id,m.recipient_id,m.body,m.media_url,m.media_type,m.created_at,m.is_pinned,u.display_name AS sender_name
      FROM messages m JOIN users u ON u.id=m.sender_id
      WHERE (m.sender_id=? AND m.recipient_id=?) OR (m.sender_id=? AND m.recipient_id=?)
      ORDER BY m.id DESC LIMIT 100`).all(req.user.id, recipient, recipient, req.user.id).reverse();
  } else {
    rows = db.prepare(`SELECT m.id,m.sender_id,m.channel,m.body,m.media_url,m.media_type,m.created_at,m.is_pinned,u.display_name AS sender_name
      FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.recipient_id IS NULL AND m.channel=?
      ORDER BY m.id DESC LIMIT 100`).all(channel).reverse();
  }
  res.json({messages: rows});
});
app.post('/api/messages', requireAuth, (req,res) => {
  const body = clean(req.body.body, 2000);
  const mediaUrl = clean(req.body.mediaUrl, 300);
  const mediaType = clean(req.body.mediaType || 'text', 12);
  const recipient = req.body.recipientId ? Number(req.body.recipientId) : null;
  if (!['text','image','audio','video','file'].includes(mediaType)) return res.status(400).json({error:'نوع پیام نامعتبر است.'});
  const channel = clean(req.body.channel || 'general', 32);
  if (!body && !mediaUrl) return res.status(400).json({error:'متن پیام خالی است.'});
  if (mediaUrl && !mediaUrl.startsWith('/uploads/')) return res.status(400).json({error:'رسانه نامعتبر است.'});
  if (recipient && (recipient === req.user.id || !db.prepare('SELECT id FROM users WHERE id=? AND banned=0').get(recipient) || db.prepare('SELECT 1 FROM user_blocks WHERE (blocker_id=? AND blocked_id=?) OR (blocker_id=? AND blocked_id=?)').get(req.user.id,recipient,recipient,req.user.id)))
    return res.status(400).json({error:'گیرنده معتبر نیست.'});
  const info = db.prepare('INSERT INTO messages(sender_id,recipient_id,channel,body,media_url,media_type) VALUES(?,?,?,?,?,?)')
    .run(req.user.id, recipient, channel, body, mediaUrl, mediaType);
  const message = {id:Number(info.lastInsertRowid),sender_id:req.user.id,recipient_id:recipient,channel,body,media_url:mediaUrl,media_type:mediaType,created_at:new Date().toISOString(),sender_name:req.user.display_name};
  if (recipient) {
    for (const [id, socketSet] of userSockets.entries()) {
      if (id === req.user.id || id === recipient) for (const s of socketSet) s.emit('new-message', message);
    }
  } else io.to(`channel:${channel}`).emit('new-message', message);
  res.json({message});
});

// Edit or delete a message. Users can edit/delete their own messages; admins can moderate any message.
app.patch('/api/messages/:id', requireAuth, (req,res) => {
  const id=Number(req.params.id), message=db.prepare('SELECT * FROM messages WHERE id=?').get(id);
  if(!message) return res.status(404).json({error:'پیام پیدا نشد.'});
  if(message.sender_id!==req.user.id && req.user.role!=='admin') return res.status(403).json({error:'اجازه ویرایش این پیام را ندارید.'});
  const body=clean(req.body.body,2000);
  if(!body) return res.status(400).json({error:'متن پیام نمی‌تواند خالی باشد.'});
  if(message.media_type!=='text' && !message.media_url) return res.status(400).json({error:'این پیام قابل ویرایش نیست.'});
  db.prepare('UPDATE messages SET body=? WHERE id=?').run(body,id);
  const updated=db.prepare('SELECT m.id,m.sender_id,m.recipient_id,m.channel,m.group_id,m.body,m.media_url,m.media_type,m.created_at,m.is_pinned,u.display_name AS sender_name FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.id=?').get(id);
  if(message.group_id) io.to('conversation:'+message.group_id).emit('conversation-message',{conversationId:message.group_id,message:updated});
  else if(message.recipient_id) { for(const uid of [message.sender_id,message.recipient_id]) for(const s of (userSockets.get(uid)||[])) s.emit('new-message',updated); }
  else io.to('channel:'+message.channel).emit('new-message',updated);
  res.json({ok:true,message:updated});
});
app.delete('/api/messages/:id', requireAuth, (req,res) => {
  const id=Number(req.params.id), message=db.prepare('SELECT * FROM messages WHERE id=?').get(id);
  if(!message) return res.status(404).json({error:'پیام پیدا نشد.'});
  if(message.sender_id!==req.user.id && req.user.role!=='admin') return res.status(403).json({error:'اجازه حذف این پیام را ندارید.'});
  db.prepare('DELETE FROM messages WHERE id=?').run(id);
  const event={id,deleted:true};
  if(message.group_id) io.to('conversation:'+message.group_id).emit('conversation-message',{conversationId:message.group_id,message:event});
  else if(message.recipient_id) { for(const uid of [message.sender_id,message.recipient_id]) for(const s of (userSockets.get(uid)||[])) s.emit('new-message',event); }
  else io.to('channel:'+message.channel).emit('new-message',event);
  logAction(req.user.id,'delete_message',String(id));
  res.json({ok:true});
});

// Message menu actions: pin/unpin and save to the user's private space.
app.post('/api/messages/:id/pin', requireAuth, (req,res) => {
  const id=Number(req.params.id), m=db.prepare('SELECT * FROM messages WHERE id=?').get(id);
  if(!m) return res.status(404).json({error:'پیام پیدا نشد.'});
  const allowed=m.sender_id===req.user.id || req.user.role==='admin' || (m.group_id && db.prepare("SELECT role FROM conversation_members WHERE conversation_id=? AND user_id=?").get(m.group_id,req.user.id)?.role==='admin');
  if(!allowed) return res.status(403).json({error:'فقط نویسنده یا مدیر می‌تواند پیام را سنجاق کند.'});
  const pinned=m.is_pinned?0:1; db.prepare('UPDATE messages SET is_pinned=? WHERE id=?').run(pinned,id);
  logAction(req.user.id,pinned?'pin_message':'unpin_message',String(id));
  const event={messageId:id,isPinned:!!pinned};
  if(m.group_id) io.to('conversation:'+m.group_id).emit('message-pin',event);
  else if(m.recipient_id){for(const uid of [m.sender_id,m.recipient_id])for(const sock of (userSockets.get(uid)||[]))sock.emit('message-pin',event)}
  else io.to('channel:'+m.channel).emit('message-pin',event);
  res.json({ok:true,isPinned:!!pinned});
});
app.post('/api/messages/:id/save', requireAuth, (req,res) => {
  const id=Number(req.params.id), m=db.prepare('SELECT * FROM messages WHERE id=?').get(id);
  if(!m) return res.status(404).json({error:'پیام پیدا نشد.'});
  db.prepare('INSERT OR IGNORE INTO saved_messages(user_id,message_id) VALUES(?,?)').run(req.user.id,id);
  res.json({ok:true});
});
app.get('/api/saved-messages', requireAuth, (req,res) => {
  const messages=db.prepare(`SELECT m.id,m.sender_id,m.recipient_id,m.channel,m.group_id,m.body,m.media_url,m.media_type,m.created_at,m.is_pinned,u.display_name AS sender_name FROM saved_messages s JOIN messages m ON m.id=s.message_id JOIN users u ON u.id=m.sender_id WHERE s.user_id=? ORDER BY s.saved_at DESC LIMIT 200`).all(req.user.id);
  res.json({messages});
});

app.get('/api/channel', requireAuth, (req,res) => {
  const posts = db.prepare(`SELECT p.id,p.body,p.created_at,u.display_name AS author_name
    FROM channel_posts p JOIN users u ON u.id=p.author_id ORDER BY p.id DESC LIMIT 100`).all().reverse();
  res.json({posts});
});
app.post('/api/channel', requireAuth, requireAdmin, (req,res) => {
  const body = clean(req.body.body, 4000);
  if (!body) return res.status(400).json({error:'متن اطلاعیه خالی است.'});
  const info = db.prepare('INSERT INTO channel_posts(author_id,body) VALUES(?,?)').run(req.user.id, body);
  const post = {id:Number(info.lastInsertRowid),body,created_at:new Date().toISOString(),author_name:req.user.display_name};
  io.emit('channel-post', post); logAction(req.user.id,'channel_post',body.slice(0,120));
  res.json({post});
});
app.patch('/api/channel/:id', requireAuth, requireAdmin, (req,res) => {
  const id=Number(req.params.id), body=clean(req.body.body,4000);
  if(!Number.isSafeInteger(id)||id<1) return res.status(400).json({error:'شناسه اطلاعیه نامعتبر است.'});
  if(!body) return res.status(400).json({error:'متن اطلاعیه خالی است.'});
  const existing=db.prepare('SELECT id FROM channel_posts WHERE id=?').get(id);
  if(!existing) return res.status(404).json({error:'اطلاعیه پیدا نشد.'});
  db.prepare('UPDATE channel_posts SET body=? WHERE id=?').run(body,id);
  const post=db.prepare('SELECT p.id,p.body,p.created_at,u.display_name AS author_name FROM channel_posts p JOIN users u ON u.id=p.author_id WHERE p.id=?').get(id);
  io.emit('channel-post-updated',post); logAction(req.user.id,'edit_channel_post',String(id)); res.json({post});
});
app.delete('/api/channel/:id', requireAuth, requireAdmin, (req,res) => {
  const id=Number(req.params.id); if(!Number.isSafeInteger(id)||id<1) return res.status(400).json({error:'شناسه اطلاعیه نامعتبر است.'});
  const result=db.prepare('DELETE FROM channel_posts WHERE id=?').run(id); if(!result.changes) return res.status(404).json({error:'اطلاعیه پیدا نشد.'});
  io.emit('channel-post-deleted',{id}); logAction(req.user.id,'delete_channel_post',String(id)); res.json({ok:true});
});
app.patch('/api/channel/:id', requireAuth, requireAdmin, (req,res) => {
  const id=Number(req.params.id), body=clean(req.body.body,4000);
  if(!Number.isSafeInteger(id)||id<1) return res.status(400).json({error:'شناسه اطلاعیه نامعتبر است.'});
  if(!body) return res.status(400).json({error:'متن اطلاعیه خالی است.'});
  if(!db.prepare('SELECT id FROM channel_posts WHERE id=?').get(id)) return res.status(404).json({error:'اطلاعیه پیدا نشد.'});
  db.prepare('UPDATE channel_posts SET body=? WHERE id=?').run(body,id);
  const post=db.prepare('SELECT p.id,p.body,p.created_at,u.display_name AS author_name FROM channel_posts p JOIN users u ON u.id=p.author_id WHERE p.id=?').get(id);
  io.emit('channel-post-updated',post); logAction(req.user.id,'edit_channel_post',String(id)); res.json({post});
});
app.delete('/api/channel/:id', requireAuth, requireAdmin, (req,res) => {
  const id=Number(req.params.id); if(!Number.isSafeInteger(id)||id<1) return res.status(400).json({error:'شناسه اطلاعیه نامعتبر است.'});
  const result=db.prepare('DELETE FROM channel_posts WHERE id=?').run(id); if(!result.changes) return res.status(404).json({error:'اطلاعیه پیدا نشد.'});
  io.emit('channel-post-deleted',{id}); logAction(req.user.id,'delete_channel_post',String(id)); res.json({ok:true});
});
app.patch('/api/profile', requireAuth, (req,res) => {
  const displayName=clean(req.body.displayName,40), bio=clean(req.body.bio,280), avatarUrl=clean(req.body.avatarUrl,300);
  if(displayName.length<2) return res.status(400).json({error:'نام نمایشی حداقل ۲ حرف باشد.'});
  if(avatarUrl && !avatarUrl.startsWith('/uploads/')) return res.status(400).json({error:'تصویر پروفایل نامعتبر است.'});
  db.prepare('UPDATE users SET display_name=?,bio=?,avatar_url=? WHERE id=?').run(displayName,bio,avatarUrl,req.user.id);
  res.json({ok:true,user:db.prepare('SELECT id,username,display_name,bio,avatar_url,role,banned,created_at FROM users WHERE id=?').get(req.user.id)});
});
app.post('/api/upload', requireAuth, (req,res) => upload.single('file')(req,res,err => {
  if(err) return res.status(400).json({error:err.message || 'بارگذاری فایل ناموفق بود.'});
  if(!req.file) return res.status(400).json({error:'فایلی انتخاب نشده است.'});
  const mime=req.file.mimetype.split(';')[0].toLowerCase(), ext=path.extname(req.file.originalname).toLowerCase();
  const type=mime.startsWith('image/') || ['.png','.jpg','.jpeg','.gif','.webp'].includes(ext)?'image':mime.startsWith('audio/') || ['.mp3','.m4a','.aac','.ogg','.oga','.opus','.wav'].includes(ext)?'audio':mime.startsWith('video/') || ['.mp4','.mov','.webm'].includes(ext)?'video':'file';
  res.json({ok:true,url:'/uploads/'+req.file.filename,type,originalName:clean(req.file.originalname,120)});
}));
// Message moderation endpoints. Access is restricted to the author or an administrator.
app.patch('/api/messages/:id', requireAuth, (req,res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({error:'شناسه پیام نامعتبر است.'});
  const m = db.prepare('SELECT * FROM messages WHERE id=?').get(id);
  if (!m) return res.status(404).json({error:'پیام پیدا نشد.'});
  if (m.sender_id !== req.user.id && req.user.role !== 'admin') return res.status(403).json({error:'اجازه ویرایش این پیام را ندارید.'});
  if (m.media_type !== 'text' || m.media_url) return res.status(400).json({error:'فعلاً فقط پیام متنی قابل ویرایش است.'});
  const body = clean(req.body.body, 2000);
  if (!body) return res.status(400).json({error:'متن پیام نمی‌تواند خالی باشد.'});
  db.prepare('UPDATE messages SET body=? WHERE id=?').run(body,id);
  const updated = db.prepare(`SELECT m.id,m.sender_id,m.recipient_id,m.channel,m.group_id,m.body,m.media_url,m.media_type,m.created_at,m.is_pinned,u.display_name AS sender_name FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.id=?`).get(id);
  if (m.group_id) io.to('conversation:'+m.group_id).emit('conversation-message',{conversationId:m.group_id,message:updated});
  else if (m.recipient_id) { for (const uid of [m.sender_id,m.recipient_id]) for (const sock of (userSockets.get(uid)||[])) sock.emit('new-message',updated); }
  else io.to('channel:'+m.channel).emit('new-message',updated);
  logAction(req.user.id,'edit_message',String(id));
  res.json({ok:true,message:updated});
});
app.delete('/api/messages/:id', requireAuth, (req,res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({error:'شناسه پیام نامعتبر است.'});
  const m = db.prepare('SELECT * FROM messages WHERE id=?').get(id);
  if (!m) return res.status(404).json({error:'پیام پیدا نشد.'});
  if (m.sender_id !== req.user.id && req.user.role !== 'admin') return res.status(403).json({error:'اجازه حذف این پیام را ندارید.'});
  db.prepare('DELETE FROM messages WHERE id=?').run(id);
  const event = {id:m.id,deleted:true,sender_id:m.sender_id,recipient_id:m.recipient_id,channel:m.channel,group_id:m.group_id};
  if (m.group_id) io.to('conversation:'+m.group_id).emit('conversation-message',{conversationId:m.group_id,message:event});
  else if (m.recipient_id) { for (const uid of [m.sender_id,m.recipient_id]) for (const sock of (userSockets.get(uid)||[])) sock.emit('new-message',event); }
  else io.to('channel:'+m.channel).emit('new-message',event);
  logAction(req.user.id,'delete_message',String(id));
  res.json({ok:true});
});

app.get('/api/conversations', requireAuth, (req,res) => {
  const rows=db.prepare(`SELECT c.id,c.name,c.slug,c.type,c.description,c.avatar_url,c.owner_id,c.live,c.live_host_id,c.created_at,cm.role AS member_role,
    (SELECT COUNT(*) FROM conversation_members x WHERE x.conversation_id=c.id) AS members
    FROM conversations c JOIN conversation_members cm ON cm.conversation_id=c.id AND cm.user_id=? ORDER BY c.id DESC`).all(req.user.id);
  res.json({conversations:rows});
});
app.get('/api/discover/conversations', requireAuth, (req,res) => {
  const q=clean(req.query.q,80);
  if(q.length<2) return res.json({conversations:[]});
  const rows=db.prepare(`SELECT c.id,c.name,c.slug,c.type,c.description,c.avatar_url,c.owner_id,
    (SELECT COUNT(*) FROM conversation_members x WHERE x.conversation_id=c.id) AS members,
    EXISTS(SELECT 1 FROM conversation_members cm WHERE cm.conversation_id=c.id AND cm.user_id=?) AS is_member
    FROM conversations c WHERE c.type='channel' AND (c.name LIKE ? OR c.slug LIKE ?) ORDER BY c.name LIMIT 50`).all(req.user.id,'%'+q+'%','%'+q+'%');
  res.json({conversations:rows});
});
app.post('/api/conversations', requireAuth, (req,res) => {
  const name=clean(req.body.name,60), description=clean(req.body.description,300), type=req.body.type==='channel'?'channel':'group';
  if(name.length<2) return res.status(400).json({error:'نام گروه یا کانال حداقل ۲ حرف باشد.'});
  const base=slugify(name)+'-'+crypto.randomBytes(3).toString('hex');
  const create=db.transaction(()=>{
    const info=db.prepare('INSERT INTO conversations(name,slug,type,description,owner_id) VALUES(?,?,?,?,?)').run(name,base,type,description,req.user.id);
    db.prepare('INSERT INTO conversation_members(conversation_id,user_id,role) VALUES(?,?,?)').run(info.lastInsertRowid,req.user.id,'owner');
    return db.prepare('SELECT * FROM conversations WHERE id=?').get(info.lastInsertRowid);
  });
  const c=create(); logAction(req.user.id,'create_'+type,`${c.id}:${name}`); res.json({conversation:c});
});
app.patch('/api/conversations/:id/avatar', requireAuth, (req,res) => {
  const id=Number(req.params.id), avatarUrl=clean(req.body.avatarUrl,300);
  if(!Number.isSafeInteger(id)||id<1) return res.status(400).json({error:'شناسه گفت‌وگو نامعتبر است.'});
  if(!avatarUrl.startsWith('/uploads/')) return res.status(400).json({error:'تصویر انتخاب‌شده معتبر نیست.'});
  const c=db.prepare('SELECT * FROM conversations WHERE id=?').get(id);
  if(!c) return res.status(404).json({error:'گروه یا کانال پیدا نشد.'});
  const member=db.prepare('SELECT role FROM conversation_members WHERE conversation_id=? AND user_id=?').get(id,req.user.id);
  if(req.user.role!=='admin' && c.owner_id!==req.user.id && !['owner','admin'].includes(member?.role)) return res.status(403).json({error:'فقط مدیر گروه یا کانال می‌تواند عکس را تغییر دهد.'});
  const mimeExt=path.extname(avatarUrl).toLowerCase();
  if(!['.png','.jpg','.jpeg','.gif','.webp'].includes(mimeExt)) return res.status(400).json({error:'فقط فایل تصویری مجاز است.'});
  db.prepare('UPDATE conversations SET avatar_url=? WHERE id=?').run(avatarUrl,id);
  const updated=db.prepare('SELECT c.id,c.name,c.slug,c.type,c.description,c.avatar_url,c.owner_id,c.live,c.live_host_id,c.created_at FROM conversations c WHERE c.id=?').get(id);
  io.to('conversation:'+id).emit('conversation-updated',updated);
  logAction(req.user.id,'conversation_avatar',String(id));
  res.json({ok:true,conversation:updated});
});
app.patch('/api/conversations/:id/avatar', requireAuth, (req,res) => {
  const id=Number(req.params.id), avatarUrl=clean(req.body.avatarUrl,300);
  if(!Number.isSafeInteger(id)||id<1) return res.status(400).json({error:'شناسه گفت‌وگو نامعتبر است.'});
  if(!avatarUrl.startsWith('/uploads/')) return res.status(400).json({error:'تصویر انتخاب‌شده معتبر نیست.'});
  const c=db.prepare('SELECT * FROM conversations WHERE id=?').get(id);
  if(!c) return res.status(404).json({error:'گروه یا کانال پیدا نشد.'});
  const member=db.prepare('SELECT role FROM conversation_members WHERE conversation_id=? AND user_id=?').get(id,req.user.id);
  if(req.user.role!=='admin' && c.owner_id!==req.user.id && !['owner','admin'].includes(member?.role)) return res.status(403).json({error:'فقط مدیر گروه یا کانال می‌تواند عکس را تغییر دهد.'});
  if(!['.png','.jpg','.jpeg','.gif','.webp'].includes(path.extname(avatarUrl).toLowerCase())) return res.status(400).json({error:'فقط فایل تصویری مجاز است.'});
  db.prepare('UPDATE conversations SET avatar_url=? WHERE id=?').run(avatarUrl,id);
  const updated=db.prepare('SELECT c.id,c.name,c.slug,c.type,c.description,c.avatar_url,c.owner_id,c.live,c.live_host_id,c.created_at FROM conversations c WHERE c.id=?').get(id);
  io.to('conversation:'+id).emit('conversation-updated',updated); logAction(req.user.id,'conversation_avatar',String(id)); res.json({ok:true,conversation:updated});
});
app.get('/api/conversations/:id/details', requireAuth, (req,res) => {
  const id=Number(req.params.id), c=db.prepare('SELECT c.*, (SELECT COUNT(*) FROM conversation_members x WHERE x.conversation_id=c.id) AS members FROM conversations c WHERE c.id=?').get(id);
  if(!c) return res.status(404).json({error:'گروه یا کانال پیدا نشد.'});
  const membership=db.prepare('SELECT role FROM conversation_members WHERE conversation_id=? AND user_id=?').get(id,req.user.id); c.member_role=membership?.role||null;
  if(!membership && c.owner_id!==req.user.id && req.user.role!=='admin') return res.status(403).json({error:'برای دیدن جزئیات ابتدا باید عضو گروه یا کانال باشید.'});
  const members=db.prepare(`SELECT u.id,u.username,u.display_name,u.avatar_url,u.bio,u.created_at,cm.role,cm.joined_at FROM conversation_members cm JOIN users u ON u.id=cm.user_id WHERE cm.conversation_id=? ORDER BY CASE cm.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END,u.display_name`).all(id);
  const media=db.prepare(`SELECT m.id,m.body,m.media_url,m.media_type,m.created_at,u.display_name AS sender_name FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.group_id=? AND m.media_type IN ('image','video','audio','file') ORDER BY m.id DESC LIMIT 300`).all(id);
  res.json({conversation:c,members,media});
});
app.post('/api/conversations/:id/members', requireAuth, (req,res) => {
  const id=Number(req.params.id), userId=Number(req.body.userId), c=db.prepare('SELECT * FROM conversations WHERE id=?').get(id);
  if(!c) return res.status(404).json({error:'گروه یا کانال پیدا نشد.'});
  const actor=db.prepare('SELECT role FROM conversation_members WHERE conversation_id=? AND user_id=?').get(id,req.user.id);
  if(req.user.role!=='admin' && c.owner_id!==req.user.id && !['owner','admin'].includes(actor?.role)) return res.status(403).json({error:'فقط مدیر گروه یا کانال می‌تواند عضو اضافه کند.'});
  if(!Number.isSafeInteger(userId)||userId<1) return res.status(400).json({error:'کاربر را انتخاب کن.'});
  const target=db.prepare('SELECT id FROM users WHERE id=? AND banned=0').get(userId);
  if(!target) return res.status(404).json({error:'کاربر پیدا نشد.'});
  db.prepare("INSERT OR IGNORE INTO conversation_members(conversation_id,user_id,role) VALUES(?,?,'member')").run(id,userId);
  const member=db.prepare(`SELECT u.id,u.username,u.display_name,u.avatar_url,cm.role,cm.joined_at FROM conversation_members cm JOIN users u ON u.id=cm.user_id WHERE cm.conversation_id=? AND u.id=?`).get(id,userId);
  io.to('conversation:'+id).emit('conversation-members-updated',{conversationId:id});
  res.json({ok:true,member});
});
app.delete('/api/conversations/:id/members/:userId', requireAuth, (req,res) => {
  const id=Number(req.params.id), userId=Number(req.params.userId), c=db.prepare('SELECT * FROM conversations WHERE id=?').get(id);
  if(!c) return res.status(404).json({error:'گروه یا کانال پیدا نشد.'});
  const actor=db.prepare('SELECT role FROM conversation_members WHERE conversation_id=? AND user_id=?').get(id,req.user.id);
  if(req.user.role!=='admin' && c.owner_id!==req.user.id && !['owner','admin'].includes(actor?.role)) return res.status(403).json({error:'فقط مدیر گروه یا کانال می‌تواند عضو حذف کند.'});
  if(userId===c.owner_id) return res.status(400).json({error:'مالک گروه را نمی‌توان حذف کرد.'});
  db.prepare('DELETE FROM conversation_members WHERE conversation_id=? AND user_id=?').run(id,userId);
  io.to('conversation:'+id).emit('conversation-members-updated',{conversationId:id});
  res.json({ok:true});
});

app.post('/api/conversations/:id/join', requireAuth, (req,res) => {
  const c=db.prepare('SELECT * FROM conversations WHERE id=?').get(Number(req.params.id));
  if(!c) return res.status(404).json({error:'گروه یا کانال پیدا نشد.'});
  if(c.type!=='channel') return res.status(403).json({error:'برای عضویت در گروه، مالک یا مدیر باید شما را اضافه کند.'});
  db.prepare("INSERT OR IGNORE INTO conversation_members(conversation_id,user_id,role) VALUES(?,?,'member')").run(c.id,req.user.id);
  const member=db.prepare('SELECT role FROM conversation_members WHERE conversation_id=? AND user_id=?').get(c.id,req.user.id);
  res.json({ok:true,member_role:member?.role||'member'});
});
app.get('/api/conversations/:id/messages', requireAuth, (req,res) => {
  const id=Number(req.params.id), c=db.prepare('SELECT * FROM conversations WHERE id=?').get(id);
  if(!c) return res.status(404).json({error:'گفت‌وگو پیدا نشد.'});
  const member=db.prepare('SELECT 1 FROM conversation_members WHERE conversation_id=? AND user_id=?').get(id,req.user.id);
  if(!member && c.owner_id!==req.user.id && req.user.role!=='admin') return res.status(403).json({error:c.type==='group'?'ابتدا باید مالک یا مدیر شما را به گروه اضافه کند.':'ابتدا در کانال عضو شوید.'});
  const messages=db.prepare(`SELECT m.id,m.sender_id,m.body,m.media_url,m.media_type,m.created_at,m.is_pinned,u.display_name AS sender_name,u.avatar_url
    FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.group_id=? ORDER BY m.id DESC LIMIT 200`).all(id).reverse();
  res.json({messages,conversation:c});
});
app.post('/api/conversations/:id/messages', requireAuth, (req,res) => {
  const id=Number(req.params.id), c=db.prepare('SELECT * FROM conversations WHERE id=?').get(id), body=clean(req.body.body,2000), mediaUrl=clean(req.body.mediaUrl,300), mediaType=clean(req.body.mediaType||'text',12);
  if (!['text','image','audio','video','file'].includes(mediaType)) return res.status(400).json({error:'نوع پیام نامعتبر است.'});
  if(!c) return res.status(404).json({error:'گفت‌وگو پیدا نشد.'});
  const member=db.prepare('SELECT role FROM conversation_members WHERE conversation_id=? AND user_id=?').get(id,req.user.id);
  if(!member && c.owner_id!==req.user.id && req.user.role!=='admin') return res.status(403).json({error:c.type==='group'?'ابتدا باید مالک یا مدیر شما را به گروه اضافه کند.':'ابتدا در کانال عضو شوید.'});
  if(c.type==='channel' && req.user.role!=='admin' && c.owner_id!==req.user.id && member?.role!=='owner' && member?.role!=='admin') return res.status(403).json({error:'فقط مدیران کانال می‌توانند پیام بفرستند.'});
  if(!body && !mediaUrl) return res.status(400).json({error:'پیام خالی است.'});
  if(mediaUrl && !mediaUrl.startsWith('/uploads/')) return res.status(400).json({error:'رسانه نامعتبر است.'});
  const info=db.prepare('INSERT INTO messages(sender_id,channel,group_id,body,media_url,media_type) VALUES(?,?,?,?,?,?)').run(req.user.id,'conversation:'+id,id,body,mediaUrl,mediaType);
  const message={id:Number(info.lastInsertRowid),sender_id:req.user.id,body,media_url:mediaUrl,media_type:mediaType,created_at:new Date().toISOString(),sender_name:req.user.display_name,avatar_url:req.user.avatar_url||''};
  io.to('conversation:'+id).emit('conversation-message', {conversationId:id,message});
  res.json({message});
});
app.get('/api/admin/conversations', requireAuth, requireAdmin, (req,res) => {
  res.json({conversations:db.prepare(`SELECT c.*,u.username AS owner_name,(SELECT COUNT(*) FROM conversation_members m WHERE m.conversation_id=c.id) AS members FROM conversations c JOIN users u ON u.id=c.owner_id ORDER BY c.id DESC`).all(),
    directChats:db.prepare(`SELECT COUNT(*) AS n FROM messages WHERE recipient_id IS NOT NULL`).get().n,
    recentPrivate:db.prepare(`SELECT m.id,m.sender_id,m.recipient_id,m.body AS body,m.media_type,m.created_at,a.username AS sender,b.username AS recipient FROM messages m JOIN users a ON a.id=m.sender_id JOIN users b ON b.id=m.recipient_id WHERE m.recipient_id IS NOT NULL ORDER BY m.id DESC LIMIT 100`).all()});
});
app.patch('/api/admin/conversations/:id', requireAuth, requireAdmin, (req,res) => {
  const id=Number(req.params.id), c=db.prepare('SELECT * FROM conversations WHERE id=?').get(id);
  if(!c) return res.status(404).json({error:'گفت‌وگو پیدا نشد.'});
  if(typeof req.body.name==='string') db.prepare('UPDATE conversations SET name=? WHERE id=?').run(clean(req.body.name,60),id);
  if(typeof req.body.description==='string') db.prepare('UPDATE conversations SET description=? WHERE id=?').run(clean(req.body.description,300),id);
  if(typeof req.body.live==='boolean') db.prepare('UPDATE conversations SET live=? WHERE id=?').run(req.body.live?1:0,id);
  if(req.body.delete===true){ db.transaction(()=>{ db.prepare('DELETE FROM messages WHERE group_id=?').run(id); db.prepare('DELETE FROM conversations WHERE id=?').run(id); })(); logAction(req.user.id,'delete_conversation',String(id)); return res.json({ok:true,deleted:true}); }
  logAction(req.user.id,'manage_conversation',String(id)); res.json({ok:true});
});
app.get('/api/live', requireAuth, (req,res)=>res.json({sessions:db.prepare(`SELECT c.id,c.name,c.type,c.live,u.display_name AS host FROM conversations c JOIN users u ON u.id=c.owner_id WHERE c.live=1 ORDER BY c.id DESC`).all()}));
app.post('/api/conversations/:id/live', requireAuth, (req,res)=>{
 const id=Number(req.params.id), c=db.prepare('SELECT * FROM conversations WHERE id=?').get(id); if(!c) return res.status(404).json({error:'کانال یا گروه پیدا نشد.'});
 const member=db.prepare('SELECT role FROM conversation_members WHERE conversation_id=? AND user_id=?').get(id,req.user.id);
 if(c.owner_id!==req.user.id && req.user.role!=='admin' && member?.role!=='owner' && member?.role!=='admin') return res.status(403).json({error:'فقط مدیر گروه یا کانال می‌تواند پخش زنده را کنترل کند.'});
 db.prepare('UPDATE conversations SET live=? WHERE id=?').run(req.body.live?1:0,id); io.to('conversation:'+id).emit('live-state',{conversationId:id,live:!!req.body.live,host:req.user.display_name}); logAction(req.user.id,req.body.live?'live_start':'live_stop',String(id)); res.json({ok:true,live:!!req.body.live});
});

app.get('/api/admin/overview', requireAuth, requireAdmin, (req,res) => {
  res.json({
    stats: {
      users: db.prepare('SELECT COUNT(*) n FROM users').get().n,
      banned: db.prepare('SELECT COUNT(*) n FROM users WHERE banned=1').get().n,
      messages: db.prepare('SELECT COUNT(*) n FROM messages').get().n, reports: db.prepare("SELECT COUNT(*) n FROM user_reports WHERE status='open'").get().n,
      posts: db.prepare('SELECT COUNT(*) n FROM channel_posts').get().n,
      conversations: db.prepare('SELECT COUNT(*) n FROM conversations').get().n
    },
    users: db.prepare('SELECT id,username,display_name,role,banned,created_at FROM users ORDER BY id DESC LIMIT 200').all(),
    logs: db.prepare(`SELECT a.id,a.action,a.details,a.created_at,u.username FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT 50`).all()
  });
});
app.patch('/api/admin/users/:id', requireAuth, requireAdmin, (req,res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) return res.status(400).json({error:'شناسه نامعتبر است.'});
  const target = db.prepare('SELECT id,role,banned FROM users WHERE id=?').get(id);
  if (!target) return res.status(404).json({error:'کاربر پیدا نشد.'});
  if (id === req.user.id && (req.body.banned === true || req.body.role === 'user'))
    return res.status(400).json({error:'نمی‌توانید دسترسی حساب خود را حذف کنید.'});
  if (typeof req.body.banned === 'boolean') {
    db.prepare('UPDATE users SET banned=? WHERE id=?').run(req.body.banned ? 1 : 0,id);
    logAction(req.user.id, req.body.banned ? 'ban_user':'unban_user', `user:${id}`);
  }
  if (req.body.role === 'admin' || req.body.role === 'user') {
    if (target.role === 'admin' && req.body.role === 'user' &&
      db.prepare('SELECT COUNT(*) n FROM users WHERE role="admin" AND banned=0').get().n <= 1)
      return res.status(400).json({error:'باید حداقل یک مدیر فعال باقی بماند.'});
    db.prepare('UPDATE users SET role=? WHERE id=?').run(req.body.role,id);
    logAction(req.user.id,'change_role',`user:${id},role:${req.body.role}`);
  }
  res.json({ok:true});
});
app.get('*', (req,res) => res.sendFile(path.join(__dirname,'public','index.html')));

const userSockets = new Map();
io.on('connection', socket => {
  const userId = socket.request.session.userId;
  const user = db.prepare('SELECT id,role,banned FROM users WHERE id=?').get(userId);
  if (!user || user.banned) return socket.disconnect(true);
  if (!userSockets.has(userId)) userSockets.set(userId,new Set());
  userSockets.get(userId).add(socket);
  io.emit('presence',{userId,online:true});
  socket.join('channel:general');
  socket.on('join-conversation', id => { const n=Number(id); if(!Number.isInteger(n)||n<1)return; const member=db.prepare('SELECT 1 FROM conversation_members WHERE conversation_id=? AND user_id=?').get(n,userId); const c=db.prepare('SELECT owner_id FROM conversations WHERE id=?').get(n); if(c&&(member||c.owner_id===userId||user.role==='admin')) socket.join(`conversation:${n}`); });
  socket.on('call-signal', payload => { const target=Number(payload?.targetId); if(!Number.isInteger(target)||!userSockets.has(target)) return; for(const targetSocket of userSockets.get(target)) targetSocket.emit('call-signal',{fromId:userId,fromName:db.prepare('SELECT display_name FROM users WHERE id=?').get(userId)?.display_name||'کاربر',signal:payload.signal,callType:payload.callType==='video'?'video':'audio'}); });
  socket.on('live-signal', payload => { const target=Number(payload?.targetId), conversationId=Number(payload?.conversationId); if(!Number.isInteger(target)||!userSockets.has(target)||!Number.isInteger(conversationId)) return; const live=db.prepare('SELECT live FROM conversations WHERE id=?').get(conversationId); if(!live?.live) return; for(const targetSocket of userSockets.get(target)) targetSocket.emit('live-signal',{fromId:userId,conversationId,signal:payload.signal}); });
  socket.on('live-comment', payload => { const id=Number(payload?.conversationId), body=clean(payload?.body,500); if(!id||!body) return; const c=db.prepare('SELECT live FROM conversations WHERE id=?').get(id); if(!c?.live) return; const member=db.prepare('SELECT 1 FROM conversation_members WHERE conversation_id=? AND user_id=?').get(id,userId); if(!member && user.role!=='admin') return; const info=db.prepare('INSERT INTO live_comments(conversation_id,user_id,body) VALUES(?,?,?)').run(id,userId,body); io.to(`conversation:${id}`).emit('live-comment',{conversationId:id,id:Number(info.lastInsertRowid),userId,username:db.prepare('SELECT display_name FROM users WHERE id=?').get(userId).display_name,body,created_at:new Date().toISOString()}); });
  socket.on('join-channel', name => {
    const channel = clean(name,32);
    if (/^[a-z0-9_-]{1,32}$/.test(channel)) socket.join(`channel:${channel}`);
  });
  socket.on('disconnect', () => {
    const set=userSockets.get(userId); if (set) { set.delete(socket); if (!set.size) { userSockets.delete(userId); io.emit('presence',{userId,online:false}); } }
  });
});
server.listen(PORT, () => console.log(`SSB Messenger listening on port ${PORT}`));
