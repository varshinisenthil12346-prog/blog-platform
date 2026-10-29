const express = require('express');
const { DatabaseSync } = require('node:sqlite');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const SECRET = process.env.JWT_SECRET || 'change-this-secret';
const PORT = process.env.PORT || 3000;

const db = new DatabaseSync(path.join(__dirname, 'blog.db'));
db.exec('PRAGMA foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  content TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);`);

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Auth middleware ----------
function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Please login first' });
  }
}
const sign = (u) =>
  jwt.sign({ id: u.id, username: u.username }, SECRET, { expiresIn: '7d' });

// ---------- Auth routes ----------
app.post('/api/auth/register', (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password || password.length < 6)
    return res.status(400).json({ error: 'Username, email and password (min 6 chars) required' });
  try {
    const hash = bcrypt.hashSync(password, 10);
    const r = db.prepare('INSERT INTO users (username,email,password) VALUES (?,?,?)')
      .run(username.trim(), email.trim().toLowerCase(), hash);
    const user = { id: r.lastInsertRowid, username: username.trim() };
    res.status(201).json({ token: sign(user), user });
  } catch {
    res.status(409).json({ error: 'Username or email already exists' });
  }
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const u = db.prepare('SELECT * FROM users WHERE email=?').get((email || '').toLowerCase());
  if (!u || !bcrypt.compareSync(password || '', u.password))
    return res.status(401).json({ error: 'Invalid email or password' });
  res.json({ token: sign(u), user: { id: u.id, username: u.username } });
});

// ---------- Posts ----------
app.get('/api/posts', (req, res) => {
  res.json(db.prepare(`
    SELECT p.*, u.username AS author,
      (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) AS comment_count
    FROM posts p JOIN users u ON u.id=p.user_id
    ORDER BY p.created_at DESC`).all());
});

app.get('/api/posts/:id', (req, res) => {
  const post = db.prepare(`SELECT p.*, u.username AS author FROM posts p
    JOIN users u ON u.id=p.user_id WHERE p.id=?`).get(req.params.id);
  if (!post) return res.status(404).json({ error: 'Post not found' });
  post.comments = db.prepare(`SELECT c.*, u.username AS author FROM comments c
    JOIN users u ON u.id=c.user_id WHERE c.post_id=? ORDER BY c.created_at ASC`).all(req.params.id);
  res.json(post);
});

app.post('/api/posts', auth, (req, res) => {
  const { title, content } = req.body;
  if (!title || !content) return res.status(400).json({ error: 'Title and content required' });
  const r = db.prepare('INSERT INTO posts (title,content,user_id) VALUES (?,?,?)')
    .run(title.trim(), content.trim(), req.user.id);
  res.status(201).json(db.prepare('SELECT * FROM posts WHERE id=?').get(r.lastInsertRowid));
});

app.put('/api/posts/:id', auth, (req, res) => {
  const post = db.prepare('SELECT * FROM posts WHERE id=?').get(req.params.id);
  if (!post) return res.status(404).json({ error: 'Post not found' });
  if (post.user_id !== req.user.id) return res.status(403).json({ error: 'Not your post' });
  const { title, content } = req.body;
  if (!title || !content) return res.status(400).json({ error: 'Title and content required' });
  db.prepare('UPDATE posts SET title=?, content=?, updated_at=CURRENT_TIMESTAMP WHERE id=?')
    .run(title.trim(), content.trim(), post.id);
  res.json(db.prepare('SELECT * FROM posts WHERE id=?').get(post.id));
});

app.delete('/api/posts/:id', auth, (req, res) => {
  const post = db.prepare('SELECT * FROM posts WHERE id=?').get(req.params.id);
  if (!post) return res.status(404).json({ error: 'Post not found' });
  if (post.user_id !== req.user.id) return res.status(403).json({ error: 'Not your post' });
  db.prepare('DELETE FROM posts WHERE id=?').run(post.id);
  res.json({ message: 'Post deleted' });
});

// ---------- Comments ----------
app.post('/api/posts/:id/comments', auth, (req, res) => {
  const post = db.prepare('SELECT id FROM posts WHERE id=?').get(req.params.id);
  if (!post) return res.status(404).json({ error: 'Post not found' });
  const content = (req.body.content || '').trim();
  if (!content) return res.status(400).json({ error: 'Comment cannot be empty' });
  const r = db.prepare('INSERT INTO comments (post_id,user_id,content) VALUES (?,?,?)')
    .run(post.id, req.user.id, content);
  res.status(201).json(db.prepare('SELECT * FROM comments WHERE id=?').get(r.lastInsertRowid));
});

app.delete('/api/comments/:id', auth, (req, res) => {
  const c = db.prepare('SELECT * FROM comments WHERE id=?').get(req.params.id);
  if (!c) return res.status(404).json({ error: 'Comment not found' });
  if (c.user_id !== req.user.id) return res.status(403).json({ error: 'Not your comment' });
  db.prepare('DELETE FROM comments WHERE id=?').run(c.id);
  res.json({ message: 'Comment deleted' });
});

app.listen(PORT, () => console.log(`Blog running at http://localhost:${PORT}`));
