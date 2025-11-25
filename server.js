// Gerekli kütüphaneler
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: 'gizli-key',
  resave: false,
  saveUninitialized: true
}));
app.use('/public', express.static(path.join(__dirname, 'public')));

// SQLite veritabanı
const db = new sqlite3.Database('database.db');
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT
)`);

// ----------------- ROUTES -----------------

// Ana sayfa → login
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views/login.html'));
});

// Login sayfası
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views/login.html'));
});

// Login işlemi
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    if (!user) return res.send("Kullanıcı bulunamadı!");

    const match = await bcrypt.compare(password, user.password);
    if (match) {
      req.session.user = user;
      res.redirect('/dashboard');
    } else {
      res.send("Şifre yanlış!");
    }
  });
});

// Kayıt sayfası
app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'views/register.html'));
});

// Kayıt işlemi
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hash = await bcrypt.hash(password, 10);

  db.run("INSERT INTO users(username, password) VALUES(?, ?)", [username, hash], function(err) {
    if (err) {
      return res.send("Bu kullanıcı adı zaten alınmış!");
    }
    res.send("Kayıt başarılı! <a href='/login'>Giriş yap</a>");
  });
});

// Dashboard sayfası (sadece login olanlar)
app.get('/dashboard', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'views/dashboard.html'));
});

// Çıkış
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// ----------------- SERVER -----------------
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
