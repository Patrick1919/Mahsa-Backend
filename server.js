const express = require('express');
const cors = require('cors');
const { createClient } = require('@libsql/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

// اتصال به Turso (اطلاعات از Environment Variables در Render خوانده می‌شود)
const turso = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key';

// ۱. ثبت‌نام
app.post('/api/signup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'ایمیل و رمز عبور الزامی است' });

  try {
    const existing = await turso.execute({
      sql: "SELECT * FROM site_users WHERE email = ?",
      args: [email],
    });
    if (existing.rows.length > 0) return res.status(400).json({ error: 'این ایمیل قبلا ثبت شده است' });

    const hashedPassword = await bcrypt.hash(password, 10);
    await turso.execute({
      sql: "INSERT INTO site_users (email, password) VALUES (?, ?)",
      args: [email, hashedPassword],
    });

    res.json({ success: true, message: 'ثبت‌نام با موفقیت انجام شد' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ۲. ورود
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await turso.execute({
      sql: "SELECT * FROM site_users WHERE email = ?",
      args: [email],
    });
    if (result.rows.length === 0) return res.status(400).json({ error: 'کاربر یافت نشد' });

    const user = result.rows[0];
    const validPass = await bcrypt.compare(password, user.password);
    if (!validPass) return res.status(400).json({ error: 'رمز عبور اشتباه است' });

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, message: 'ورود موفقیت‌آمیز بود' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ۳. ذخیره متن
app.post('/api/save-note', async (req, res) => {
  const { text } = req.body;
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'دسترسی غیرمجاز' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    await turso.execute({
      sql: "UPDATE site_users SET note = ? WHERE id = ?",
      args: [text, decoded.userId],
    });
    res.json({ success: true, message: 'متن ذخیره شد' });
  } catch (error) {
    res.status(401).json({ error: 'توکن نامعتبر است' });
  }
});

const port = process.env.PORT || 4000;
app.listen(port, () => console.log(`Backend running on port ${port}`));
