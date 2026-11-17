const express = require('express');
const cors = require('cors');
const { createClient } = require('@libsql/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));

const turso = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key';
// ⚠️ اینجا API Key خودت از سایت api.imgbb.com رو بذار
const IMGBB_API_KEY = 'YOUR_IMGBB_API_KEY'; 

// ۱. ثبت‌نام
app.post('/api/signup', async (req, res) => {
  const { email, password } = req.body;
  try {
    const existing = await turso.execute({ sql: "SELECT * FROM site_users WHERE email = ?", args: [email] });
    if (existing.rows.length > 0) return res.status(400).json({ error: 'این ایمیل قبلا ثبت شده است' });

    const hashedPassword = await bcrypt.hash(password, 10);
    await turso.execute({ sql: "INSERT INTO site_users (email, password) VALUES (?, ?)", args: [email, hashedPassword] });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ۲. ورود و دریافت اطلاعات قبلی (متن، چک‌لیست و مدیا)
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await turso.execute({ sql: "SELECT * FROM site_users WHERE email = ?", args: [email] });
    if (result.rows.length === 0) return res.status(400).json({ error: 'کاربر یافت نشد' });

    const user = result.rows[0];
    const validPass = await bcrypt.compare(password, user.password);
    if (!validPass) return res.status(400).json({ error: 'رمز عبور اشتباه است' });

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    // ارسال اطلاعات ذخیره شده به همراه توکن
    res.json({ 
      success: true, 
      token, 
      note: user.note || "", 
      media_url: user.media_url || "", 
      media_type: user.media_type || "",
      checklist: user.checklist || "[]"
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ۳. آپدیت دیتابیس (متن، چک‌لیست و مدیا)
app.post('/api/update-profile', async (req, res) => {
  const { note, checklist, media_url, media_type } = req.body;
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'دسترسی غیرمجاز' });

  try {
    const decoded = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
    await turso.execute({
      sql: `UPDATE site_users SET note = ?, checklist = ?, media_url = ?, media_type = ? WHERE id = ?`,
      args: [note, checklist, media_url, media_type, decoded.userId],
    });
    res.json({ success: true });
  } catch (error) {
    res.status(401).json({ error: 'توکن نامعتبر است' });
  }
});

// ۴. آپلود عکس و ویدیو به ImgBB
app.post('/api/upload', async (req, res) => {
  const { fileBase64 } = req.body;
  try {
    const formData = new URLSearchParams();
    formData.append('image', fileBase64.split(',')[1]);

    const response = await fetch(`https://api.imgbb.com/1/upload?key=${IMGBB_API_KEY}`, {
      method: 'POST',
      body: formData
    });
    const data = await response.json();
    if (data.success) {
      res.json({ success: true, url: data.data.url, type: data.data.image.mime });
    } else {
      res.status(500).json({ error: 'خطا در آپلود' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const port = process.env.PORT || 4000;
app.listen(port, () => console.log(`Backend running on port ${port}`));
