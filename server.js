// Backend API sử dụng Express.js để lưu log check-in/check-out vào MongoDB
// Cần cài đặt: express, mongoose, cors, body-parser, qrcode, jsonwebtoken, bcrypt

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const QRCode = require('qrcode');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const port = 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'backupsecret';

app.use(cors());
app.use(bodyParser.json());

mongoose.connect(process.env.MONGODB_URI, {

  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const logSchema = new mongoose.Schema({
  userId: String,
  type: String,
  time: Date,
  latitude: Number,
  longitude: Number,
  locationCode: String,
});

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  role: String, // 'admin' hoặc 'employee'
});

const Log = mongoose.model('Log', logSchema);
const User = mongoose.model('User', userSchema);

const validLocationCodes = ['QUAN01', 'QUAN02'];

// Middleware xác thực token và kiểm tra quyền admin
function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];
  if (!token) return res.status(401).send('Token required');

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).send('Token invalid');
    req.user = user;
    next();
  });
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).send('Chỉ admin được phép');
  }
  next();
}

// API đăng ký tài khoản admin hoặc nhân viên
app.post('/api/register', async (req, res) => {
  const { username, password, role } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashed, role });
  await user.save();
  res.send({ message: 'Đăng ký thành công' });
});

// API đăng nhập để lấy token
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).send({ message: 'Sai thông tin đăng nhập' });
  }
  const token = jwt.sign({ username: user.username, role: user.role }, JWT_SECRET);
  res.send({ token });
});

app.post('/api/log', async (req, res) => {
  const { userId, type, time, latitude, longitude, locationCode } = req.body;
  if (!validLocationCodes.includes(locationCode)) {
    return res.status(403).send({ message: 'Địa điểm không hợp lệ' });
  }
  const log = new Log({ userId, type, time: new Date(time), latitude, longitude, locationCode });
  await log.save();
  res.send({ message: 'Log saved successfully' });
});

app.get('/api/logs/:userId', async (req, res) => {
  const logs = await Log.find({ userId: req.params.userId }).sort({ time: -1 });
  res.send(logs);
});

app.get('/api/summary/:userId', async (req, res) => {
  const userId = req.params.userId;
  const startOfDay = new Date();
  startOfDay.setHours(0, 0, 0, 0);

  const logs = await Log.find({
    userId,
    time: { $gte: startOfDay },
  }).sort({ time: 1 });

  let total = 0;
  for (let i = 0; i < logs.length - 1; i++) {
    if (logs[i].type === 'check-in' && logs[i + 1].type === 'check-out') {
      total += new Date(logs[i + 1].time) - new Date(logs[i].time);
    }
  }

  const hours = total / (1000 * 60 * 60);
  const wagePerHour = 25000;
  const totalSalary = hours * wagePerHour;

  res.send({ totalMilliseconds: total, totalHours: hours, totalSalary });
});

// API thêm mã địa điểm mới - chỉ admin
app.post('/api/locations', authMiddleware, adminOnly, (req, res) => {
  const { newLocationCode } = req.body;
  if (!newLocationCode) return res.status(400).send('Thiếu mã địa điểm');
  if (!validLocationCodes.includes(newLocationCode)) {
    validLocationCodes.push(newLocationCode);
  }
  res.send({ message: 'Đã thêm mã địa điểm' });
});

// Tạo QR code cho địa điểm (admin)
app.get('/api/qrcode/:locationCode', authMiddleware, adminOnly, async (req, res) => {
  const code = req.params.locationCode;
  if (!validLocationCodes.includes(code)) {
    return res.status(404).send('Mã không tồn tại');
  }
  const qr = await QRCode.toDataURL(code);
  res.send(`<img src="${qr}" />`);
});

app.use(express.static(path.join(__dirname, 'dashboard')));

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'dashboard', 'index.html'));
});

app.listen(port, () => {
  console.log(`Backend API đang chạy tại http://localhost:${port}`);
});
