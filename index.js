require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const ethers = require('ethers');
const path = require("path");
const bodyParser = require("body-parser");
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.static(__dirname));
app.use(express.json())
app.use(bodyParser.json());

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname + '/index.html'));
});

app.get('/api/nonce', (req, res) => {
  const nonce = crypto.randomBytes(32).toString('hex');
  res.json({ nonce });
});

const secretKey = process.env.SECRET_KEY;

app.post('/login', (req, res) => {
    const { signedMessage, message, address } = req.body;
    const recoveredAddress = ethers.utils.verifyMessage(message, signedMessage);
    if (recoveredAddress !== address) {
      return res.status(401).json({ error: 'Invalid signature' });
    }
    const token = jwt.sign({ address }, secretKey, { expiresIn: '10s' });
    res.json(token);
});

app.post('/verify', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    const token = authHeader.split(' ')[1];
    try {
      const decoded = jwt.verify(token, secretKey);
      const currentTime = Math.floor(Date.now() / 1000);
      if (decoded.exp < currentTime) {
        res.json("tokenExpired");
      } else {
        res.json("ok");
      }
    } catch (err) {
      res.status(401).json({ error: 'Invalid token' });
    }
});

app.get('/success', (req, res) => {
    res.sendFile(path.join(__dirname + '/success.html'));
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
