const express = require("express");  //ESTE CÓDIGO UTILIZA EL APPROACH USANDO LA LIBRERIA jsonwebtoken
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const app = express();
app.use(express.json());
const port = 3000;

const generateSymmetricKey = () => {
    return crypto.randomBytes(32).toString('hex'); // 32 bytes for HS256 (256 bits)
  };

const generateRsaKeys = () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048, // Adjust based on security requirements
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    return { publicKey, privateKey };
};

const secretKey = generateSymmetricKey();
const { publicKey, privateKey } = generateRsaKeys();


const users = [
    { id: 1, username: 'user1', password: 'password1' },
    // Add more users as needed
  ];
  
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const user = users.find((u) => u.username === username && u.password === password);
    if (!user) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Generate JWT
    const token = jwt.sign({ userId: user.id, username: user.username }, privateKey, { expiresIn: '1h', algorithm: 'RS256' });

    res.json({ token });
});

// Middleware to verify JWT for protected route
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization;
  
    if (!token) {
      return res.status(401).json({ message: 'Token not provided' });
    }
  
    jwt.verify(token, publicKey, (err, decoded) => {
      if (err) {
        return res.status(403).json({ message: 'Invalid token' });
      }
  
      req.user = decoded;
      next();
    });
  };
  
// Protected route
app.get('/protected', verifyToken, (req, res) => {
    res.json({ message: 'Protected route accessed', user: req.user });
});
  

// Start the server
app.listen(port, () => {
console.log(`Server is running at http://localhost:${port}`);
});