const express = require("express");  //ESTE CÓDIGO UTILIZA EL APPROACH USANDO LA LIBRERIA node-jose
const jose = require("node-jose");
const fs = require('fs');
require('dotenv').config();

const app = express();
app.use(express.json());
const port = 3000;

const users = [
    { id: 1, username: 'user2', password: 'password2' },
    // Add more users as needed
  ];

//async function generateRsaKeys(){ // Se supone que es para que el rpopio jose genere las llaves pero no me jala
    //const keyStore = jose.JWK.createKeyStore();
    //const { privateKey, publicKey } = await keyStore.generate('RSA', 2048);
   // return privateKey, publicKey
//}

const privateKey = fs.readFileSync('private-key.pem', 'utf8');
const publicKey = fs.readFileSync('public-key.pem', 'utf8');

const keystore = jose.JWK.createKeyStore();
keystore.add(fs.readFileSync('private-key.pem', 'utf8'), 'pem', { use: 'sig' });
keystore.add(privateKey, 'pem', { use: 'sig' })
  .catch((err) => {
    console.error('Error adding private key to keystore:', err);
  });


app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const user = users.find((u) => u.username === username && u.password === password);
    if (!user) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Generate JWT
    try {
        // Generate JWT
        const payload = { username };
        const { protected: header, payload: signedPayload } = await jose.JWS.createSign({ format: 'compact' }, keystore)
          .update(JSON.stringify(payload), 'utf8')
          .final();
    
        const jwtToken = `${header}.${signedPayload}`;
        res.json({ token: jwtToken });
      } catch (err) {
        console.error('Error generating JWT:', err);
        res.status(500).json({ message: 'Internal Server Error' });
      }
});

// Middleware to verify JWT for protected route
const verifyToken = async (req, res, next) => {
  const authorizationHeader = req.headers.authorization;

  if (!authorizationHeader) {
    return res.status(401).json({ message: 'Authorization header missing' });
  }

  const token = authorizationHeader.replace('Bearer ', '');

  try {
    const verified = await jose.JWS.createVerify({ format: 'compact' }, keystore.sig).verify(token);
    req.user = JSON.parse(verified.payload.toString());
    next();
  } catch (err) {
    return res.status(403).json({ message: 'Invalid token' });
  }
};

// Protected route
app.get('/protected', verifyToken, (req, res) => {
  res.json({ message: 'Protected route accessed', user: req.user });
});


  

// Start the server
app.listen(port, () => {
console.log(`Server is running at http://localhost:${port}`);
});