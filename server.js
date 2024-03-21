// Import required modules
import express from 'express';
import jwt from 'jsonwebtoken';
import { generateKeyPairSync } from 'crypto';

// Create Express app
const app = express();
const port = 8080;
const host = '127.0.0.1';

// RSA public and private key pair generation
const generateKeyPair = () => {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    const kid = 'TheBestKid';
    const expiry = Math.floor(Date.now() / 1000) + 3600; // Key expiry set to 1 hour

    return { kid, expiry, publicKey, privateKey };
};

// Initial key pair
let { kid, expiry, publicKey, privateKey } = generateKeyPair();

// Middleware to check key expiry
const checkKeyExpiry = (req, res, next) => {
    const currentTimestamp = Math.floor(Date.now() / 1000);
    // Generate a new key pair if the current key is expired
    if (currentTimestamp > expiry) {
        ({ kid, expiry, publicKey, privateKey } = generateKeyPair());
    }
    next();
};

// Middleware to parse JSON bodies
app.use(express.json());

// RESTful JWKS(/.well-known/jwks.json) endpoint that issues jwks
app.get('/.well-known/jwks.json', checkKeyExpiry, (req, res) => {
    const jwks = {
        keys: [
            {
                kid: kid,
                kty: 'RSA',
                use: 'sig',
                alg: 'RS256',
                n: publicKey.n,
                e: publicKey.e,
                exp: expiry,
            },
        ],
    };
    res.json(jwks);
});

// POST endpoint for authentication
app.post('/auth', checkKeyExpiry, (req, res) => {
    const expired = req.query.expired == 'true';
    let expiresIn = expired ? -1 : 3600;

    const payload = { sub: 'zew0013' };
    const token = jwt.sign(payload, privateKey, {
        algorithm: 'RS256',
        expiresIn,
        header: { kid },
    });
    res.json({ token });
});

// Start the server
app.listen(port, host, () => {
    console.log(`Server is running on http://${host}:${port}`);
});
