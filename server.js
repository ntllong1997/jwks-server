import express from 'express';
import jwt from 'jsonwebtoken';
import { generateKeyPairSync } from 'crypto';

const app = express();
const port = process.env.PORT || 8080;
const host = '127.0.0.1';

// Initialize JWKS variable
let jwks = generateJWKS();

// Function to generate JWKS
function generateJWKS() {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'jwk' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    const kid = 'TheBestkid';
    const expiry = Math.floor(Date.now() / 1000) + 3600; // Key expiry set to 1 hour

    return {
        keys: [
            {
                kid,
                kty: 'RSA',
                use: 'sig',
                alg: 'RS256',
                n: publicKey.n,
                e: publicKey.e,
                pem: privateKey, // Store the private key in JWKS
                exp: expiry,
            },
        ],
    };
}

// Middleware to check key expiry
const checkKeyExpiry = (req, res, next) => {
    const currentTimestamp = Math.floor(Date.now() / 1000);
    const expiry = jwks.keys[0].exp; // Expiry from JWKS
    // Generate a new key pair if the current key is expired
    if (currentTimestamp > expiry) {
        jwks = generateJWKS();
    }
    next();
};

// RESTful JWKS(/.well-known/jwks.json) endpoint that issues jwks
app.get('/.well-known/jwks.json', checkKeyExpiry, (req, res) => {
    res.json(jwks);
});

// /auth endpoint for token issuance
app.post('/auth', checkKeyExpiry, (req, res) => {
    const expired = req.query.expired == 'true';
    const expiresIn = expired ? -1 : 36000;

    const payload = { sub: 'zew0013' };
    const privateKey = jwks.keys[0].pem; // Get the private key from JWKS
    const token = jwt.sign(payload, privateKey, {
        algorithm: 'RS256',
        expiresIn,
        header: { kid: jwks.keys[0].kid },
    });
    res.json({ token });
});

// Route handling for unsupported methods
app.all('/auth', checkKeyExpiry, (req, res) => {
    res.status(405).end('Method Not Allowed');
});

// Route handling for unsupported JWKS endpoints
app.all('/.well-known/jwks.json', (req, res) => {
    res.status(405).end('Method Not Allowed');
});

// Start the server
app.listen(port, host, () => {
    console.log(`Server is running on http://${host}:${port}`);
});
