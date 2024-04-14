import express from 'express';
import jwt from 'jsonwebtoken';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import jose from 'node-jose';
import crypto from 'crypto';
import argon2 from 'argon2';
import { v4 as uuidv4 } from 'uuid';

import encryptionKey from './encryptionKey.js';
const app = express();
const port = 8080;

app.use(express.json());

let db;
const iv = crypto.randomBytes(16); // Generate IV once

async function initDB() {
    db = await open({
        filename: 'totally_not_my_privateKeys.db',
        driver: sqlite3.Database,
    });
    await db.exec(`CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT NOT NULL,
        exp INTEGER NOT NULL
    )`);
    await db.exec(`CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP      
    )`);
    await db.exec(`CREATE TABLE IF NOT EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,  
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);
}

async function saveKeyToDB(key, exp) {
    // Encrypt the key before saving it to the database
    const encryptedKey = encryptData(key);
    await db.run(
        'INSERT INTO keys (key, exp) VALUES (?, ?)',
        encryptedKey,
        exp
    );
}

async function getValidKeysFromDB() {
    const now = Math.floor(Date.now() / 1000);
    const rows = await db.all('SELECT * FROM keys WHERE exp > ?', now);
    // Deserialize the keys back to their original format before returning
    const keys = await Promise.all(
        rows.map(async (row) => {
            return jose.JWK.asKey(decryptData(row.key), 'pem');
        })
    );
    return keys;
}

async function getKeyFromDB(expired) {
    const now = Math.floor(Date.now() / 1000);
    const query = expired
        ? 'SELECT * FROM keys WHERE exp <= ? ORDER BY RANDOM() LIMIT 1'
        : 'SELECT * FROM keys WHERE exp > ? ORDER BY RANDOM() LIMIT 1';
    const row = await db.get(query, expired ? now : now);

    // Deserialize the key back to its original format before returning
    if (row) {
        return jose.JWK.asKey(decryptData(row.key), 'pem');
    } else {
        return null;
    }
}

function encryptData(data) {
    const cipher = crypto.createCipheriv('aes-256-cbc', encryptionKey, iv);
    let encryptedData = cipher.update(data, 'utf8', 'hex');
    encryptedData += cipher.final('hex');
    return encryptedData;
}

// Function to decrypt data using AES decryption
function decryptData(encryptedData) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', encryptionKey, iv);
    let decryptedData = decipher.update(encryptedData, 'hex', 'utf8');
    decryptedData += decipher.final('utf8');
    return decryptedData;
}

async function generateAndSaveKeyPairs() {
    const keyPair = await jose.JWK.createKey('RSA', 2048, {
        alg: 'RS256',
        use: 'sig',
    });
    await saveKeyToDB(
        keyPair.toPEM(true),
        Math.floor(Date.now() / 1000) + 3600
    ); // Expiring in 1 hour
    await saveKeyToDB(
        keyPair.toPEM(true),
        Math.floor(Date.now() / 1000) - 3600
    ); // Expired
}

async function generateExpiredJWT() {
    const expiredKey = await getKeyFromDB(true);
    if (!expiredKey) {
        throw new Error('No expired keys found in the database.');
    }
    const payload = {
        user: 'sampleUser',
        iat: Math.floor(Date.now() / 1000) - 30000,
        exp: Math.floor(Date.now() / 1000) - 3600,
    };
    const options = {
        algorithm: 'RS256',
        header: {
            typ: 'JWT',
            alg: 'RS256',
            kid: expiredKey.kid,
        },
    };
    return jwt.sign(payload, expiredKey.toPEM(true), options);
}

async function generateToken() {
    const key = await getKeyFromDB(false); // Getting a valid (unexpired) key
    if (!key) {
        throw new Error('No valid keys found in the database.');
    }
    const payload = {
        user: 'sampleUser',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
    };
    const options = {
        algorithm: 'RS256',
        header: {
            typ: 'JWT',
            alg: 'RS256',
            kid: key.kid,
        },
    };
    return jwt.sign(payload, key.toPEM(true), options);
}

app.all('/auth', (req, res, next) => {
    if (req.method !== 'POST') {
        return res.status(405).send('Method Not Allowed');
    }
    next();
});

app.all('/.well-known/jwks.json', (req, res, next) => {
    if (req.method !== 'GET') {
        return res.status(405).send('Method Not Allowed');
    }
    next();
});

app.get('/.well-known/jwks.json', async (req, res) => {
    const validKeys = await getValidKeysFromDB();
    console.log(validKeys);
    res.setHeader('Content-Type', 'application/json');
    res.json({ keys: validKeys.map((key) => key.toJSON()) });
});

app.post('/register', async (req, res) => {
    try {
        const { username, email } = req.body;

        // Generate a secure password using UUIDv4
        const password = generateSecurePassword();

        // Hash the password using Argon2
        const passwordHash = await hashPassword(password);

        // Store user details and hashed password in the users table
        const result = await db.run(
            'INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
            [username, passwordHash, email]
        );

        if (result.changes > 0) {
            // Registration successful, return the generated password to the user
            res.status(201).json({ password });
        } else {
            // Registration failed due to unknown reasons
            console.error(
                'Failed to register user. No changes were made to the database.'
            );
            res.status(500).send(
                'Failed to register user. Please try again later.'
            );
        }
    } catch (error) {
        // Registration failed due to an error
        console.error('Error registering user:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Logging Authentication Requests
app.post('/auth', async (req, res) => {
    try {
        const { username } = req.body;

        // Log authentication request details
        await logAuthenticationRequest(req.ip, username);

        // Authenticate user and generate token (existing logic)
        const token = await generateToken(); // Implement your authentication logic

        res.send(token);
    } catch (error) {
        console.error('Error authenticating user:', error);
        res.status(500).send('Internal Server Error');
    }
});

async function startServer() {
    await initDB();
    await generateAndSaveKeyPairs();
    app.listen(port, () => {
        console.log(`Server started on http://localhost:${port}`);
    });
}

startServer().catch((err) => {
    console.error('Error starting server:', err);
    process.exit(1);
});

// Function to generate a secure password using UUIDv4
function generateSecurePassword() {
    return uuidv4();
}

// Function to hash a password using Argon2
async function hashPassword(password) {
    return argon2.hash(password);
}

// Function to log authentication request details into the auth_logs table
async function logAuthenticationRequest(ip, username) {
    await db.run(
        'INSERT INTO auth_logs (request_ip, user_id) VALUES (?, (SELECT id FROM users WHERE username = ?))',
        [ip, username]
    );
}

export default app;
