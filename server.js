import express from 'express';
import jwt from 'jsonwebtoken';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import jose from 'node-jose';

const app = express();
const port = 8080;

let db;

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
}

async function saveKeyToDB(key, exp) {
    // Serialize the key to a string format (PKCS1 PEM) before saving to the database
    const serializedKey = key.toString('pem');
    await db.run(
        'INSERT INTO keys (key, exp) VALUES (?, ?)',
        serializedKey,
        exp
    );
}

async function getValidKeysFromDB() {
    const now = Math.floor(Date.now() / 1000);
    const rows = await db.all('SELECT * FROM keys WHERE exp > ?', now);
    // Deserialize the keys back to their original format before returning
    const keys = await Promise.all(
        rows.map(async (row) => {
            return jose.JWK.asKey(row.key, 'pem');
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
        return jose.JWK.asKey(row.key, 'pem');
    } else {
        return null;
    }
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

app.post('/auth', async (req, res) => {
    try {
        const token =
            req.query.expired === 'true'
                ? await generateExpiredJWT()
                : await generateToken();
        res.send(token); // No JSON parsing required
    } catch (error) {
        console.error(error);
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

export default app;
