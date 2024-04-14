import crypto from 'crypto';

// Generate a random encryption key
const encryptionKey = crypto.randomBytes(32); // 32 bytes for AES-256-CBC

// Export the encryption key
export default encryptionKey;
