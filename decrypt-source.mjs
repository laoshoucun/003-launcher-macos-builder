import { createDecipheriv, pbkdf2Sync } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const input = process.argv[2];
const output = process.argv[3];
const password = process.env.SOURCE_ARCHIVE_PASSWORD;
if (!input || !output || !password) throw new Error('missing decrypt arguments or password');
const data = readFileSync(input);
const split = data.indexOf(10);
const metadata = JSON.parse(data.subarray(0, split).toString('utf8'));
const key = pbkdf2Sync(password, Buffer.from(metadata.salt, 'base64'), 210000, 32, 'sha256');
const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(metadata.iv, 'base64'));
decipher.setAuthTag(Buffer.from(metadata.tag, 'base64'));
writeFileSync(output, Buffer.concat([decipher.update(data.subarray(split + 1)), decipher.final()]));
