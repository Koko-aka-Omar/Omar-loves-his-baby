'use strict';
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const { promisify } = require('node:util');
const scrypt = promisify(crypto.scrypt);
const PARAMS = { N:131072, r:8, p:1, maxmem:256 * 1024 * 1024 };
async function passwordHash(password) {
  const salt = crypto.randomBytes(16);
  const digest = await scrypt(password, salt, 32, PARAMS);
  return ['scrypt',PARAMS.N,PARAMS.r,PARAMS.p,salt.toString('base64url'),digest.toString('base64url')].join('$');
}
function validHash(value) { return /^scrypt\$131072\$8\$1\$[\w-]{22}\$[\w-]{43}$/.test(value || ''); }
async function verifyPassword(password, hash) {
  if (!validHash(hash)) throw new Error('Invalid password settings');
  const fields = hash.split('$');
  const result = await scrypt(password, Buffer.from(fields[4], 'base64url'), 32, PARAMS);
  return crypto.timingSafeEqual(result, Buffer.from(fields[5], 'base64url'));
}
function seal(text, key, purpose) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(key,'base64url'), iv);
  cipher.setAAD(Buffer.from('karmel-private-v1:' + purpose));
  const bytes = Buffer.concat([cipher.update(zlib.gzipSync(text)), cipher.final()]);
  return {iv:iv.toString('base64url'),tag:cipher.getAuthTag().toString('base64url'),data:bytes.toString('base64url')};
}
function unseal(payload, key, purpose) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(key,'base64url'), Buffer.from(payload.iv,'base64url'));
  decipher.setAAD(Buffer.from('karmel-private-v1:' + purpose));
  decipher.setAuthTag(Buffer.from(payload.tag,'base64url'));
  return zlib.gunzipSync(Buffer.concat([decipher.update(Buffer.from(payload.data,'base64url')),decipher.final()])).toString('utf8');
}
const fingerprint = value => crypto.createHash('sha256').update(value).digest('hex');
module.exports = {passwordHash,verifyPassword,validHash,seal,unseal,fingerprint};
