const crypto = require('crypto');
const fs = require('fs');

const generateJWTSecret = () => {
  const secretBytes = crypto.randomBytes(32);
  const secret = secretBytes.toString('hex');
  return secret;
};

const secret = generateJWTSecret();
fs.writeFileSync('.env', `JWT_SECRET=${secret}`);

console.log('JWT Secret generated and saved to .env file.');
