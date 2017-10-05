const readline = require('readline-sync')
const crypto = require('crypto')
const lengths = {salt:32, iv:16};
const pp = readline.question("Passphrase: ", {hideEchoBack:true, mask:""})
const px = readline.question("Contents: ")
const salt = crypto.randomBytes(lengths.salt)
const iv = crypto.pseudoRandomBytes(lengths.iv)
const key = crypto.pbkdf2Sync(pp, salt, 100000, lengths.salt, 'sha256')
console.log(salt, iv);
var cipher = crypto.createCipheriv('aes-256-ctr', key, iv)
var encrypted = cipher.update(px, 'utf8', 'hex');
encrypted += cipher.final('hex');

let db_encrypted = salt.toString('hex')+iv.toString('hex')+encrypted;

let lS = lengths.salt*2;
const dsalt = Buffer.from(db_encrypted.slice(0,lS), 'hex');
const dvi = Buffer.from(db_encrypted.slice(lS,lS+lengths.iv*2), 'hex');
console.log(dsalt, dvi);
var dkey = crypto.pbkdf2Sync(pp, dsalt, 100000, lengths.salt, 'sha256')
var decipher = crypto.createDecipheriv('aes-256-ctr', key, dvi);


decipher.write(db_encrypted.slice(lS+lengths.iv*2), 'hex')
decipher.pipe(process.stdout);
decipher.end();