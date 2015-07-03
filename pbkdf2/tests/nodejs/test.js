var crypto = require('crypto');
var iterations = 1 << 20;
var k = crypto.pbkdf2Sync('password', 'saltsalt', 1 << 20, 20);
console.log('SHA1,' + iterations + ',' + new Buffer(k, 'hex').toString('hex'));
