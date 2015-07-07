var crypto = require('crypto');
var iterations = 1 << 22;
var k = crypto.pbkdf2Sync('password', 'saltsalt', iterations, 20);
console.log('SHA1,' + iterations + ',' + new Buffer(k, 'hex').toString('hex'));
