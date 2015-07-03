var sjcl = require('./sjcl/sjcl.js');

var iterations = 1 << 20;
var k = sjcl.misc.pbkdf2('password', 'salt', iterations);
console.log('SHA256,' + iterations + ',' + sjcl.codec.hex.fromBits(k));
