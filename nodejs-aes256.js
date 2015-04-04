var aes256 = {},
    crypto = require('crypto'),
    algorithm = 'aes-256-ctr';

aes256.encrypt = function (key, data) {
    var sha256 = crypto.createHash('sha256');
    sha256.update(key);

    var iv = crypto.randomBytes(16),
        plaintext = new Buffer(data),
        cipher = crypto.createCipheriv(algorithm, sha256.digest(), iv),
        ciphertext = cipher.update(plaintext);
    ciphertext = Buffer.concat([iv, ciphertext, cipher.final()]);

    return ciphertext.toString('base64');
};

aes256.decrypt = function (key, data) {
    var sha256 = crypto.createHash('sha256');
    sha256.update(key);

    var input = new Buffer(data, 'base64'),
        iv = input.slice(0, 16),
        ciphertext = input.slice(16),
        decipher = crypto.createDecipheriv(algorithm, sha256.digest(), iv),
        plaintext = decipher.update(ciphertext);
    plaintext += decipher.final();

    return plaintext;
};

module.exports = aes256;