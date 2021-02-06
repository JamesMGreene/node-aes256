// Node.js core modules
var crypto = require('crypto');


/**
 * The encryption algorithm (cipher) type to be used.
 * @type {String}
 * @const
 * @private
 */
var CIPHER_ALGORITHM = 'aes-256-ctr';


//
// Primary API
//

/**
 * An API to allow for greatly simplified AES-256 encryption and decryption using a passphrase of
 * any length plus a random Initialization Vector.
 * @exports aes256
 * @public
 */
var aes256 = {

  /**
   * Encrypt a clear-text message using AES-256 plus a random Initialization Vector.
   * @param {String} key  A passphrase of any length to used to generate a symmetric session key.
   * @param {String|Buffer} input  The clear-text message or buffer to be encrypted.
   * @returns {String|Buffer} A custom-encrypted version of the input.
   * @public
   * @method
   */
  encrypt: function(key, input) {
    if (typeof key !== 'string' || !key) {
      throw new TypeError('Provided "key" must be a non-empty string');
    }

    var isString = typeof input === 'string';
    var isBuffer = Buffer.isBuffer(input);
    if (!(isString || isBuffer) || (isString && !input) || (isBuffer && !Buffer.byteLength(input))) {
      throw new TypeError('Provided "input" must be a non-empty string or buffer');
    }

    var sha256 = crypto.createHash('sha256');
    sha256.update(key);

    // Initialization Vector
    var iv = crypto.randomBytes(16);
    var cipher = crypto.createCipheriv(CIPHER_ALGORITHM, sha256.digest(), iv);

    var buffer = input;
    if (isString) {
      buffer = Buffer.from(input);
    }

    var ciphertext = cipher.update(buffer);
    var encrypted = Buffer.concat([iv, ciphertext, cipher.final()]);

    if (isString) {
      encrypted = encrypted.toString('base64');
    }

    return encrypted;
  },

  /**
   * Decrypt an encrypted message back to clear-text using AES-256 plus a random Initialization Vector.
   * @param {String} key  A passphrase of any length to used to generate a symmetric session key.
   * @param {String|Buffer} encrypted  The encrypted message to be decrypted.
   * @returns {String|Buffer} The original plain-text message or buffer.
   * @public
   * @method
   */
  decrypt: function(key, encrypted) {
    if (typeof key !== 'string' || !key) {
      throw new TypeError('Provided "key" must be a non-empty string');
    }

    var isString = typeof encrypted === 'string';
    var isBuffer = Buffer.isBuffer(encrypted);
    if (!(isString || isBuffer) || (isString && !encrypted) || (isBuffer && !Buffer.byteLength(encrypted))) {
      throw new TypeError('Provided "encrypted" must be a non-empty string or buffer');
    }

    var sha256 = crypto.createHash('sha256');
    sha256.update(key);

    var input = encrypted;
    if (isString) {
      input = Buffer.from(encrypted, 'base64');

      if (input.length < 17) {
        throw new TypeError('Provided "encrypted" must decrypt to a non-empty string or buffer');
      }
    } else {
      if (Buffer.byteLength(encrypted) < 17) {
        throw new TypeError('Provided "encrypted" must decrypt to a non-empty string or buffer');
      }
    }

    // Initialization Vector
    var iv = input.slice(0, 16);
    var decipher = crypto.createDecipheriv(CIPHER_ALGORITHM, sha256.digest(), iv);

    var ciphertext = input.slice(16);

    var output;
    if (isString) {
      output = decipher.update(ciphertext) + decipher.final();
    } else {
      output = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    }

    return output;
  }

};




/**
 * Create a symmetric cipher with a given passphrase to then encrypt/decrypt data symmetrically.
 * @param {String} key  A passphrase of any length to used to generate a symmetric session key.
 * @public
 * @constructor
 */
function AesCipher(key) {
  if (typeof key !== 'string' || !key) {
    throw new TypeError('Provided "key" must be a non-empty string');
  }

  /**
   * A passphrase of any length to used to generate a symmetric session key.
   * @member {String} key
   * @readonly
   */
  Object.defineProperty(this, 'key', { value: key });

}

/**
 * Encrypt a clear-text message using AES-256 plus a random Initialization Vector.
 * @param {String} plaintext  The clear-text message to be encrypted.
 * @returns {String} A custom-encrypted version of the input.
 * @public
 * @method
 */
AesCipher.prototype.encrypt = function(plaintext) {
  return aes256.encrypt(this.key, plaintext);
};

/**
 * Decrypt an encrypted message back to clear-text using AES-256 plus a random Initialization Vector.
 * @param {String} encrypted  The encrypted message to be decrypted.
 * @returns {String} The original plain-text message.
 * @public
 * @method
 */
AesCipher.prototype.decrypt = function(encrypted) {
  return aes256.decrypt(this.key, encrypted);
};




//
// API Extension
//


/**
 * Create a symmetric cipher with a given passphrase to then encrypt/decrypt data symmetrically.
 * @param {String} key  A passphrase of any length to used to generate a symmetric session key.
 * @returns {AesCipher}
 * @public
 * @method
 */
aes256.createCipher = function(key) {
  return new AesCipher(key);
};




//
// Export the API
//

module.exports = aes256;
