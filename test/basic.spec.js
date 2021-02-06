/*global describe, it, before */

var expect = require('chai').expect;

var api = require('..');


var validKey = 'my magical passphrase';
var validPlaintext = 'My plaintext message';
var validBuffer = Buffer.from(validPlaintext);


describe('aes256', function() {

  it('should be an object with the expected exported methods', function() {
    expect(api).to.be.a('object');
    expect(api.encrypt).to.be.a('function');
    expect(api.decrypt).to.be.a('function');
    expect(api.createCipher).to.be.a('function');
  });


  describe('.encrypt', function() {

    it('should have an arity of 2', function() {
      expect(api.encrypt.length).to.equal(2);
    });

    it('should return a string', function() {
      expect(api.encrypt(validKey, validPlaintext)).to.be.a('string');
    });

    it('should return a buffer', function() {
      expect(api.encrypt(validKey, validBuffer)).to.be.instanceof(Buffer);
    });

    it('should return a different encrypted message each time due to randomized initialization vectors using plaintext', function() {
      var encrypted1 = api.encrypt(validKey, validPlaintext);
      var encrypted2 = api.encrypt(validKey, validPlaintext);

      expect(encrypted1).to.be.a('string');
      expect(encrypted2).to.be.a('string');
      expect(encrypted1).to.have.length.greaterThan(16);  // 16 === length of a standard IV
      expect(encrypted2).to.have.length.greaterThan(16);  // 16 === length of a standard IV
      expect(encrypted1).to.not.equal(encrypted2);
    });

    it('should return a different encrypted message each time due to randomized initialization vectors using buffers', function() {
      var encrypted1 = api.encrypt(validKey, validBuffer);
      var encrypted2 = api.encrypt(validKey, validBuffer);

      expect(encrypted1).to.be.instanceof(Buffer);
      expect(encrypted2).to.be.instanceof(Buffer);
      expect(encrypted1).to.have.length.greaterThan(16);  // 16 === length of a standard IV
      expect(encrypted2).to.have.length.greaterThan(16);  // 16 === length of a standard IV
      expect(encrypted1).to.not.equal(encrypted2);
    });

    it('should throw an Error if a null `key` is provided', function() {
      var fn = function() {
        return api.encrypt(null, validPlaintext);
      };
      var expectedErrMsgRegExp = /^Provided "key" must be a non-empty string$/;
      expect(fn).to.throw(TypeError, expectedErrMsgRegExp);
    });

    it('should throw an Error if a non-string `key` is provided', function() {
      var fn = function() {
        return api.encrypt({}, validPlaintext);
      };
      var expectedErrMsgRegExp = /^Provided "key" must be a non-empty string$/;
      expect(fn).to.throw(TypeError, expectedErrMsgRegExp);
    });

    it('should throw an Error if a empty string `key` is provided', function() {
      var fn = function() {
        return api.encrypt('', validPlaintext);
      };
      var expectedErrMsgRegExp = /^Provided "key" must be a non-empty string$/;
      expect(fn).to.throw(TypeError, expectedErrMsgRegExp);
    });

    it('should throw an Error if a null `input` is provided', function() {
      var fn = function() {
        return api.encrypt(validKey, null);
      };
      var expectedErrMsgRegExp = /^Provided "input" must be a non-empty string or buffer$/;
      expect(fn).to.throw(TypeError, expectedErrMsgRegExp);
    });

    it('should throw an Error if a non-string and non-buffer `input` is provided', function() {
      var fn = function() {
        return api.encrypt(validKey, {});
      };
      var expectedErrMsgRegExp = /^Provided "input" must be a non-empty string or buffer$/;
      expect(fn).to.throw(TypeError, expectedErrMsgRegExp);
    });

    it('should throw an Error if a empty string `input` is provided', function() {
      var fn = function() {
        return api.encrypt(validKey, '');
      };
      var expectedErrMsgRegExp = /^Provided "input" must be a non-empty string or buffer$/;
      expect(fn).to.throw(TypeError, expectedErrMsgRegExp);
    });

    it('should throw an Error if a empty buffer `input` is provided', function() {
      var fn = function() {
        return api.encrypt(validKey, Buffer.from(''));
      };
      var expectedErrMsgRegExp = /^Provided "input" must be a non-empty string or buffer$/;
      expect(fn).to.throw(TypeError, expectedErrMsgRegExp);
    });

  });


  describe('.decrypt', function() {

    var validEncrypted;
    var validEncryptedBuffer;

    before(function() {
      validEncrypted = api.encrypt(validKey, validPlaintext);
      validEncryptedBuffer = api.encrypt(validKey, validBuffer);
    });

    it('should have an arity of 2', function() {
      expect(api.decrypt.length).to.equal(2);
    });

    it('should return a string', function() {
      expect(api.decrypt(validKey, validEncrypted)).to.be.a('string');
    });

    it('should return a buffer', function() {
      expect(api.decrypt(validKey, validEncryptedBuffer)).to.be.instanceof(Buffer);
    });

    it('should return the original plaintext message each time from the same encrypted message', function() {
      var decrypted1 = api.decrypt(validKey, validEncrypted);
      var decrypted2 = api.decrypt(validKey, validEncrypted);

      expect(decrypted1).to.be.a('string');
      expect(decrypted2).to.be.a('string');
      expect(decrypted1).to.equal(validPlaintext);
      expect(decrypted2).to.equal(validPlaintext);
      expect(decrypted1).to.equal(decrypted2);
    });

    it('should return the original buffer message each time from the same encrypted message', function() {
      var decrypted1 = api.decrypt(validKey, validEncryptedBuffer);
      var decrypted2 = api.decrypt(validKey, validEncryptedBuffer);

      expect(decrypted1).to.be.instanceof(Buffer);
      expect(decrypted2).to.be.instanceof(Buffer);
      expect(decrypted1.toString('utf8')).to.equal(validPlaintext);
      expect(decrypted2.toString('utf8')).to.equal(validPlaintext);
      expect(decrypted1.toString('utf8')).to.equal(decrypted2.toString('utf8'));
    });

    it('should return the original plaintext message each time from different encrypted messages', function() {
      var encrypted1 = api.encrypt(validKey, validPlaintext);
      var encrypted2 = api.encrypt(validKey, validPlaintext);
      var decrypted1 = api.decrypt(validKey, encrypted1);
      var decrypted2 = api.decrypt(validKey, encrypted2);

      // Precondition
      expect(encrypted1).to.not.equal(encrypted2);

      expect(decrypted1).to.be.a('string');
      expect(decrypted2).to.be.a('string');
      expect(decrypted1).to.equal(validPlaintext);
      expect(decrypted2).to.equal(validPlaintext);
      expect(decrypted1).to.equal(decrypted2);
    });

    it('should return the original buffer message each time from different encrypted messages', function() {
      var encrypted1 = api.encrypt(validKey, validBuffer);
      var encrypted2 = api.encrypt(validKey, validBuffer);
      var decrypted1 = api.decrypt(validKey, encrypted1);
      var decrypted2 = api.decrypt(validKey, encrypted2);

      // Precondition
      expect(encrypted1).to.not.equal(encrypted2);

      expect(decrypted1).to.be.instanceof(Buffer);
      expect(decrypted2).to.be.instanceof(Buffer);
      expect(decrypted1.toString('utf8')).to.equal(validPlaintext);
      expect(decrypted2.toString('utf8')).to.equal(validPlaintext);
      expect(decrypted1.toString('utf8')).to.equal(decrypted2.toString('utf8'));
    });

    it('should throw an Error if a null `key` is provided', function() {
      var fn = function() {
        return api.decrypt(null, validEncrypted);
      };
      var expectedErrMsgRegExp = /^Provided "key" must be a non-empty string$/;
      expect(fn).to.throw(TypeError, expectedErrMsgRegExp);
    });

    it('should throw an Error if a non-string `key` is provided', function() {
      var fn = function() {
        return api.decrypt({}, validEncrypted);
      };
      var expectedErrMsgRegExp = /^Provided "key" must be a non-empty string$/;
      expect(fn).to.throw(TypeError, expectedErrMsgRegExp);
    });

    it('should throw an Error if a empty string `key` is provided', function() {
      var fn = function() {
        return api.decrypt('', validEncrypted);
      };
      var expectedErrMsgRegExp = /^Provided "key" must be a non-empty string$/;
      expect(fn).to.throw(TypeError, expectedErrMsgRegExp);
    });

    it('should throw an Error if a null `encrypted` is provided', function() {
      var fn = function() {
        return api.decrypt('my magical passphrase', null);
      };
      var expectedErrMsgRegExp = /^Provided "encrypted" must be a non-empty string or buffer$/;
      expect(fn).to.throw(TypeError, expectedErrMsgRegExp);
    });

    it('should throw an Error if a non-string and non-buffer `encrypted` is provided', function() {
      var fn = function() {
        return api.decrypt('my magical passphrase', {});
      };
      var expectedErrMsgRegExp = /^Provided "encrypted" must be a non-empty string or buffer$/;
      expect(fn).to.throw(TypeError, expectedErrMsgRegExp);
    });

    it('should throw an Error if a empty string `encrypted` is provided', function() {
      var fn = function() {
        return api.decrypt('my magical passphrase', '');
      };
      var expectedErrMsgRegExp = /^Provided "encrypted" must be a non-empty string or buffer$/;
      expect(fn).to.throw(TypeError, expectedErrMsgRegExp);
    });

    it('should throw an Error if a empty buffer `encrypted` is provided', function() {
      var fn = function() {
        return api.decrypt('my magical passphrase', Buffer.from(''));
      };
      var expectedErrMsgRegExp = /^Provided "encrypted" must be a non-empty string or buffer$/;
      expect(fn).to.throw(TypeError, expectedErrMsgRegExp);
    });

    it('should throw an Error if a non-decryptable string `encrypted` is provided', function() {
      var fn = function() {
        // string length >= 17, Buffer length < 17
        return api.decrypt('my magical passphrase', 'abcdef1234567890abcdef');  // length < 17
      };
      var expectedErrMsgRegExp = /^Provided "encrypted" must decrypt to a non-empty string or buffer$/;
      expect(fn).to.throw(TypeError, expectedErrMsgRegExp);
    });

    it('should throw an Error if a non-decryptable buffer `encrypted` is provided', function() {
      var fn = function() {
        return api.decrypt('my magical passphrase', Buffer.from('abc'));  // Buffer length < 17
      };
      var expectedErrMsgRegExp = /^Provided "encrypted" must decrypt to a non-empty string or buffer$/;
      expect(fn).to.throw(TypeError, expectedErrMsgRegExp);
    });

  });



  describe('.createCipher', function() {

    it('should have an arity of 1', function() {
      expect(api.createCipher.length).to.equal(1);
    });

    it('should return a new AesCipher object with the expected property and methods', function() {
      var key = 'my magical passphrase';
      var cipher = api.createCipher(key);
      expect(cipher).to.be.a('object');
      expect(cipher.constructor.name).to.equal('AesCipher');
    });


    describe('AesCipher', function() {

      var AesCipher;

      before(function() {
        AesCipher = api.createCipher('foo').constructor;
      });


      it('should be a function named AesCipher', function() {
        expect(AesCipher).to.be.a('function');
        expect(AesCipher.name).to.equal('AesCipher');
      });

      it('should have an arity of 1', function() {
        expect(AesCipher.length).to.equal(1);
      });

      it('should work as a constructor', function() {
        /*jshint expr:true */

        var fn = function() {
          return new AesCipher(validKey);
        };
        expect(fn).to.not.throw(Error);

        var cipher = fn();
        expect(cipher).to.exist;
        expect(cipher.constructor).to.equal(AesCipher);
      });

      it('should have the expected methods on its prototype', function() {
        expect(AesCipher.prototype.encrypt).to.be.a('function');
        expect(AesCipher.prototype.decrypt).to.be.a('function');
      });

      it('should instantiate an object with the expected property and methods', function() {
        var cipher = new AesCipher(validKey);

        expect(cipher).to.have.property('key');
        expect(cipher).to.have.ownProperty('key');
        expect(cipher.key).to.be.a('string');
        expect(cipher.key).to.equal(validKey);

        expect(cipher).to.have.property('encrypt');
        expect(cipher.encrypt).to.be.a('function');

        expect(cipher).to.have.property('decrypt');
        expect(cipher.decrypt).to.be.a('function');
      });

      it('should throw an Error if a null `key` is provided', function() {
        var fn = function() {
          return new AesCipher(null);
        };
        var expectedErrMsgRegExp = /^Provided "key" must be a non-empty string$/;
        expect(fn).to.throw(TypeError, expectedErrMsgRegExp);
      });

      it('should throw an Error if a non-string `key` is provided', function() {
        var fn = function() {
          return new AesCipher({});
        };
        var expectedErrMsgRegExp = /^Provided "key" must be a non-empty string$/;
        expect(fn).to.throw(TypeError, expectedErrMsgRegExp);
      });

      it('should throw an Error if a empty string `key` is provided', function() {
        var fn = function() {
          return new AesCipher('');
        };
        var expectedErrMsgRegExp = /^Provided "key" must be a non-empty string$/;
        expect(fn).to.throw(TypeError, expectedErrMsgRegExp);
      });


      describe('#encrypt', function() {

        var validCipher;

        before(function() {
           validCipher = new AesCipher(validKey);
        });

        it('should be defined on the AesCipher.prototype', function() {
          expect(validCipher).to.have.property('encrypt');
          expect(validCipher.encrypt).to.be.a('function');
          expect(validCipher).to.not.have.ownProperty('encrypt');
          expect(validCipher.encrypt).to.equal(AesCipher.prototype.encrypt);
        });

        it('should have an arity of 1', function() {
          expect(validCipher.encrypt.length).to.equal(1);
        });

        it('should return a string', function() {
          expect(validCipher.encrypt(validPlaintext)).to.be.a('string');
        });

        it('should return a buffer', function() {
          expect(validCipher.encrypt(validBuffer)).to.be.instanceof(Buffer);
        });

        it('should return a different encrypted message each time due to randomized initialization vectors using plaintext', function() {
          var encrypted1 = validCipher.encrypt(validPlaintext);
          var encrypted2 = validCipher.encrypt(validPlaintext);

          expect(encrypted1).to.be.a('string');
          expect(encrypted2).to.be.a('string');
          expect(encrypted1).to.have.length.greaterThan(16);  // 16 === length of a standard IV
          expect(encrypted2).to.have.length.greaterThan(16);  // 16 === length of a standard IV
          expect(encrypted1).to.not.equal(encrypted2);
        });

        it('should return a different encrypted message each time due to randomized initialization vectors using buffers', function() {
          var encrypted1 = validCipher.encrypt(validBuffer);
          var encrypted2 = validCipher.encrypt(validBuffer);

          expect(encrypted1).to.be.instanceof(Buffer);
          expect(encrypted2).to.be.instanceof(Buffer);
          expect(encrypted1).to.have.length.greaterThan(16);  // 16 === length of a standard IV
          expect(encrypted2).to.have.length.greaterThan(16);  // 16 === length of a standard IV
          expect(encrypted1).to.not.equal(encrypted2);
        });

        it('should throw an Error if a null `input` is provided', function() {
          var fn = function() {
            return validCipher.encrypt(null);
          };
          var expectedErrMsgRegExp = /^Provided "input" must be a non-empty string or buffer$/;
          expect(fn).to.throw(TypeError, expectedErrMsgRegExp);
        });

        it('should throw an Error if a non-string and non-buffer `input` is provided', function() {
          var fn = function() {
            return validCipher.encrypt({});
          };
          var expectedErrMsgRegExp = /^Provided "input" must be a non-empty string or buffer$/;
          expect(fn).to.throw(TypeError, expectedErrMsgRegExp);
        });

        it('should throw an Error if a empty string `input` is provided', function() {
          var fn = function() {
            return validCipher.encrypt('');
          };
          var expectedErrMsgRegExp = /^Provided "input" must be a non-empty string or buffer$/;
          expect(fn).to.throw(TypeError, expectedErrMsgRegExp);
        });

        it('should throw an Error if a empty buffer `input` is provided', function() {
          var fn = function() {
            return validCipher.encrypt(Buffer.from(''));
          };
          var expectedErrMsgRegExp = /^Provided "input" must be a non-empty string or buffer$/;
          expect(fn).to.throw(TypeError, expectedErrMsgRegExp);
        });

        it('should create encrypted plaintext messages that can be decrypted with `aes256.decrypt`', function() {
          var encrypted = validCipher.encrypt(validPlaintext);
          var decrypted = api.decrypt(validKey, encrypted);

          expect(validCipher.key).to.equal(validKey);
          expect(decrypted).to.equal(validPlaintext);
        });

        it('should create encrypted buffer messages that can be decrypted with `aes256.decrypt`', function() {
          var encrypted = validCipher.encrypt(validBuffer);
          var decrypted = api.decrypt(validKey, encrypted);

          expect(validCipher.key).to.equal(validKey);
          expect(decrypted.toString('utf8')).to.equal(validPlaintext);
        });

      });


      describe('#decrypt', function() {

        var validCipher;
        var validEncrypted;
        var validEncryptedBuffer;

        before(function() {
          validCipher = new AesCipher(validKey);
          validEncrypted = validCipher.encrypt(validPlaintext);
          validEncryptedBuffer = validCipher.encrypt(validBuffer);
        });

        it('should be defined on the AesCipher.prototype', function() {
          expect(validCipher).to.have.property('decrypt');
          expect(validCipher.decrypt).to.be.a('function');
          expect(validCipher).to.not.have.ownProperty('decrypt');
          expect(validCipher.decrypt).to.equal(AesCipher.prototype.decrypt);
        });

        it('should have an arity of 1', function() {
          expect(validCipher.decrypt.length).to.equal(1);
        });

        it('should return a string', function() {
          expect(validCipher.decrypt(validEncrypted)).to.be.a('string');
        });

        it('should return a buffer', function() {
          expect(validCipher.decrypt(validEncryptedBuffer)).to.be.instanceof(Buffer);
        });

        it('should return the original plaintext message each time from the same encrypted message', function() {
          var decrypted1 = validCipher.decrypt(validEncrypted);
          var decrypted2 = validCipher.decrypt(validEncrypted);

          expect(decrypted1).to.be.a('string');
          expect(decrypted2).to.be.a('string');
          expect(decrypted1).to.equal(validPlaintext);
          expect(decrypted2).to.equal(validPlaintext);
          expect(decrypted1).to.equal(decrypted2);
        });

        it('should return the original buffer message each time from the same encrypted message', function() {
          var decrypted1 = validCipher.decrypt(validEncryptedBuffer);
          var decrypted2 = validCipher.decrypt(validEncryptedBuffer);

          expect(decrypted1).to.be.instanceof(Buffer);
          expect(decrypted2).to.be.instanceof(Buffer);
          expect(decrypted1.toString('utf8')).to.equal(validPlaintext);
          expect(decrypted2.toString('utf8')).to.equal(validPlaintext);
          expect(decrypted1.toString('utf8')).to.equal(decrypted2.toString('utf8'));
        });

        it('should return the original plaintext message each time from different encrypted messages', function() {
          var encrypted1 = validCipher.encrypt(validPlaintext);
          var encrypted2 = validCipher.encrypt(validPlaintext);
          var decrypted1 = validCipher.decrypt(encrypted1);
          var decrypted2 = validCipher.decrypt(encrypted2);

          // Precondition
          expect(encrypted1).to.not.equal(encrypted2);

          expect(decrypted1).to.be.a('string');
          expect(decrypted2).to.be.a('string');
          expect(decrypted1).to.equal(validPlaintext);
          expect(decrypted2).to.equal(validPlaintext);
          expect(decrypted1).to.equal(decrypted2);
        });

        it('should return the original buffer message each time from different encrypted messages', function() {
          var encrypted1 = validCipher.encrypt(validBuffer);
          var encrypted2 = validCipher.encrypt(validBuffer);
          var decrypted1 = validCipher.decrypt(encrypted1);
          var decrypted2 = validCipher.decrypt(encrypted2);

          // Precondition
          expect(encrypted1).to.not.equal(encrypted2);

          expect(decrypted1).to.be.instanceof(Buffer);
          expect(decrypted2).to.be.instanceof(Buffer);
          expect(decrypted1.toString('utf8')).to.equal(validPlaintext);
          expect(decrypted2.toString('utf8')).to.equal(validPlaintext);
          expect(decrypted1.toString('utf8')).to.equal(decrypted2.toString('utf8'));
        });

        it('should throw an Error if a null `encrypted` is provided', function() {
          var fn = function() {
            return validCipher.decrypt(null);
          };
          var expectedErrMsgRegExp = /^Provided "encrypted" must be a non-empty string or buffer$/;
          expect(fn).to.throw(TypeError, expectedErrMsgRegExp);
        });

        it('should throw an Error if a non-string and non-buffer `encrypted` is provided', function() {
          var fn = function() {
            return validCipher.decrypt({});
          };
          var expectedErrMsgRegExp = /^Provided "encrypted" must be a non-empty string or buffer$/;
          expect(fn).to.throw(TypeError, expectedErrMsgRegExp);
        });

        it('should throw an Error if a empty string `encrypted` is provided', function() {
          var fn = function() {
            return validCipher.decrypt('');
          };
          var expectedErrMsgRegExp = /^Provided "encrypted" must be a non-empty string or buffer$/;
          expect(fn).to.throw(TypeError, expectedErrMsgRegExp);
        });

        it('should throw an Error if a empty buffer `encrypted` is provided', function() {
          var fn = function() {
            return validCipher.decrypt(Buffer.from(''));
          };
          var expectedErrMsgRegExp = /^Provided "encrypted" must be a non-empty string or buffer$/;
          expect(fn).to.throw(TypeError, expectedErrMsgRegExp);
        });

        it('should throw an Error if a non-decryptable string `encrypted` is provided', function() {
          var fn = function() {
            // string length >= 17, Buffer length < 17
            return validCipher.decrypt('abcdef1234567890abcdef');
          };
          var expectedErrMsgRegExp = /^Provided "encrypted" must decrypt to a non-empty string or buffer$/;
          expect(fn).to.throw(TypeError, expectedErrMsgRegExp);
        });

        it('should throw an Error if a non-decryptable buffer `encrypted` is provided', function() {
          var fn = function() {
            // Buffer length < 17
            return validCipher.decrypt(Buffer.from('abc'));
          };
          var expectedErrMsgRegExp = /^Provided "encrypted" must decrypt to a non-empty string or buffer$/;
          expect(fn).to.throw(TypeError, expectedErrMsgRegExp);
        });

        it('should be able to decrypt encrypted plaintext messages created with `aes256.encrypt`', function() {
          var encrypted = api.encrypt(validKey, validPlaintext);
          var decrypted = validCipher.decrypt(encrypted);

          expect(validCipher.key).to.equal(validKey);
          expect(decrypted).to.equal(validPlaintext);
        });

        it('should be able to decrypt encrypted buffer messages created with `aes256.encrypt`', function() {
          var encrypted = api.encrypt(validKey, validBuffer);
          var decrypted = validCipher.decrypt(encrypted);

          expect(validCipher.key).to.equal(validKey);
          expect(decrypted.toString('utf8')).to.equal(validPlaintext);
        });

      });

    });

  });

});
