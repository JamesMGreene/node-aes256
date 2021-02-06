# aes256
[![GitHub Latest Release](https://badge.fury.io/gh/JamesMGreene%2Fnode-aes256.svg)](https://github.com/JamesMGreene/node-aes256) [![Build Status](https://secure.travis-ci.org/JamesMGreene/node-aes256.svg?branch=master)](https://travis-ci.org/JamesMGreene/node-aes256) [![Coverage Status](https://coveralls.io/repos/JamesMGreene/node-aes256/badge.svg?branch=master&service=github)](https://coveralls.io/github/JamesMGreene/node-aes256?branch=master) [![Dependency Status](https://david-dm.org/JamesMGreene/node-aes256.svg?theme=shields.io)](https://david-dm.org/JamesMGreene/node-aes256) [![Dev Dependency Status](https://david-dm.org/JamesMGreene/node-aes256/dev-status.svg?theme=shields.io)](https://david-dm.org/JamesMGreene/node-aes256#info=devDependencies)


A Node.js module to simplify using the built-in `crypto` module for AES-256 encryption with random initialization vectors.

This module generates a random [initialization vector](https://en.wikipedia.org/wiki/Initialization_vector) each time one of the `encrypt` methods is called.

Furthermore, your symmetric session key (a.k.a. secret, a.k.a. passphrase) can be of any size because it is hashed using SHA-256.


## Install

```shell
$ npm install aes256
```


## Usage

### Example using static methods

```js
var aes256 = require('aes256');

var key = 'my passphrase';
var plaintext = 'my plaintext message';
var buffer = Buffer.from(plaintext);

var encryptedPlainText = aes256.encrypt(key, plaintext);
var decryptedPlainText = aes256.decrypt(key, encryptedPlainText);
// plaintext === decryptedPlainText

var encryptedBuffer = aes256.encrypt(key, buffer);
var decryptedBuffer = aes256.decrypt(key, encryptedBuffer);
// plaintext === decryptedBuffer.toString('utf8)
```


### Example using an `AesCipher` instance

```js
var aes256 = require('aes256');

var key = 'my passphrase';
var plaintext = 'my plaintext message';
var buffer = Buffer.from(plaintext);

var cipher = aes256.createCipher(key);

var encryptedPlainText = cipher.encrypt(plaintext);
var decryptedPlainText = cipher.decrypt(encryptedPlainText);
// plaintext === decryptedPlainText

var encryptedBuffer = cipher.encrypt(buffer);
var decryptedBuffer = cipher.decrypt(encryptedBuffer);
// plaintext === decryptedBuffer.toString('utf8)
```


#### API

_Documentation maaaaaybe forthcoming...._

For now, looking at the above usage examples, the code, or the unit tests should all give you a pretty good idea without much effort as the API surface area is very small.


## License

Copyright (c) 2015-2021, James M. Greene (MIT License)
