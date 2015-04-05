# nodejs-aes256
This is an easy to use AES256 module for nodejs.

This module generates a random [initialization vector](https://en.wikipedia.org/wiki/Initialization_vector) each time the encrypt method is called. Furthermore, your shared key can be of any size because it is hashed using sha256.

## Setup
Make sure you install and require the nodejs-aes256 module.

`npm install nodejs-aes256`

`var aes256 = require('nodejs-aes256');`

##Encryption
Ciphertext is base64 encoded. The first parameter is the shared key and the second is the plaintext.

`var ciphertext = aes256.encrypt(key, plaintext);`

##Decryption
For decryption, simply provide the shared key and ciphertext.

`var plaintext = aes256.decrypt(key, ciphertext);`

##Notes

* This has only been tested with strings for the shared key and plaintext
* It does not detect if decryption has failed
