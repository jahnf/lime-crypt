![](lclogo.png) > LimeCrypt
=========
[![Build Status](https://travis-ci.org/jahnf/lime-crypt.svg?branch=master)](https://travis-ci.org/jahnf/lime-crypt)

LimeCrypt wants to provide an easy C++ interface to some cryptographic
functionality without bothering the user with much details. LimeCrypt 
is in essence a wrapper around _some_ of the [Crypto++ Libary][1] with 
an interface that is simple to use. 

Currently the library provides methods for:

* RSA Public/Private Key cryptography
    * Key pair generation (and store to file, load from file)
    * Signing/Verification (Recovery and Appendix Schemes)
    * Encryption/Decryption
* Symmetric AES encryption/decryption
* Encoding and Decoding Base64 and Hex

[1]: https://cryptopp.com/  "Crypto++ Library"

Examples
--------

### RSA 

#### Sign and Verify
TODO

#### Encrypt and Decrypt
TODO

### AES
TODO

Building
--------
LimeCrypt comes with CMake files and should build almost everywhere and
should build everywhere where [Crypto++][1] builds.

**Example:** Build the library including examples and tests inside `build` directory
and run the tests.
```
$ cd lime-crypt
$ mkdir build && cd build
$ cmake .. -DBUILD_EXAMPLES=1 -DBUILD_TESTS=1
$ make
$ make test
```

