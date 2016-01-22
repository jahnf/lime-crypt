LimeCrypt
=========
![](lclogo.png)

[![Build Status](https://travis-ci.org/jahnf/lime-crypt.svg?branch=master)](https://travis-ci.org/jahnf/lime-crypt)

LimeCrypt provides an easy C++ interface to some cryptographic functionality without
bothering the user with much details while providing secure defaults.
LimeCrypt is in essence a wrapper around _some_ of the [Crypto++ Libary][1] with
an interface that is simple to use and supports C++ standard iostreams.

**Table of Contents**

- [Features](#features)
- [Building](#building)
- [Examples](#examples)
  - [RSA](#rsa)
  - [AES](#aes)
- [License](#license)

Features
--------
Currently the LimeCrypt library provides methods for:

* RSA Public/Private Key cryptography
    * Key pair generation (and store to file, load from file)
    * Signing/Verification (Recovery and Appendix Schemes)
    * Encryption/Decryption
* Symmetric AES encryption/decryption
* Encoding and Decoding Base64 and Hex

[1]: https://cryptopp.com/  "Crypto++ Library"

Building
--------
LimeCrypt comes with CMake build files and should build almost everywhere and
should build everywhere where [Crypto++][1] builds.

**Example:** Build the library including examples and tests inside the out of
source `build` directory and run the tests.

    $ cd lime-crypt
    $ mkdir build && cd build
    $ cmake .. -DBUILD_EXAMPLES=1 -DBUILD_TESTS=1
    $ make
    $ make test


_Note_: You will need to run a

    git submodule update

if you have a fresh checkout to build the tests.
This will fetch the googletest submodule.

Examples
--------

### RSA
For more detailed examples see the examples directory.

#### Create, Save and Load Keys

    #include <lcpubkey.h>
    #include <lcencode.h>

    // Uninitialized, invalid private key instance.
    PrivateKey privKey;
    // Create a new random private key with default key size.
    if (privKey.create()) std::cout << "Created new private key." << std::endl;
    // Create matching public key instance, derived from the private key.
    PublicKey pubKey(privKey);

    // Save keys to files
    privKey.save("privateKey.file");
    pubKey.save("publicKey.file");

    // Load keys from files
    privKey.load("privateKey.file");
    pubKey.load("publicKey.file");

    // Check if keys are valid
    if (!privKey.isValid()) std::cout << "Invalid Private Key..." << std::endl;
    if (!pubKey.isValid()) std::cout << "Invalid Public Key..." << std::endl;

#### Sign and Verify
For more detailed examples see the examples directory.

##### Sign (Appendix Scheme)

    std::stringstream in("This is my message."), signed;
    privKey.signWithAppendix(in, signed);

    std::cout << "Signed message with recovery - Hex format (")
              << signed.str().size() << " bytes): " << Hex::encode(signed.str());

##### Simple Verify (Appendix Scheme)

    if (pubKey.verifyWithAppendix(signed))
        std::cout << "Signature verified." << std::endl;
    else
        std::cout << "Signature verification failed." << std::endl;

### AES
For more detailed examples see the examples directory.

#### Encrypt

    #include <lcaes.h>
    #include <lcencode.h>

    std::stringstream in("Secret Message."), encrypted;
    AES::encrypt("MyPassphrase", in, encrypted);
    std::cout << "Encrypted Message - Hex format (")
              << encrypted.str().size() << " bytes): "
              << Hex::encode(encrypted.str());
#### Decrypt

    std::stringstream decrypted;
    AES::encrypt("MyPassphrase", encrypted, decrypted);
    std::cout << "Decrypted Message ("
              << decrypted.str().size() << " bytes): "
              << decrypted.str();

License
-------
See [LICENSE](https://github.com/jahnf/lime-crypt/blob/master/LICENSE).

