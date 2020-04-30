#include <memory>
#include <string>
#include <iostream>

namespace LimeCrypt
{

/// LimeCrypt Key Interface class.
class IKey
{
public:
    virtual ~IKey() {}
    virtual bool isValid() const = 0;
    virtual bool save(const std::string& filename) const = 0;
    virtual bool load(const std::string& filename) = 0;
    virtual bool loadFromString(const std::string& content) = 0;
    
    // auto_ptr is deprecated with C++11
    #if __cplusplus <= 199711L
        template<typename T> struct Pointer { typedef std::auto_ptr<T> Type; };
    #else
        template<typename T> struct Pointer { typedef std::unique_ptr<T> Type; };
    #endif
};

class PrivateKey; // forward declaration.
class PublicKey : public IKey
{
public:
    PublicKey();
    PublicKey(const PublicKey& other);
    PublicKey(const PrivateKey& privateKey);
    ~PublicKey();

    PublicKey& operator=(const PublicKey& rhs);
    bool operator==(const PublicKey& rhs) const;
    bool operator!=(const PublicKey& rhs) const;

    /// Returns if the current instance is a valid public key.
    bool isValid() const;

    /// Save the public key to a file.
    bool save(const std::string& filename) const;

    /// Load a public key from file.
    bool load(const std::string& filename);
    
    /// Load a public key from string
    bool loadFromString(const std::string& content);

    /// Derive and set the public key from a private key.
    bool assignFrom(const PrivateKey& privateKey);

    /// Verifies that the signature matches the input data. If signatureIn is an empty string
    /// it is assumed that the input data already has the signature attached. If signatureIn
    /// is not empty, dataIn will be treated as if it has no signature attached and signatureIn
    /// is used as signature.
    bool verifyWithAppendix(std::istream& dataIn, const std::string& signatureIn = "") const;

    /// Verifies the dataIn (includes appended signature) and writes out the data without
    /// signature to dataOut.
    bool verifyWithAppendix(std::istream& dataIn, std::ostream& dataOut) const;

    /// Verifies the input data with recovery signature and write out the message
    /// and recovered message part to dataOut.
    bool verifyWithRecovery(std::istream& dataIn, std::ostream& dataOut) const;

    /// Verifies the input data with PSSR SHA1 signature and write out the message
    /// and recovered message part to dataOut.
    bool verifyWithPSSR_SHA1(std::istream& dataIn, std::ostream& dataOut) const;
    
    /// Verifies the input data with recovery signature.
    bool verifyWithRecovery(std::istream& dataIn) const;

    /// Encrypt data with the public key.
    /// If successful, true is returned and the encrypted data is written to dataOut.
    /// Note that the size of data that can be encrypted
    /// is very limited (asymmetric encryption is only designed for encrypting
    /// data smaller than it's key size). To encrypt more data the usual approach
    /// is to generate a random symmetric key, encrypt the large message with the
    /// symmetric key, encrypt the symmetric key with RSA and put both part
    /// together as a message.
    bool encrypt(std::istream& dataIn, std::ostream& dataOut) const;

    /// Encrypt data with the public key - in place encryption version.
    /// If successful, true is returned and the content of dataInOut will
    /// contain the cipher text. See also notes on asymmetric encryption in
    /// the stream version of the encrypt method.
    bool encrypt(std::string& dataInOut) const;

    /// Returns the maximum plain test length that the encrypt method can process
    /// or 0 if the key is invalid. @see isValid().
    unsigned int maxPlainTextLength() const;

private:
    struct PublicKeyImpl;
    const IKey::Pointer<PublicKeyImpl>::Type _impl;
};

class PrivateKey : public IKey
{
public:
    PrivateKey();
    PrivateKey(const PrivateKey& other);
    ~PrivateKey();

    PrivateKey& operator=(const PrivateKey& rhs);
    bool operator==(const PrivateKey& rhs) const;
    bool operator!=(const PrivateKey& rhs) const;

    /// Returns if the current instance is a valid private key.
    bool isValid() const;

    /// Save the public key to a file.
    bool save(const std::string& filename) const;

    /// Load a public key from file.
    bool load(const std::string& filename);
    
    /// Load a private key from string
    bool loadFromString(const std::string& content);

    /// Create and initialize new random private key with the given key size.
    bool create(unsigned int keySizeBit = 2048);

    /// Signature scheme with recovery
    bool signWithRecovery(std::istream& in, std::ostream& out) const;

    /// Signature scheme with appendix
    bool signWithAppendix(std::istream& in, std::string& signatureOut) const;

    /// Signature scheme with appendix
    bool signWithAppendix(std::istream& in, std::ostream& out) const;

    /// Decrypt data previously enrypted with the corresponding public key.
    /// If successful, true is returned and the decrypted data is
    /// written to dataOut.
    bool decrypt(std::istream &dataIn, std::ostream& dataOut) const;

    /// Decrypt data method previously enrypted with the corresponding public key.
    /// If successful, true is returned and dataInOut contains the plain text.
    bool decrypt(std::string& dataInOut) const;

    /// Returns the maximum size of the recoverable size or 0 if the key is
    /// invalid. @see isValid().
    unsigned int maxRecoverableLength() const;

private:
    struct PrivateKeyImpl;
    const IKey::Pointer<PrivateKeyImpl>::Type _impl;

    // Allow certain members of PublicKey access to the private
    // implementation to be able to derive a crypto++ public key from
    // the existing crypto++ private key.
    friend bool PublicKey::assignFrom(const PrivateKey&);
};

} // end namespace LimeCrypt

