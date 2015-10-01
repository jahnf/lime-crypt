#include <lcpubkey.h>
#include "limecrypt_p.h"

#include <sstream>

// Crypto++ includes
#include "crypto++/rsa.h"
#include "crypto++/osrng.h"     // AutoSeededRandomPool
#include "crypto++/files.h"
#include "crypto++/base64.h"
#include "crypto++/pssr.h"

namespace {
    // local typedefs
    typedef CryptoPP::RSAES<CryptoPP::OAEP<CryptoPP::SHA256> >::Decryptor RSAES_Decryptor;
    typedef CryptoPP::RSAES<CryptoPP::OAEP<CryptoPP::SHA256> >::Encryptor RSAES_Encryptor;

    typedef CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Signer RSA_Appendix_Signer;
    typedef CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Verifier RSA_Appendix_Verifier;

    typedef CryptoPP::RSASS<CryptoPP::PSSR, CryptoPP::SHA256>::Signer RSA_Revovery_Signer;
    typedef CryptoPP::RSASS<CryptoPP::PSSR, CryptoPP::SHA256>::Verifier RSA_Recovery_Verifier;

    // Basic key functionality for public and private keys
    template <typename T>
    struct CCKeyImpl
    {
        CCKeyImpl() : keyValid(false) {}

        bool isValid() const { return keyValid; }

        bool saveKeyFileBase64(const std::string& filename) const
        {
            try {
                if (!isValid()) throw CryptoPP::Exception(CryptoPP::Exception::INVALID_DATA_FORMAT, "Invalid key." );
                key.Save(CryptoPP::Base64Encoder(new CryptoPP::FileSink(filename.c_str())).Ref());
                return true;
            }
            catch (CryptoPP::Exception& e) {
                LimeCrypt::handleError(std::string("Public/Private key save: ") + e.what());
            }
            return false;
        }

        bool saveKeyBase64(std::string& keyOut) const
        {
            try {
                if (!isValid()) throw CryptoPP::Exception(CryptoPP::Exception::INVALID_DATA_FORMAT, "Invalid key." );
                key.Save(CryptoPP::Base64Encoder(new CryptoPP::StringSink(keyOut)).Ref());
                return true;
            }
            catch (CryptoPP::Exception& e) {
                LimeCrypt::handleError(std::string("Public/Private key save: ") + e.what());
            }
            return false;
        }

        // Source can be either CryptoPP::FileSource or CryptoPP::StringSource
        // Later implementations will also load and save keys from and to std::strings.
        template <typename Source>
        bool loadKeyBase64(const std::string& in)
        {
            reset();
            try {
                key.Load(Source(in.c_str(), true, new CryptoPP::Base64Decoder).Ref());
                validate();
            }
            catch (CryptoPP::Exception& e) {
                LimeCrypt::handleError(std::string("Public/Private key load: ") + e.what());
            }
            return isValid();
        }

        void reset() { keyValid = false; }

        bool validate()
        {
            CryptoPP::AutoSeededRandomPool rng;
            key.ThrowIfInvalid(rng,3);
            keyValid = true;
        }

        T key;
        bool keyValid;
    };

    class StreambufConcatenator : public std::streambuf
    {
    public:
        StreambufConcatenator(const std::vector<std::istream*>& istrms)
            : m_istrms(istrms), m_current_strm(0) {}

    private:
        int_type underflow() {
            if (m_current_strm >= m_istrms.size()) return std::streambuf::underflow();
            int_type tmp;
            while( (tmp = m_istrms[m_current_strm]->rdbuf()->sgetc()) == traits_type::eof() ) {
                if(++m_current_strm >= m_istrms.size()) break;
            }
            return tmp;
        }

        int_type uflow() {
            if (m_current_strm >= m_istrms.size()) return std::streambuf::uflow();
            int_type tmp;
            while( (tmp = m_istrms[m_current_strm]->rdbuf()->sbumpc()) == traits_type::eof() ) {
                if(++m_current_strm >= m_istrms.size()) break;
            }
            return tmp;
        }

        const std::vector<std::istream*>& m_istrms;
        size_t m_current_strm;
    };

    class IStreamConcatenator : private StreambufConcatenator, public std::istream
    {
    public:
        IStreamConcatenator(const std::vector<std::istream*>& istrms)
            : m_istrms(istrms), StreambufConcatenator(m_istrms),
              std::istream((StreambufConcatenator*)this), std::ios(0) {}

        IStreamConcatenator(std::istream& istrm)
            : m_istrms(1, &istrm), StreambufConcatenator(m_istrms),
              std::istream((StreambufConcatenator*)this), std::ios(0) {}

        IStreamConcatenator(std::istream& istrm0, std::istream& istrm1)
            : m_istrms(1, &istrm0), StreambufConcatenator(m_istrms),
              std::istream((StreambufConcatenator*)this), std::ios(0) { append(istrm1); }

        append(std::istream& istrm) { m_istrms.push_back(&istrm); }

    private:
        std::vector<std::istream*> m_istrms;
    };

} // end anonymous namspace

namespace LimeCrypt {

struct PrivateKey::PrivateKeyImpl : public CCKeyImpl<CryptoPP::RSA::PrivateKey>
{
    template <typename Type>
    bool sign(std::istream& in, std::ostream& out, bool putMessage) const
    {
        try {
            if (!isValid()) throw CryptoPP::Exception(CryptoPP::Exception::INVALID_DATA_FORMAT, "Invalid key." );
            Type signer(key);
            CryptoPP::AutoSeededRandomPool rng;
            CryptoPP::FileSource(in, true,
                new CryptoPP::SignerFilter(rng, signer,
                    new CryptoPP::FileSink( out ),
                    putMessage
                )
            );
            return true;
        }
        catch (CryptoPP::Exception& e) {
            handleError(std::string("Sign data: ") + e.what());
        }
        return false;
    }

    template<typename SrcType, typename SinkType, typename SrcArg, typename SinkArg>
    bool decrypt(SrcArg& in, SinkArg& out)
    {
        try {
            if (!isValid()) throw CryptoPP::Exception(CryptoPP::Exception::INVALID_DATA_FORMAT, "Invalid key." );
            CryptoPP::AutoSeededRandomPool rng;
            RSAES_Decryptor d(key);
            SrcType( in, true,
                new CryptoPP::PK_DecryptorFilter( rng, d,
                    new SinkType( out )
                ) // PK_DecryptorFilter
             ); // SrcType
            return true;
        }
        catch (CryptoPP::Exception& e) {
            handleError(std::string("Decrypt data (private key): ") + e.what());
        }
        return false;
    }
};

struct PublicKey::PublicKeyImpl : public CCKeyImpl<CryptoPP::RSA::PublicKey>
{
    template <typename Type>
    bool verify(std::istream& in, std::ostream& out, bool putMessage = true) const
    {
        int additionalFlags = putMessage ? CryptoPP::VerifierFilter::PUT_MESSAGE : 0;
        try {
            CryptoPP::BufferedTransformation *attachment =
                    putMessage ? new CryptoPP::FileSink(out) : NULL;

            Type verifier(key);
            CryptoPP::FileSource(in, true,
                new CryptoPP::SignatureVerificationFilter( verifier,
                    attachment,
                    CryptoPP::VerifierFilter::THROW_EXCEPTION
                    | CryptoPP::VerifierFilter::SIGNATURE_AT_END
                    | additionalFlags
               )
            );
            return true;
        }
        catch (CryptoPP::Exception& e) {
            handleError(std::string("Verify data: ") + e.what());
        }
        return false;
    }

    template <typename Type>
    bool verify(std::istream& in) const
    {
        std::ostringstream out;
        return verify<Type>(in, out, false);
    }

    template<typename SrcType, typename SinkType, typename SrcArg, typename SinkArg>
    bool encrypt(SrcArg& in, SinkArg& out)
    {
        try {
            if (!isValid()) throw CryptoPP::Exception(CryptoPP::Exception::INVALID_DATA_FORMAT, "Invalid key." );
            CryptoPP::AutoSeededRandomPool rng;
            RSAES_Encryptor e(key);
            SrcType( in, true,
                new CryptoPP::PK_EncryptorFilter( rng, e,
                    new SinkType( out )
               ) // PK_EncryptorFilter
            ); // SrcType
            return true;
        }
        catch (CryptoPP::Exception& e) {
            handleError(std::string("Encrypt data (public key): ") + e.what());
        }
        return false;
    }
};

PrivateKey::PrivateKey() : IKey(), _impl(new PrivateKeyImpl)
{
}

PrivateKey::PrivateKey(const PrivateKey& other)
    : IKey(), _impl(new PrivateKeyImpl(*other._impl))
{
}

PrivateKey::~PrivateKey()
{
}

PrivateKey& PrivateKey::operator=(const PrivateKey& rhs)
{
    *_impl = *rhs._impl;
}

bool PrivateKey::isValid() const
{
    return _impl->isValid();
}

bool PrivateKey::save(const std::string &filename) const
{
    return _impl->saveKeyFileBase64(filename);
}

bool PrivateKey::load(const std::string &filename)
{
    return _impl->loadKeyBase64<CryptoPP::FileSource>(filename);
}

bool PrivateKey::create(unsigned int keySizeBit)
{
    _impl->reset();
    try {
        CryptoPP::AutoSeededRandomPool rng;
        _impl->key.GenerateRandomWithKeySize(rng, keySizeBit);
        _impl->validate();
    }
    catch (CryptoPP::Exception& e) {
        handleError(std::string("Create key pair: ") + e.what());
    }
    return isValid();
}

bool PrivateKey::signWithAppendix(std::istream& in, std::string& signatureOut) const
{
    std::ostringstream oss;
    if(!_impl->sign<RSA_Appendix_Signer>(in, oss, false)) return false;
    signatureOut = oss.str();
    return true;
}

bool PrivateKey::signWithAppendix(std::istream& in, std::ostream& out) const
{
    return _impl->sign<RSA_Appendix_Signer>(in, out, true);
}

bool PrivateKey::signWithRecovery(std::istream& in, std::ostream& out) const
{
    return _impl->sign<RSA_Revovery_Signer>(in, out, true);
}

bool PrivateKey::decrypt(std::istream &dataIn, std::ostream& dataOut) const
{
    return _impl->decrypt<CryptoPP::FileSource, CryptoPP::FileSink>(dataIn, dataOut);
}

bool PrivateKey::decrypt(std::string &dataInOut) const
{
    std::string plainText;
    if (!_impl->decrypt<CryptoPP::StringSource, CryptoPP::StringSink>(dataInOut, plainText))
        return false;
    dataInOut.swap(plainText);
    return true;
}

PublicKey::PublicKey() : IKey(), _impl(new PublicKeyImpl)
{
}

PublicKey::PublicKey(const PublicKey& other)
    : IKey(), _impl(new PublicKeyImpl(*other._impl))
{
}

PublicKey::PublicKey(const PrivateKey& privateKey)
    : IKey(), _impl(new PublicKeyImpl)
{
    assignFrom(privateKey);
}

PublicKey::~PublicKey()
{
}

PublicKey& PublicKey::operator=(const PublicKey& rhs)
{
    *_impl = *rhs._impl;
}

bool PublicKey::isValid() const
{
    return _impl->isValid();
}

bool PublicKey::save(const std::string& filename) const
{
    return _impl->saveKeyFileBase64(filename);
}

bool PublicKey::load(const std::string& filename)
{
    return _impl->loadKeyBase64<CryptoPP::FileSource>(filename);
}

bool PublicKey::assignFrom(const PrivateKey& privateKey)
{
    _impl->reset();
    try {
        _impl->key.AssignFrom(privateKey._impl->key);
        _impl->validate();
    }
    catch (CryptoPP::Exception& e) {
        handleError(std::string("Create public key from private key: ") + e.what());
    }
    return isValid();
}

bool PublicKey::verifyWithAppendix(std::istream& dataIn, const std::string& signatureIn) const
{
    std::istringstream iss_sig(signatureIn);
    IStreamConcatenator dataWithSignature(dataIn,iss_sig);
    return _impl->verify<RSA_Appendix_Verifier>(dataWithSignature);
}

bool PublicKey::verifyWithAppendix(std::istream& dataIn, std::ostream& dataOut) const
{
    return _impl->verify<RSA_Appendix_Verifier>(dataIn, dataOut);
}

bool PublicKey::verifyWithRecovery(std::istream& dataIn) const
{
    return _impl->verify<RSA_Recovery_Verifier>(dataIn);
}

bool PublicKey::verifyWithRecovery(std::istream& dataIn, std::ostream& dataOut) const
{
    return _impl->verify<RSA_Recovery_Verifier>(dataIn, dataOut);
}

bool PublicKey::encrypt(std::string& dataInOut) const
{
    std::string cipherText;
    if (!_impl->encrypt<CryptoPP::StringSource, CryptoPP::StringSink>(dataInOut, cipherText))
        return false;
    dataInOut.swap(cipherText);
    return true;
}

bool PublicKey::encrypt(std::istream& dataIn, std::ostream& dataOut) const
{
    return _impl->encrypt<CryptoPP::FileSource, CryptoPP::FileSink>(dataIn, dataOut);
}

unsigned int PublicKey::maxPlainTextSize() const
{
    try {
        if (!isValid()) throw CryptoPP::Exception(CryptoPP::Exception::INVALID_DATA_FORMAT, "Invalid key." );
        return RSAES_Encryptor(_impl->key).FixedMaxPlaintextLength();
    }
    catch (CryptoPP::Exception& e) {
        handleError(std::string("maxPlainTextSize (pubkey): ") + e.what());
    }
    return 0;
}

} // end namespace LimeCrypt
