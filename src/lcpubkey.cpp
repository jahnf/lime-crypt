#include <lcpubkey.h>
#include "limecrypt_p.h"

#include <sstream>
#include <iostream>

// Crypto++ includes
#include "crypto++/rsa.h"
#include "crypto++/osrng.h"     // AutoSeededRandomPool
#include "crypto++/files.h"
#include "crypto++/base64.h"
#include "crypto++/pssr.h"
#include "crypto++/fltrimpl.h"

namespace {
    // local typedefs
    typedef CryptoPP::RSAES<CryptoPP::OAEP<CryptoPP::SHA256> >::Decryptor RSAES_Decryptor;
    typedef CryptoPP::RSAES<CryptoPP::OAEP<CryptoPP::SHA256> >::Encryptor RSAES_Encryptor;

    typedef CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Signer RSA_Appendix_Signer;
    typedef CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Verifier RSA_Appendix_Verifier;

    typedef CryptoPP::RSASS<CryptoPP::PSSR, CryptoPP::SHA256>::Signer RSA_Recovery_Signer;
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
                CryptoPP::Base64Encoder encoder(new CryptoPP::FileSink(filename.c_str()));
                key.Save(encoder);
                encoder.MessageEnd();
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
                CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(keyOut));
                key.Save(encoder);
                encoder.MessageEnd();
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

        void append(std::istream& istrm) { m_istrms.push_back(&istrm); }

    private:
        std::vector<std::istream*> m_istrms;
    };

} // end anonymous namspace

namespace LimeCrypt {

typedef CryptoPP::SignatureVerificationFilter AppendixVerifyFilter;
typedef CryptoPP::SignerFilter AppendixSignerFilter;

class RecoveryVerifyFilter : public CryptoPP::Unflushable<CryptoPP::Filter>
{
public:
    RecoveryVerifyFilter(const CryptoPP::PK_Verifier &verifier,
                         BufferedTransformation *attachment = NULL,
                         CryptoPP::word32 flags = AppendixVerifyFilter::PUT_MESSAGE)
        : m_verifier(verifier), m_messageAccumulator(verifier.NewVerificationAccumulator()),
          m_putMessage(flags & AppendixVerifyFilter::PUT_MESSAGE),
          m_buf(verifier.MaxSignatureLength()), m_streambufLength(0),
          m_signatureLength(verifier.MaxSignatureLength()) {Detach(attachment);}

    std::string AlgorithmName() const {return m_verifier.AlgorithmName();}

    size_t Put2(const byte *begin, size_t length, int messageEnd, bool blocking) {
        using namespace CryptoPP;
        size_t readlen;
        FILTER_BEGIN;
        m_streambuf.write((std::stringstream::char_type*)begin,length);
        m_streambufLength += length;
        while (m_streambufLength > m_signatureLength) {
            readlen = std::min(m_streambufLength - m_signatureLength, m_buf.size());
            m_streambuf.read((std::stringstream::char_type*)(byte*)m_buf, readlen);
            m_messageAccumulator->Update(m_buf, readlen);
            if (m_putMessage)
                FILTER_OUTPUT(1, m_buf, readlen, 0);
            m_streambufLength -= readlen;
        }
        if (messageEnd)
        {
            if (m_streambufLength != m_signatureLength)
                throw AppendixVerifyFilter::SignatureVerificationFailed();

            m_streambuf.read((std::stringstream::char_type*)(byte*)m_buf, m_streambufLength);
            m_verifier.InputSignature(*m_messageAccumulator, m_buf, m_streambufLength);
            m_decodingResult = m_verifier.RecoverAndRestart(m_buf, *m_messageAccumulator);

            if (!m_decodingResult.isValidCoding)
                throw AppendixVerifyFilter::SignatureVerificationFailed();

            if (m_putMessage)
                FILTER_OUTPUT(2, m_buf, m_decodingResult.messageLength, messageEnd);

            m_messageAccumulator.reset(m_verifier.NewVerificationAccumulator());
        }
        FILTER_END_NO_MESSAGE_END;
    }

private:
    const CryptoPP::PK_Verifier &m_verifier;
    IKey::Pointer<CryptoPP::PK_MessageAccumulator>::Type m_messageAccumulator;
    const bool m_putMessage;
    CryptoPP::SecByteBlock m_buf;
    CryptoPP::DecodingResult m_decodingResult;
    std::stringstream m_streambuf;
    size_t m_streambufLength;
    const size_t m_signatureLength;
};

class RecoverySignerFilter : public CryptoPP::Unflushable<CryptoPP::Filter>
{
public:
    RecoverySignerFilter(CryptoPP::RandomNumberGenerator &rng,
                         const CryptoPP::PK_Signer &signer,
                         BufferedTransformation *attachment = NULL, bool putMessage=false)
        : m_rng(rng), m_signer(signer), m_messageAccumulator(signer.NewSignatureAccumulator(rng)),
          m_putMessage(putMessage), m_buf(signer.MaxSignatureLength()), m_streambufLength(0),
          m_recoverableLength(signer.MaxRecoverableLength()) {Detach(attachment);}

    std::string AlgorithmName() const {return m_signer.AlgorithmName();}

    size_t Put2(const byte *begin, size_t length, int messageEnd, bool blocking) {
        using namespace CryptoPP;
        size_t readlen;
        FILTER_BEGIN;
        m_streambuf.write((std::stringstream::char_type*)begin,length);
        m_streambufLength += length;
        while (m_streambufLength > m_recoverableLength) {
            readlen = std::min(m_streambufLength - m_recoverableLength, m_buf.size());
            m_streambuf.read((std::stringstream::char_type*)(byte*)m_buf, readlen);
            m_messageAccumulator->Update(m_buf, readlen);
            if (m_putMessage)
                FILTER_OUTPUT(1, m_buf, readlen, 0);
            m_streambufLength -= readlen;
        }
        if (messageEnd)
        {
            // The remaining bytes (with a maximum of m_recoverableLength will be put into
            // the signature as recoverable part.
            m_streambuf.read((std::stringstream::char_type*)(byte*)m_buf, m_streambufLength);
            m_signer.InputRecoverableMessage(*m_messageAccumulator,m_buf,m_streambufLength);
            m_signer.Sign(m_rng, m_messageAccumulator.release(), m_buf);
            FILTER_OUTPUT(2, m_buf, m_signer.SignatureLength(), messageEnd);
            m_messageAccumulator.reset(m_signer.NewSignatureAccumulator(m_rng));
        }
        FILTER_END_NO_MESSAGE_END;
    }

private:
    CryptoPP::RandomNumberGenerator &m_rng;
    const CryptoPP::PK_Signer &m_signer;
    IKey::Pointer<CryptoPP::PK_MessageAccumulator>::Type m_messageAccumulator;
    const bool m_putMessage;
    CryptoPP::SecByteBlock m_buf;
    std::stringstream m_streambuf;
    size_t m_streambufLength;
    const size_t m_recoverableLength;
};

struct PrivateKey::PrivateKeyImpl : public CCKeyImpl<CryptoPP::RSA::PrivateKey>
{
    template <typename Type, typename FilterType>
    bool sign(std::istream& in, std::ostream& out, bool putMessage) const
    {
        try {
            if (!isValid()) throw CryptoPP::Exception(CryptoPP::Exception::INVALID_DATA_FORMAT, "Invalid key." );
            Type signer(key);
            CryptoPP::AutoSeededRandomPool rng;
            CryptoPP::FileSource(in, true,
                new FilterType(rng, signer,
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
    template <typename Type, typename FilterType>
    bool verify(std::istream& in, std::ostream& out, bool putMessage = true) const
    {
        CryptoPP::word32 additionalFlags = putMessage ? AppendixVerifyFilter::PUT_MESSAGE : 0;
        try {
            CryptoPP::BufferedTransformation *attachment =
                    putMessage ? new CryptoPP::FileSink(out) : NULL;

            Type verifier(key);
            CryptoPP::FileSource(in, true,
                new FilterType( verifier,
                    attachment,
                    CryptoPP::VerifierFilter::THROW_EXCEPTION
                    //| CryptoPP::VerifierFilter::SIGNATURE_AT_END
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

    template <typename Type, typename FilterType>
    bool verify(std::istream& in) const
    {
        std::ostringstream out;
        return verify<Type, FilterType>(in, out, false);
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
    if(!_impl->sign<RSA_Appendix_Signer, AppendixSignerFilter>(in, oss, false)) return false;
    signatureOut = oss.str();
    return true;
}

bool PrivateKey::signWithAppendix(std::istream& in, std::ostream& out) const
{
    return _impl->sign<RSA_Appendix_Signer, AppendixSignerFilter>(in, out, true);
}

bool PrivateKey::signWithRecovery(std::istream& in, std::ostream& out) const
{
    return _impl->sign<RSA_Recovery_Signer, RecoverySignerFilter>(in, out, true);
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
    return _impl->verify<RSA_Appendix_Verifier, AppendixVerifyFilter>(dataWithSignature);
}

bool PublicKey::verifyWithAppendix(std::istream& dataIn, std::ostream& dataOut) const
{
    return _impl->verify<RSA_Appendix_Verifier, AppendixVerifyFilter>(dataIn, dataOut);
}

bool PublicKey::verifyWithRecovery(std::istream& dataIn) const
{
    return _impl->verify<RSA_Recovery_Verifier, RecoveryVerifyFilter>(dataIn);
}

bool PublicKey::verifyWithRecovery(std::istream& dataIn, std::ostream& dataOut) const
{
    return _impl->verify<RSA_Recovery_Verifier, RecoveryVerifyFilter>(dataIn, dataOut);
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
