#include <lcaes.h>
#include "limecrypt_p.h"

#include <iostream>
#include <fstream>

// C++11 check
#if __cplusplus <= 199711L
    #include <stdint.h>
#else
    #include <cstdint>
#endif

// Crypto++ includes
#include "crypto++/gcm.h"
#include "crypto++/aes.h"
#include "crypto++/osrng.h"     // AutoSeededRandomPool
#include "crypto++/pwdbased.h"
#include "crypto++/files.h"

namespace LimeCrypt { namespace AES {

namespace {
    typedef CryptoPP::SHA256 LcAESHashFunction; // The hash function used by LimeCrypt
    static const int PBKDF_Salt_Size = CryptoPP::AES::MAX_KEYLENGTH;

    // Runtime check for endianess.
    inline bool is_big_endian(void)
    {
        static union { uint32_t i; char c[4]; } bint = {0x01020304};
        return bint.c[0] == 1;
    }

    // Swap uint32_t from little to big endian and the other way around.
    // Used to always store uint32_t in LE format to streams.
    inline void byteswap32(uint32_t &i)
    {
        i = ((i>>24)&0xff)          // move byte 3 to byte 0
            | ((i<<8)&0xff0000)     // move byte 1 to byte 2
            | ((i>>8)&0xff00)       // move byte 2 to byte 1
            | ((i<<24)&0xff000000); // byte 0 to byte 3
    }
}

bool encrypt(const std::string& password, std::istream& in, std::ostream& out,
             bool storeIterations, const unsigned int iterations)
{
    try	{
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::SecByteBlock iv_key(CryptoPP::AES::MAX_KEYLENGTH + CryptoPP::AES::BLOCKSIZE);
        CryptoPP::SecByteBlock salt(PBKDF_Salt_Size);
        rng.GenerateBlock(salt, salt.size());

        // Generate IV and key from password and salt
        CryptoPP::PKCS5_PBKDF2_HMAC<LcAESHashFunction> pbkdf;
        pbkdf.DeriveKey(
            // buffer that holds the derived key
            iv_key, iv_key.size(),
            // purpose byte. unused by this PBKDF implementation.
            0x00,
            // password bytes. careful to be consistent with encoding...
            (byte *) password.data(), password.size(),
            // salt bytes
            salt, salt.size(),
            // iteration count. See SP 800-132 for details.
            // You want this as large as you can tolerate.
            // make sure to use the same iteration count on both sides...
            (uint32_t) iterations
        );

        CryptoPP::GCM< CryptoPP::AES >::Encryption e;
        e.SetKeyWithIV(iv_key, CryptoPP::AES::MAX_KEYLENGTH, &iv_key[CryptoPP::AES::MAX_KEYLENGTH]);

        // Write salt before encrypted data
        CryptoPP::ArraySource( salt, salt.size(), true, new CryptoPP::FileSink( out ) );

        if (storeIterations) {
            uint32_t iterbytes = iterations;
            if(is_big_endian()) byteswap32(iterbytes);
            CryptoPP::ArraySource( (byte*)&iterbytes, sizeof(iterbytes), true, new CryptoPP::FileSink( out ) );
        }

        // Writ encrypted data
        CryptoPP::FileSource( in, true,
            new CryptoPP::AuthenticatedEncryptionFilter( e,
                new CryptoPP::FileSink( out )
            ) // AuthenticatedEncryptionFilter
        ); // FileSource
        return true;
    }
    catch(const CryptoPP::Exception& e)	{
        handleError(std::string("AES encrypt: ") + e.what());
    }

    return false;
}

bool decrypt(const std::string& password, std::istream& in, std::ostream& out,
             bool readIterations, const unsigned int iterations_in)
{
    try	{
        CryptoPP::SecByteBlock iv_key(CryptoPP::AES::MAX_KEYLENGTH + CryptoPP::AES::BLOCKSIZE);
        CryptoPP::SecByteBlock salt(PBKDF_Salt_Size);

        // Read in salt from beginning of input
        CryptoPP::FileSource(in, false,
            new CryptoPP::ArraySink(salt, salt.size())
        ).Pump(salt.size());

        uint32_t iterations = iterations_in;

        if (readIterations) {
            CryptoPP::FileSource(in, false,
                new CryptoPP::ArraySink((byte*)&iterations, 4)
            ).Pump(sizeof(iterations));
            if(is_big_endian()) byteswap32(iterations);
        }

        CryptoPP::PKCS5_PBKDF2_HMAC<LcAESHashFunction> pbkdf;
        pbkdf.DeriveKey(
            // buffer that holds the derived key
            iv_key, iv_key.size(),
            // purpose byte. unused by this PBKDF implementation.
            0x00,
            // password bytes. careful to be consistent with encoding...
            (byte *) password.data(), password.size(),
            // salt bytes
            salt, salt.size(),
            // iteration count. See SP 800-132 for details.
            // You want this as large as you can tolerate.
            // make sure to use the same iteration count on both sides...
            iterations
        );

        CryptoPP::GCM< CryptoPP::AES >::Decryption d;
        d.SetKeyWithIV(iv_key, CryptoPP::AES::MAX_KEYLENGTH, &iv_key[CryptoPP::AES::MAX_KEYLENGTH]);

        CryptoPP::FileSource( in, true,
            new CryptoPP::AuthenticatedDecryptionFilter( d,
                new CryptoPP::FileSink( out )
            ) // AuthenticatedDecryptionFilter
        ); // FileSource
        return true;
    }
    catch(const CryptoPP::Exception& e)	{
        handleError(std::string("AES decrypt: ") + e.what());
    }
    return false;
}

bool encryptFile(const std::string& password, const std::string& inFile,
                 const std::string& outFile, bool storeIterations,
                 const unsigned int iterations)
{
    std::ifstream ifs(inFile.c_str(), std::ios_base::in | std::ios_base::binary);
    if(!ifs.is_open()) {
        handleError("EncryptFile: inFile: Could not open " + inFile);
        return false;
    }

    std::ofstream ofs(outFile.c_str(), std::ios_base::out | std::ios_base::binary);
    if(!ofs.is_open()) {
        handleError("EncryptFile: outFile: Could not open " + outFile);
        return false;
    }

    return encrypt(password, ifs, ofs, storeIterations, iterations);
}

bool decryptFile(const std::string& password, const std::string& inFile,
                 const std::string& outFile, bool readIterations,
                 const unsigned int iterations)
{
    std::ifstream ifs(inFile.c_str(), std::ios_base::in | std::ios_base::binary);
    if(!ifs.is_open()) {
        LimeCrypt::handleError("DecryptFile: inFile: Could not open " + inFile);
        return false;
    }

    std::ofstream ofs(outFile.c_str(), std::ios_base::out | std::ios_base::binary);
    if(!ofs.is_open()) {
        handleError("DecryptFile: outFile: Could not open " + outFile);
        return false;
    }

    return decrypt(password, ifs, ofs, readIterations, iterations);
}

}} //end namespaces LimeCrypt::AES
