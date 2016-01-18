#include <gtest/gtest.h>
#include <lcpubkey.h>
#include <fstream>
#include <sstream>

using namespace LimeCrypt;

class RSA : public testing::Test
{
    virtual void SetUp() {
        ASSERT_TRUE(privKey.create(2048));
        ASSERT_TRUE(privKey3072.create(3072));
        ASSERT_TRUE(pubKey.assignFrom(privKey));
        ASSERT_TRUE(pubKey3072.assignFrom(privKey3072));
        privateKeyFile.assign("rsatest.private.key");
        publicKeyFile.assign("rsatest.public.key");
        privateKeyFile3072.assign("rsatest.private.3072.key");
        publicKeyFile3072.assign("rsatest.public.3072.key");
        short_message.assign("This is just a test message.");
        long_message.assign("This message has exactly 256 bytes including this notice. __" \
                            "012345678901234567890123456789012345678901234567890123456789" \
                            "012345678901234567890123456789012345678901234567890123456789" \
                            "012345678901234567890123456789012345678901234567890123456789" \
                            "0123456789ABCDEF");
        ASSERT_TRUE(privKey.save(privateKeyFile));
        ASSERT_TRUE(pubKey.save(publicKeyFile));
        ASSERT_TRUE(privKey3072.save(privateKeyFile3072));
        ASSERT_TRUE(pubKey3072.save(publicKeyFile3072));
    }

protected:
    PrivateKey privKey, privKey3072;
    PublicKey pubKey, pubKey3072;
    std::string privateKeyFile, privateKeyFile3072;
    std::string publicKeyFile, publicKeyFile3072;
    std::string short_message;
    std::string long_message;

    bool fileExists(const std::string& filename) const
    {
        std::ifstream ifile(filename.c_str());
        return ifile;
    }

    // for testing signWithAppendix with first version
    //   -- generating the message+the appendix signature to the output stream...
    void signAppendixSig0(const std::string& message, const PrivateKey& key, std::string& output, bool expect_true = true) const
    {
        std::stringstream in(message), out;
        if (expect_true)
            ASSERT_TRUE(key.signWithAppendix(in,out));
        else
            ASSERT_FALSE(key.signWithAppendix(in,out));
        output = out.str();
    }

    // for testing signWithAppendix with second version
    //  -- generating only the appendix signature in the output string.
    void signAppendixSig1(const std::string& message, const PrivateKey& key, std::string& output, bool expect_true = true) const
    {
        std::stringstream in(message);
        output.clear();
        if (expect_true)
            ASSERT_TRUE(key.signWithAppendix(in, output));
        else
            ASSERT_FALSE(key.signWithAppendix(in, output));
    }

    // for testing verifyWithAppendix, first version
    void verifyAppendixSig0(const std::string& msg_and_signature, const PublicKey& key, std::string& output, bool expect_true = true)
    {
        std::stringstream in(msg_and_signature), out;
        if (expect_true)
            ASSERT_TRUE(key.verifyWithAppendix(in,out));
        else
            ASSERT_FALSE(key.verifyWithAppendix(in,out));
        output = out.str();
    }

    // for testing verifyWithAppendix, second version, with empty signature input
    void verifyAppendixSig1a(const std::string& msg_and_signature, const PublicKey& key, bool expect_true = true)
    {
        std::stringstream in(msg_and_signature);
        if (expect_true)
            ASSERT_TRUE(key.verifyWithAppendix(in));
        else
            ASSERT_FALSE(key.verifyWithAppendix(in));
    }

    // for testing verifyWithAppendix, second version, with seperate signature input
    void verifyAppendixSig1b(const std::string& msg, const PublicKey& key, const std::string& signature, bool expect_true = true)
    {
        std::stringstream in(msg);
        if (expect_true)
            ASSERT_TRUE(key.verifyWithAppendix(in, signature));
        else
            ASSERT_FALSE(key.verifyWithAppendix(in, signature));
    }

    void appendixSuite(unsigned int keySize, const PrivateKey& privateKey, const PublicKey& publicKey, const std::string& msg)
    {
        std::string signedWithAppendix, appendixSignature, verifyOutput;
        signAppendixSig0(msg, privateKey, signedWithAppendix);
        signAppendixSig1(msg, privateKey, appendixSignature);
        ASSERT_EQ(signedWithAppendix.size(), msg.size() + keySize/8);
        ASSERT_EQ(appendixSignature.size(), keySize/8);
        ASSERT_EQ(msg+appendixSignature, signedWithAppendix);
        verifyAppendixSig0(signedWithAppendix, publicKey, verifyOutput);
        ASSERT_EQ(msg, verifyOutput);
        verifyAppendixSig1a(signedWithAppendix, publicKey);
        verifyAppendixSig1b(msg, publicKey, appendixSignature);
    }

    void signRecoverySig0(const std::string& msg, const PrivateKey& key, std::string& output, bool expect_true = true)
    {
        std::stringstream in(msg), out;
        if (expect_true)
            ASSERT_TRUE(key.signWithRecovery(in, out));
        else
            ASSERT_FALSE(key.signWithRecovery(in, out));
        output = out.str();
    }

    void verifyRecoverySig0(const std::string& msg, const PublicKey& key, std::string& output, bool expect_true = true)
    {
        std::stringstream in(msg), out;
        if (expect_true)
            ASSERT_TRUE(key.verifyWithRecovery(in, out));
        else
            ASSERT_FALSE(key.verifyWithRecovery(in, out));
        output = out.str();
    }

    void verifyRecoverySig1(const std::string& msg, const PublicKey& key, bool expect_true = true)
    {
        std::stringstream in(msg);
        if (expect_true)
            ASSERT_TRUE(key.verifyWithRecovery(in));
        else
            ASSERT_FALSE(key.verifyWithRecovery(in));
    }

    void recoverySuite(unsigned int keySize, const PrivateKey& privateKey, const PublicKey& publicKey, const std::string& msg)
    {
        std::string signedWithRecovery, verifyOutput;
        signRecoverySig0(msg, privateKey, signedWithRecovery);
        ASSERT_EQ(privateKey.maxRecoverableLength(), (keySize/8) - 66);

        unsigned int maxRecLength = privateKey.maxRecoverableLength();
        ASSERT_EQ(signedWithRecovery.size(),
                  (maxRecLength < msg.size()) ? msg.size() - maxRecLength + keySize/8 : keySize/8);

        verifyRecoverySig1(signedWithRecovery, publicKey);
        verifyRecoverySig0(signedWithRecovery, publicKey, verifyOutput);
        ASSERT_EQ(msg, verifyOutput);

        verifyRecoverySig1(signedWithRecovery+"0", publicKey, false);
        verifyRecoverySig0(signedWithRecovery+"2", publicKey, verifyOutput, false);
    }

    void encryptSig0(const std::string& msg, const PublicKey& key, std::string& output, bool expect_true = true)
    {
        std::stringstream in(msg), out;
        if (expect_true)
            ASSERT_TRUE(key.encrypt(in, out));
        else
            ASSERT_FALSE(key.encrypt(in, out));
        output = out.str();
    }

    void encryptSig1(std::string& msg_io, const PublicKey& key, bool expect_true = true)
    {
        if (expect_true)
            ASSERT_TRUE(key.encrypt(msg_io));
        else
            ASSERT_FALSE(key.encrypt(msg_io));
    }

    void decryptSig0(const std::string& msg, const PrivateKey& key, std::string& output, bool expect_true = true)
    {
        std::stringstream in(msg), out;
        if (expect_true)
            ASSERT_TRUE(key.decrypt(in, out));
        else
            ASSERT_FALSE(key.decrypt(in, out));
        output = out.str();
    }

    void decryptSig1(std::string& msg_io, const PrivateKey& key, bool expect_true = true)
    {
        if (expect_true)
            ASSERT_TRUE(key.decrypt(msg_io));
        else
            ASSERT_FALSE(key.decrypt(msg_io));
    }

    void encryptSuite(unsigned int keySize, const PrivateKey& privateKey, const PublicKey& publicKey, const std::string& msg)
    {
        std::string encrypted, decrypted, inout;
        ASSERT_EQ(publicKey.maxPlainTextLength(), (keySize/8) - 66);
        if (msg.size() > publicKey.maxPlainTextLength()) {
            encryptSig0(msg, publicKey, encrypted, false);
        }
        else {
            inout = msg;
            encryptSig0(msg, publicKey, encrypted, true);
            encryptSig1(inout, publicKey, true);
            ASSERT_EQ(inout.size(), encrypted.size());
            decryptSig0(encrypted, privateKey, decrypted, true);
            decryptSig1(inout, privateKey, true);
            ASSERT_EQ(inout, decrypted);
            ASSERT_EQ(decrypted, msg);
        }
    }
};

TEST(RSA0, KeyCreationAndComparison)
{
    // Test key creation
    PrivateKey privKey;
    PublicKey pubKey, pubKey2(privKey);
    ASSERT_FALSE(privKey.isValid());
    ASSERT_TRUE(privKey.create());
    ASSERT_TRUE(privKey.isValid());

    // Test public key assignment from private key
    ASSERT_FALSE(pubKey.isValid());
    ASSERT_FALSE(pubKey2.isValid());
    ASSERT_TRUE(pubKey.assignFrom(privKey));
    ASSERT_TRUE(pubKey2.assignFrom(privKey));

    PublicKey pubKey3(privKey);
    ASSERT_TRUE(pubKey3.isValid());

    // Test key comparison
    ASSERT_EQ(pubKey, pubKey2);
    ASSERT_EQ(pubKey2, pubKey3);
    PrivateKey privKeyB;
    ASSERT_TRUE(privKeyB.create());
    PublicKey pubKeyB;
    ASSERT_NE(pubKeyB, pubKey);
    ASSERT_TRUE(pubKeyB.assignFrom(privKeyB));
    ASSERT_NE(pubKeyB, pubKey2);
}

TEST_F(RSA, SavingAndLoading)
{
    // Saving already tested inside Fixture setup... only test loading
    ASSERT_TRUE(fileExists(privateKeyFile));
    ASSERT_TRUE(fileExists(publicKeyFile));
    ASSERT_TRUE(fileExists(privateKeyFile3072));
    ASSERT_TRUE(fileExists(publicKeyFile3072));
    PrivateKey privKey_copy, privKey3072_copy;
    PublicKey pubKey_copy, pubKey3072_copy;
    // Load keys from disk and compare
    ASSERT_TRUE(privKey_copy.load(privateKeyFile));
    ASSERT_TRUE(pubKey_copy.load(publicKeyFile));
    ASSERT_TRUE(privKey3072_copy.load(privateKeyFile3072));
    ASSERT_TRUE(pubKey3072_copy.load(publicKeyFile3072));
    ASSERT_EQ(privKey, privKey_copy);
    ASSERT_EQ(pubKey, pubKey_copy);
    ASSERT_EQ(privKey3072, privKey3072_copy);
    ASSERT_EQ(pubKey3072, pubKey3072_copy);
}

TEST_F(RSA, SignAndVerifyAppendix)
{
    PrivateKey invalidKey;
    std::string signedMsg, temp;
    // Test signing with an invalid key
    signAppendixSig0(short_message, invalidKey, signedMsg, false);

    // Run several tests with a pivate, public key pair
    appendixSuite(2048, privKey, pubKey, short_message);
    appendixSuite(2048, privKey, pubKey, long_message);
    appendixSuite(3072, privKey3072, pubKey3072, short_message);
    appendixSuite(3072, privKey3072, pubKey3072, long_message);
    // Run tests where we expect the verification to fail
    signAppendixSig0(long_message, privKey, signedMsg);
    verifyAppendixSig0(signedMsg, pubKey, temp, true);
    verifyAppendixSig0(long_message, pubKey, temp, false);
    verifyAppendixSig0(short_message, pubKey, temp, false);
    verifyAppendixSig0(signedMsg, pubKey3072, temp, false);
    verifyAppendixSig1a(signedMsg, pubKey3072, false);
}

TEST_F(RSA, SignAndVerifyRecovery)
{
    PrivateKey invalidKey;
    std::string signedMsg, temp;
    // Test signing with an invalid key
    signRecoverySig0(short_message, invalidKey, signedMsg, false);

    std::string another_msg(privKey.maxRecoverableLength(), 'A');

    // Run several tests with a pivate, public key pair
    recoverySuite(2048, privKey, pubKey, short_message);
    recoverySuite(2048, privKey, pubKey, long_message);
    recoverySuite(2048, privKey, pubKey, another_msg);
    recoverySuite(2048, privKey, pubKey, another_msg + "B");
    recoverySuite(3072, privKey3072, pubKey3072, short_message);
    recoverySuite(3072, privKey3072, pubKey3072, long_message);
    // Run tests where we expect the verification to fail
    signAppendixSig0(long_message, privKey, signedMsg);
    verifyAppendixSig0(signedMsg, pubKey, temp, true);
    verifyAppendixSig0(long_message, pubKey, temp, false);
    verifyAppendixSig0(short_message, pubKey, temp, false);
    verifyAppendixSig0(signedMsg, pubKey3072, temp, false);
    verifyAppendixSig1a(signedMsg, pubKey3072, false);
}

TEST_F(RSA, EncryptAndDecrypt)
{
    PrivateKey invalidKey;
    std::string encrypted, temp(short_message);
    // Test ecnrypting with an invalid key
    encryptSig0(short_message, invalidKey, encrypted, false);
    encryptSig1(temp, invalidKey, false);

    std::string maxPlainMsg(pubKey.maxPlainTextLength(), 'A');
    encryptSuite(2048, privKey, pubKey, short_message);
    encryptSuite(2048, privKey, pubKey, maxPlainMsg);
    encryptSuite(2048, privKey, pubKey, maxPlainMsg+"B");
    encryptSuite(3072, privKey3072, pubKey3072, short_message);
    encryptSuite(3072, privKey3072, pubKey3072, long_message);
    std::string maxPlainMsg3072(pubKey3072.maxPlainTextLength(), 'A');
    encryptSuite(3072, privKey3072, pubKey3072, maxPlainMsg3072);
    encryptSuite(3072, privKey3072, pubKey3072, maxPlainMsg3072+"B");
}
