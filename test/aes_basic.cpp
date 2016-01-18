#include <gtest/gtest.h>
#include <lcaes.h>
#include <fstream>
#include <sstream>

using namespace LimeCrypt;

class AES_Test : public testing::Test
{
    virtual void SetUp() {
        passphrase = "t0t@lly_sEcure-Pa55W0rD_;)";
        fileToEncrypt = "PlainTextFile.txt";
        filePlainContent = "This content needs to be secured by encryption.\n"
                           "It is very important, that only people knowing the\n"
                           "passphrase and the number of iterations can see it.";

        ASSERT_TRUE(writeFile(fileToEncrypt, filePlainContent));
    }

protected:
    std::string passphrase;
    std::string fileToEncrypt;
    std::string filePlainContent;

    bool fileExists(const std::string& filename) const
    {
        std::ifstream ifile(filename.c_str());
        return ifile;
    }

    bool writeFile(const std::string& filename, const std::string& content)
    {
        {
            std::ofstream ofile(filename.c_str());
            if (!ofile) return false;
            ofile << content;
        }
        return fileExists(filename.c_str());
    }

    bool readFileToString(const std::string& filename, std::string& contentOut)
    {
        std::ifstream ifs(filename.c_str());
        if (!ifs) return false;
        std::string content((std::istreambuf_iterator<char>(ifs)),
                             std::istreambuf_iterator<char>());
        contentOut.swap(content);
        return true;
    }

    void encrypt(const std::string& pass, const std::string& plain, std::string& encrypted,
                 bool storeIterations = true, unsigned int iterations = DEFAULT_PBDFK2_ITERATIONS)
    {
        std::stringstream in(plain), out;
        ASSERT_TRUE(AES::encrypt(pass, in, out, storeIterations, iterations));
        encrypted = out.str();
    }

    void decrypt(const std::string& pass, const std::string& encrypted, std::string& decrypted,
                 bool expect_true = true,
                 bool readIterations = true, unsigned int iterations = DEFAULT_PBDFK2_ITERATIONS)
    {
        std::stringstream in(encrypted), out;
        if (expect_true)
            ASSERT_TRUE(AES::decrypt(pass, in, out, readIterations, iterations));
        else
            ASSERT_FALSE(AES::decrypt(pass, in, out, readIterations, iterations));
        decrypted = out.str();
    }

};

TEST_F(AES_Test, StreamEncryptDecrypt)
{
    std::string encrypted, decrypted;
    encrypt(passphrase, filePlainContent, encrypted);
    decrypt(passphrase, encrypted, decrypted);
    ASSERT_EQ(decrypted, filePlainContent);
    // expected to fail:
    decrypt(passphrase, encrypted, decrypted, false, false, DEFAULT_PBDFK2_ITERATIONS-1);

    encrypt(passphrase, filePlainContent, encrypted, false, DEFAULT_PBDFK2_ITERATIONS-3);
    // expected to fail
    decrypt(passphrase, encrypted, decrypted, false, false, 100);
    decrypt(passphrase+"abc", encrypted, decrypted, false, false, DEFAULT_PBDFK2_ITERATIONS-3);
    // expected to succeed
    decrypt(passphrase, encrypted, decrypted, true, false, DEFAULT_PBDFK2_ITERATIONS-3);
    ASSERT_EQ(decrypted, filePlainContent);
}

TEST_F(AES_Test, FileEncryptDecrypt)
{
    std::string content, decrypted;
    std::string encryptedFilename(fileToEncrypt+".encrypted");
    std::string decryptedFilename(fileToEncrypt+".decrypted");
    ASSERT_TRUE(readFileToString(fileToEncrypt, content));
    ASSERT_EQ(filePlainContent, content);

    ASSERT_FALSE(AES::encryptFile(passphrase, ".doesnotexist."+fileToEncrypt, encryptedFilename));
    ASSERT_TRUE(AES::encryptFile(passphrase, fileToEncrypt, encryptedFilename));
    ASSERT_TRUE(readFileToString(encryptedFilename, content));
    decrypt(passphrase, content, decrypted, true);
    ASSERT_EQ(decrypted, filePlainContent);

    ASSERT_FALSE(AES::decryptFile(passphrase+"abc", encryptedFilename, decryptedFilename));
    ASSERT_TRUE(AES::decryptFile(passphrase, encryptedFilename, decryptedFilename));
    ASSERT_TRUE(readFileToString(decryptedFilename, decrypted));
    ASSERT_EQ(decrypted, filePlainContent);
}
