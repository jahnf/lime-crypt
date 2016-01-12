#include <lcaes.h>
#include <lcencode.h>
#include <limecrypt.h>

#include <sstream>
#include <iostream>
#include <fstream>

class Print  {
public:
    Print() : os(std::cout) {}
    template<typename T> Print(const T& input) : os(std::cout) { os << input; }
    ~Print() { os << std::endl; }
    template<typename T> std::ostream& operator<<(const T& input) { return std::cout << input; }
private:
    std::ostream& os;
};

using namespace LimeCrypt;

// AES Examples
static std::string aes_encrypt_string(const std::string& message, const std::string& passphrase)
{
    std::stringstream in(message), out;
    Print("Original Message (") << message.size() << " bytes): " <<  message;
    AES::encrypt(passphrase, in, out);
    Print("Encrypted Message - Hex format (") << out.str().size()
                              << " bytes): " << Hex::encode(out.str());

    return out.str();
}

static std::string aes_decrypt_string(const std::string& encrypted, const std::string& passphrase)
{
    std::stringstream in(encrypted), out;
    AES::decrypt(passphrase, in, out);
    Print("Decrypted Message (") << out.str().size() << " bytes): " <<  out.str();
    return out.str();
}

static std::string aes_encrypt_file(const std::string& filename, const std::string& passphrase)
{
    // For this example we will first create a file
    Print("Writing file with secret content: ") << filename;
    std::ofstream of(filename.c_str());
    of << "This is a secret file content. Nobody should see it." << std::endl;
    std::string encrypted_filename(filename + ".enc");
    Print("Encrypt '") << filename << "' to '" << encrypted_filename << "'";
    AES::encryptFile(passphrase, filename, encrypted_filename);
    return encrypted_filename;
}

static void aes_decrypt_file(const std::string& filename, const std::string& passphrase)
{
    Print("Decrypt '") << filename << "' to '" << filename + ".decrypted" << "'";
    AES::decryptFile(passphrase, filename, filename + ".decrypted");
}

int main(int argc, char** argv)
{
    errorHandling(STDERR_OUT);
    const std::string message("This is a totally secret message. No one should see it.");
    const std::string passphrase("t0t@lly_sEcure-Pa55W0rD_;)");

    Print("--- AES String Encryption/Decryption Example ---");
    std::string encrypted = aes_encrypt_string(message, passphrase);
    std::string decrypted = aes_decrypt_string(encrypted, passphrase);

    Print("--- AES File Encryption/Decryption Example ---");
    std::string encrypted_filename = aes_encrypt_file("SecretFile", passphrase);
    aes_decrypt_file(encrypted_filename, passphrase);
    return 0;
}
