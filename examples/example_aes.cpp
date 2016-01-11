#include <lcaes.h>
#include <lcencode.h>
#include <limecrypt.h>

#include <sstream>
#include <iostream>

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

int main(int argc, char** argv)
{
    errorHandling(STDERR_OUT);
    const std::string message("This is a totally secret message. No one should see it.");
    const std::string passphrase("t0t@lly_sEcure-Pa55W0rD_;)");

    Print("--- AES String Encryption/Decryption Example ---");
    std::string encrypted = aes_encrypt_string(message, passphrase);
    std::string decrypted = aes_decrypt_string(encrypted, passphrase);

    return 0;
}
