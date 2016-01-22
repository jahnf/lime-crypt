#include <limecrypt.h>
#include <lcpubkey.h>
#include <lcencode.h>

#include <sstream>

// A simple print helper class
class Print  {
public:
    explicit Print() : os(std::cout) {}
    template<typename T> explicit Print(const T& input) : os(std::cout) { os << input; }
    ~Print() { os << std::endl; }
    template<typename T> std::ostream& operator<<(const T& input) { return std::cout << input; }
private:
    std::ostream& os;
};
using namespace LimeCrypt;

// RSA examples
static void rsa_example_create_and_save()
{
    // Uninitialized private key instance.
    PrivateKey privKey;

    // ..therefore the key is not valid until we load a key from file or create a new one.
    if (!privKey.isValid())
        Print("private Key is not valid().");

    // create a new random private key with default key size.
    if (privKey.create())
        Print("Created new private key.");

    // Create matching public key instance from the private key.
    PublicKey pubKey;
    if (pubKey.assignFrom(privKey))
        Print("Created Public key instance from private key");

    // Save keys to files
    privKey.save("privateKey.file");
    pubKey.save("publicKey.file");
}

static std::string rsa_example_load_and_sign_recovery(const std::string& message)
{
    PrivateKey privKey;
    privKey.load("privateKey.file");

    std::stringstream in(message), out;
    privKey.signWithRecovery(in,out);

    Print("Signed message with recovery - Hex format (") << out.str().size()
                              << " bytes): " << Hex::encode(out.str());

    return out.str();
}

static void rsa_example_load_and_verify_recovery(const std::string& signed_message)
{
    PublicKey pubKey;
    pubKey.load("publicKey.file");
    std::stringstream in(signed_message), out;
    pubKey.verifyWithRecovery(in, out);

    Print("Recovered message with recovery: ") << out.str();
}

static std::string rsa_example_load_and_sign_appendix(const std::string& message)
{
    PrivateKey privKey;
    privKey.load("privateKey.file");

    std::stringstream in(message), out;
    privKey.signWithAppendix(in,out);

    Print("Signed message with appendix - Hex format (") << out.str().size()
                              << " bytes): " << Hex::encode(out.str());

    return out.str();
}

static void rsa_example_load_and_verify_appendix(const std::string& signed_message)
{
    PublicKey pubKey;
    pubKey.load("publicKey.file");

    std::stringstream in(signed_message), out;
    pubKey.verifyWithAppendix(in, out);

    Print("Recovered message with appendix: ") << out.str();
}

static std::string rsa_example_encrypt(const std::string& message)
{
    PublicKey pubKey;
    pubKey.load("publicKey.file");

    std::stringstream in(message), out;
    if (pubKey.encrypt(in, out))
        Print("Encrypted message - Hex format (") << out.str().size()
                             << " bytes): " << Hex::encode(out.str());
    return out.str();
}

static std::string rsa_example_decrypt(const std::string& encrypted_msg)
{
    PrivateKey privKey;
    privKey.load("privateKey.file");

    std::stringstream in(encrypted_msg), out;
    if (privKey.decrypt(in, out))
        Print("Decrypted message (") << out.str().size() << " bytes): " << out.str();
    return out.str();
}

static void rsa_example_exception_error_handling()
{
    // We set the error handling to throw exceptions on error
    ErrorHandling eh = errorHandling();
    errorHandling(THROW_EXCEPTION);

    // We need to guard LimeCrypt operations with try/catch
    try {
        std::string str("teststring.");
        PublicKey pubKey; // <-- invalid pubkey
        pubKey.encrypt(str); // <-- fails, throws exception
    } catch (LimeCrypt::Exception &e) {
        Print() << e.what();
    }

    // Set error handling to the previous value
    errorHandling(eh);
}

int main(int argc, char** argv)
{
    // Our message This is a message. This is a message. Yes it's really a message!
    const std::string long_message("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefgh" \
                                   "ijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnop" \
                                   "qrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwx" \
                                   "yz0000000000000000000000000000000000000000000000000000000000" \
                                   "0123456789abdefghijklmnopqrstuvwxyz");

    const std::string short_message("my.short.message");

    Print("Long Message  (") << long_message.size() << " bytes): " << long_message;
    Print("Short Message (") << short_message.size() << " bytes): " << short_message;

    // The error handling of LimeCrypt can be configured globally:
    // BOOLEAN_RETURN  : Methods only return true or false, this is the default.
    // STDERR_OUT      : Methods return true or false and print a detailed error message to stderr.
    // THROW_EXCEPTION : Throw a LimeCrypt::Exception that contains a detailed error message.

    // For the examples we configure, the errors for boolean return value and stderr out
    errorHandling(STDERR_OUT);

    rsa_example_create_and_save();

    Print("---- Sign Message with recovery and verify (long msg) ----");
    std::string signed_message = rsa_example_load_and_sign_recovery(long_message);
    rsa_example_load_and_verify_recovery(signed_message);

    Print("---- Sign Message with recovery and verify (short msg) ----");
    signed_message = rsa_example_load_and_sign_recovery(short_message);
    rsa_example_load_and_verify_recovery(signed_message);

    Print("---- Sign Message with appendix and verify (long msg) ----");
    signed_message = rsa_example_load_and_sign_appendix(long_message);
    rsa_example_load_and_verify_appendix(signed_message);

    Print("---- Sign Message with appendix and verify (short msg) ----");
    signed_message = rsa_example_load_and_sign_appendix(short_message);
    rsa_example_load_and_verify_appendix(signed_message);

    Print("---- Encrypt & Decrypt a Message (short msg) ----");
    std::string encrypted = rsa_example_encrypt(short_message);
    /*std::string decrypted =*/ rsa_example_decrypt(encrypted);

    Print("---- Encrypt & Decrypt a Message (long msg) ----");
    Print("---- // expected to fail, because message is too long ----");
    /*encrypted =*/ rsa_example_encrypt(long_message);

    Print("---- Example: Error Handling with exceptions ----");
    rsa_example_exception_error_handling();

    return 0;
}

