#include <string>
#include <istream>
#include <ostream>

namespace LimeCrypt { namespace AES {

// On iterations, see:
// - https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet
// - http://stackoverflow.com/questions/6054082/recommended-of-iterations-when-using-pbkdf2-sha256
#define DEFAULT_PBDFK2_ITERATIONS 128000

/// Encrypt the input stream to the output stream with 256-bit AES.
/// If storeIterations is set to true, the number of iterations used is also
/// stored in the encrypted outpu stream.
bool encrypt(const std::string& password, std::istream& in, std::ostream& out,
             bool storeIterations = true,
             const unsigned int iterations = DEFAULT_PBDFK2_ITERATIONS);

/// Decrypt the input stream (previously produces by the encrypt method) to the
/// output stream. If readIteraions is true, the iteration argument is ignored.
bool decrypt(const std::string& password, std::istream& in, std::ostream& out,
             bool readIterations = true,
             const unsigned int iterations = DEFAULT_PBDFK2_ITERATIONS);

/// Wrapper method around AES::encrypt method to directly open and encrypt files.
/// Uses standard ifstream and ofstream to read and write files.
bool encryptFile(const std::string& password, const std::string& inFile,
                 const std::string& outFile, bool storeIterations = true,
                 const unsigned int iterations = DEFAULT_PBDFK2_ITERATIONS);

/// Wrapper method around AES::decrypt method to directly open and decrypt files.
/// Uses standard ifstream and ofstream to read and write files.
bool decryptFile(const std::string& password, const std::string& inFile,
                 const std::string& outFile, bool readIterations = true,
                 const unsigned int iterations = DEFAULT_PBDFK2_ITERATIONS);

}} // end namespaces LimeCrypt::AES
