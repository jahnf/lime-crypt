#include <string>

namespace LimeCrypt {

enum ErrorHandling
{
    BOOLEAN_RETURN,     ///!< Only return true or false, this is the default.
    STDERR_OUT,         ///!< Print error message to stderr and return boolean.
    THROW_EXCEPTION,    ///!< Throw a LimeCrypt::Exception that contains a detailed error message.
};

/// Set global LimeCrypt error handling.
void errorHandling(ErrorHandling eh);

/// Get global LimeCrypt error handling.
ErrorHandling errorHandling();

/// LimeCrypt Exception class.
class Exception : public std::exception
{
public:
    Exception(const std::string& msg);
    virtual ~Exception() throw();
    const char *what() const throw();
    const std::string &GetWhat() const;
    void SetWhat(const std::string &s);
private:
    std::string m_what;
};

} // end namespace LimeCrypt
