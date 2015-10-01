#include <limecrypt.h>
#include <iostream>

namespace LimeCrypt {

namespace {
    /// Global error handling setting.
    ErrorHandling eHandling = BOOLEAN_RETURN;
}

void errorHandling(ErrorHandling eh)
{
    eHandling = eh;
}

ErrorHandling errorHandling()
{
    return eHandling;
}

Exception::Exception(const std::string& msg) : std::exception(), m_what(msg) {}
Exception::~Exception() throw() {}
const char* Exception::what() const throw() {return (m_what.c_str());}
const std::string& Exception::GetWhat() const {return m_what;}
void Exception::SetWhat(const std::string &s) {m_what = s;}

void handleError(const std::string& msg) {
    switch(errorHandling()) {
        case STDERR_OUT:
            std::cerr << "Error: " << msg << std::endl;
            break;
        case THROW_EXCEPTION:
            throw LimeCrypt::Exception("Error: " + msg);
            break;
        case BOOLEAN_RETURN:
        default:
            break;
    }
}

} //end namespace LimeCrypt

