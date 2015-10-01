#include <string>
#include <istream>
#include <ostream>

namespace LimeCrypt {

namespace Hex {

bool encode(std::istream& in, std::ostream& out,
            bool uppercase=true,
            int outputGroupSize=0,
            const std::string& separator=":",
            const std::string& terminator="");

bool encode(std::istream& in, std::string& out,
            bool uppercase=true,
            int outputGroupSize=0,
            const std::string& separator=":",
            const std::string& terminator="");

bool encode(const std::string& in, std::ostream& out,
            bool uppercase=true,
            int outputGroupSize=0,
            const std::string& separator=":",
            const std::string& terminator="");

bool encode(const std::string& in, std::string& out,
            bool uppercase=true,
            int outputGroupSize=0,
            const std::string& separator=":",
            const std::string& terminator="");

std::string encode(const std::string& in,
                   bool uppercase=true,
                   int outputGroupSize=0,
                   const std::string& separator=":",
                   const std::string& terminator="");

std::string encode(std::istream& in,
                   bool uppercase=true,
                   int outputGroupSize=0,
                   const std::string& separator=":",
                   const std::string& terminator="");

bool decode(std::istream& in, std::ostream& out);
bool decode(std::istream& in, std::string& out);
bool decode(const std::string& in, std::ostream& out);
bool decode(const std::string& in, std::string& out);
std::string decode(const std::string& in);
std::string decode(std::istream& in);

} // end namespace Hex

namespace Base64 {

bool encode(std::istream& in, std::ostream& out,
            bool insertLineBreaks = true, int maxLineLength = 72);
bool encode(std::istream& in, std::string& out,
            bool insertLineBreaks = true, int maxLineLength = 72);
bool encode(const std::string& in, std::ostream& out,
            bool insertLineBreaks = true, int maxLineLength = 72);
bool encode(const std::string& in, std::string& out,
            bool insertLineBreaks = true, int maxLineLength = 72);
std::string encode(const std::string& in,
                   bool insertLineBreaks = true, int maxLineLength = 72);
std::string encode(std::istream& in,
                   bool insertLineBreaks = true, int maxLineLength = 72);

bool decode(std::istream& in, std::ostream& out);
bool decode(std::istream& in, std::string& out);
bool decode(const std::string& in, std::ostream& out);
bool decode(const std::string& in, std::string& out);
std::string decode(const std::string& in);
std::string decode(std::istream& in);

} // end namespace Base64

} // end namespace LimeCrypt
