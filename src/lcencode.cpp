#include <lcencode.h>
#include "limecrypt_p.h"

// Crypto++ includes
#include "crypto++/files.h"
#include "crypto++/hex.h"
#include "crypto++/base64.h"

namespace LimeCrypt {

using namespace CryptoPP;

namespace {
    template<typename SrcType, typename SinkType, typename EncType, typename SrcArg, typename SinkArg>
    bool de_encode(SrcArg& in, SinkArg& out)
    {
        try {
            SrcType( in, true, new EncType( new SinkType( out ) ) );
            return true;
        }
        catch (CryptoPP::Exception& e) {
            handleError(std::string("de/encode(): ") + e.what());
        }
        return false;
    }

    template<typename SrcType, typename SinkType, typename SrcArg, typename SinkArg>
    bool hex_encode(SrcArg& in, SinkArg& out, bool uppercase, int outputGroupSize,
                    const std::string& separator, const std::string& terminator)
    {
        try {
            SrcType( in, true, new CryptoPP::HexEncoder( new SinkType( out ),
                                                         uppercase, outputGroupSize,
                                                         separator, terminator
                                                       )
                    );
            return true;
        }
        catch (CryptoPP::Exception& e) {
            handleError(std::string("Hex encode(): ") + e.what());
        }
        return false;
    }

    template<typename SrcType, typename SinkType, typename SrcArg, typename SinkArg>
    bool base64_encode(SrcArg& in, SinkArg& out, bool insertLineBreaks, int maxLineLength)
    {
        try {
            SrcType( in, true, new CryptoPP::Base64Encoder( new SinkType( out ),
                                                            insertLineBreaks, maxLineLength
                                                          )
                    );
            return true;
        }
        catch (CryptoPP::Exception& e) {
            handleError(std::string("Base64 encode(): ") + e.what());
        }
        return false;
    }} // end anonymous namespace

namespace Hex {

bool encode(std::istream& in, std::ostream& out, bool uppercase, int outputGroupSize,
            const std::string& separator, const std::string& terminator)
{
    return hex_encode<FileSource,FileSink>(in, out, uppercase, outputGroupSize, separator, terminator);
}

bool encode(std::istream& in, std::string& out, bool uppercase, int outputGroupSize, const std::string& separator, const std::string& terminator)
{
    return hex_encode<FileSource,StringSink>(in, out, uppercase, outputGroupSize, separator, terminator);
}

bool encode(const std::string& in, std::ostream& out, bool uppercase, int outputGroupSize, const std::string& separator, const std::string& terminator)
{
    return hex_encode<StringSource,FileSink>(in, out, uppercase, outputGroupSize, separator, terminator);
}

bool encode(const std::string& in, std::string& out, bool uppercase, int outputGroupSize, const std::string& separator, const std::string& terminator)
{
    return hex_encode<StringSource,StringSink>(in, out, uppercase, outputGroupSize, separator, terminator);
}

std::string encode(const std::string& in, bool uppercase, int outputGroupSize, const std::string& separator, const std::string& terminator)
{
    std::string out;
    encode(in, out, uppercase, outputGroupSize, separator, terminator);
    return out;
}

std::string encode(std::istream& in, bool uppercase, int outputGroupSize, const std::string& separator, const std::string& terminator)
{
    std::string out;
    encode(in, out, uppercase, outputGroupSize, separator, terminator);
    return out;
}

bool decode(std::istream& in, std::ostream& out)
{
    return de_encode<FileSource,FileSink,HexDecoder>(in, out);
}

bool decode(std::istream& in, std::string& out)
{
    return de_encode<FileSource,StringSink,HexDecoder>(in, out);
}

bool decode(const std::string& in, std::ostream& out)
{
    return de_encode<StringSource,FileSink,HexDecoder>(in, out);
}

bool decode(const std::string& in, std::string& out)
{
    return de_encode<StringSource,StringSink,HexDecoder>(in, out);
}

std::string decode(const std::string& in)
{
    std::string out;
    decode(in, out);
    return out;
}

std::string decode(std::istream& in)
{
    std::string out;
    decode(in, out);
    return out;
}

} // end namespace Hex

namespace Base64 {

bool encode(std::istream& in, std::ostream& out, bool insertLineBreaks, int maxLineLength)
{
    return base64_encode<FileSource,FileSink>(in, out, insertLineBreaks, maxLineLength);
}

bool encode(std::istream& in, std::string& out, bool insertLineBreaks, int maxLineLength)
{
    return base64_encode<FileSource,StringSink>(in, out, insertLineBreaks, maxLineLength);
}

bool encode(const std::string& in, std::ostream& out, bool insertLineBreaks, int maxLineLength)
{
    return base64_encode<StringSource,FileSink>(in, out, insertLineBreaks, maxLineLength);
}

bool encode(const std::string& in, std::string& out, bool insertLineBreaks, int maxLineLength)
{
    return base64_encode<StringSource,StringSink>(in, out, insertLineBreaks, maxLineLength);
}

std::string encode(const std::string& in, bool insertLineBreaks, int maxLineLength)
{
    std::string out;
    encode(in, out, insertLineBreaks, maxLineLength);
    return out;
}

std::string encode(std::istream& in, bool insertLineBreaks, int maxLineLength)
{
    std::string out;
    encode(in, out, insertLineBreaks, maxLineLength);
    return out;
}

bool decode(std::istream& in, std::ostream& out)
{
    return de_encode<FileSource,FileSink,Base64Decoder>(in, out);
}

bool decode(std::istream& in, std::string& out)
{
    return de_encode<FileSource,StringSink,Base64Decoder>(in, out);
}

bool decode(const std::string& in, std::ostream& out)
{
    return de_encode<StringSource,FileSink,Base64Decoder>(in, out);
}

bool decode(const std::string& in, std::string& out)
{
    return de_encode<StringSource,StringSink,Base64Decoder>(in, out);
}

std::string decode(const std::string& in)
{
    std::string out;
    decode(in, out);
    return out;
}

std::string decode(std::istream& in)
{
    std::string out;
    decode(in, out);
    return out;
}

} // end namespace Base64

} // end namespace LimeCrypt
