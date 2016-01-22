#include <gtest/gtest.h>
#include <lcencode.h>
#include <limecrypt.h>
#include <fstream>
#include <sstream>

using namespace LimeCrypt;

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

class Encoding : public testing::Test
{
    virtual void SetUp() {
        plainText = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
                    "Nullam sit amet pulvinar mi, vitae tempus elit. Praesent tincidunt "
                    "libero ut est sagittis, eu iaculis mi fermentum. Aliquam rutrum blandit "
                    "diam, eget egestas nulla dictum a. Fusce facilisis est eu libero posuere "
                    "efficitur. Pellentesque volutpat eu massa in sollicitudin. Suspendisse "
                    "vehicula nisi libero, in mattis odio laoreet id.\n"
                    "~!@#$%^&*()_+=-0987654321`\\\t\r\n?/.,';][}{|";

        base64Text = "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpd"
                     "C4gTnVsbGFtIHNpdCBhbWV0IHB1bHZpbmFyIG1pLCB2aXRhZSB0ZW1wdXMgZWxpdC4gUHJhZX"
                     "NlbnQgdGluY2lkdW50IGxpYmVybyB1dCBlc3Qgc2FnaXR0aXMsIGV1IGlhY3VsaXMgbWkgZmV"
                     "ybWVudHVtLiBBbGlxdWFtIHJ1dHJ1bSBibGFuZGl0IGRpYW0sIGVnZXQgZWdlc3RhcyBudWxs"
                     "YSBkaWN0dW0gYS4gRnVzY2UgZmFjaWxpc2lzIGVzdCBldSBsaWJlcm8gcG9zdWVyZSBlZmZpY"
                     "2l0dXIuIFBlbGxlbnRlc3F1ZSB2b2x1dHBhdCBldSBtYXNzYSBpbiBzb2xsaWNpdHVkaW4uIF"
                     "N1c3BlbmRpc3NlIHZlaGljdWxhIG5pc2kgbGliZXJvLCBpbiBtYXR0aXMgb2RpbyBsYW9yZWV"
                     "0IGlkLgp+IUAjJCVeJiooKV8rPS0wOTg3NjU0MzIxYFwJDQo/Ly4sJztdW317fA==";
    }

protected:
    std::string plainText;
    std::string base64Text;
};

TEST_F(Encoding, Hex)
{
    const char* separators[] =  {":","~","`","@","#","$","%","^","&","*","(",")","[","]","-","/","+","_"};
    const char* terminators[] = {"_","+","~",":","`","@","#","$","%","^","&","*","(",")","[","]","-","/"};
    std::string encoded, decoded, separator(":"), terminator("|");
    ASSERT_TRUE(Hex::encode(plainText, encoded));
    ASSERT_EQ(2*plainText.size(), encoded.size());
    ASSERT_TRUE(Hex::decode(encoded, decoded));
    ASSERT_EQ(plainText, decoded);

    for (int gs=0; gs < 17; ++gs) {
        encoded.clear(); decoded.clear();
        ASSERT_TRUE(Hex::encode(plainText, encoded, (gs % 2), gs, separators[gs], terminators[gs]));
        ASSERT_TRUE(Hex::decode(encoded, decoded));
        ASSERT_EQ(plainText, decoded);
    }

    for (int gs=0; gs < 17; ++gs) {
        std::stringstream in(plainText + std::string(gs, 'X')), out, dec;
        ASSERT_TRUE(Hex::encode(in, out, (gs % 2), gs, separators[gs], terminators[gs]));
        ASSERT_TRUE(Hex::decode(out, dec));
        ASSERT_EQ(plainText + std::string(gs, 'X'), dec.str());
    }

    encoded.clear(); decoded.clear();
    ASSERT_TRUE(Hex::encode(plainText, encoded, true, 4, "A", "B"));
    ASSERT_TRUE(Hex::decode(encoded, decoded));
    ASSERT_NE(plainText, decoded);
}

TEST_F(Encoding, Base64)
{
    std::string encoded, decoded;

    ASSERT_TRUE(Base64::decode(base64Text, decoded));
    ASSERT_EQ(plainText, decoded);

    for (int i=10; i < 200; ++i) {
        encoded.clear(); decoded.clear();
        ASSERT_TRUE(Base64::encode(plainText, encoded, (i % 2), i));
        ASSERT_TRUE(encoded.size() > plainText.size());
        ASSERT_TRUE(Base64::decode(encoded, decoded));
        ASSERT_EQ(plainText, decoded);
    }
    for (int i=10; i < 200; ++i) {
        std::stringstream in(plainText + std::string(i, 'X')), out, dec;
        ASSERT_TRUE(Base64::encode(in, out, (i % 2), i));
        ASSERT_TRUE(out.str().size() > in.str().size());
        ASSERT_TRUE(Base64::decode(out, dec));
        ASSERT_EQ(plainText + std::string(i, 'X'), dec.str());
    }
}
