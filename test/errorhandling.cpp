#include <gtest/gtest.h>

#include <limecrypt.h>
#include <lcencode.h>
#include <lcaes.h>
#include <lcpubkey.h>

#include <fstream>
#include <sstream>

using namespace LimeCrypt;

// A simple print helper class.
class Print  {
public:
    Print() : os(std::cout) {}
    template<typename T> Print(const T& input) : os(std::cout) { os << input; }
    ~Print() { os << std::endl; }
    template<typename T> std::ostream& operator<<(const T& input) { return std::cout << input; }
private:
    std::ostream& os;
};

// stderr redirect helper class.
struct cerr_redirect {
    cerr_redirect( )
        : old( std::cerr.rdbuf( ss.rdbuf() ) )
    { }

    std::string getString() const { return ss.str(); }
    std::stringstream& getStream() { return ss; }

    ~cerr_redirect( ) {
        std::cerr.rdbuf( old );
    }

private:
    std::stringstream ss;
    std::streambuf * old;
};

class TErrorHandling : public testing::Test
{
    virtual void SetUp() {
        text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
               "Nullam sit amet pulvinar mi, vitae tempus elit. Praesent tincidunt "
               "libero ut est sagittis, eu iaculis mi fermentum. Aliquam rutrum blandit "
               "diam, eget egestas nulla dictum a. Fusce facilisis est eu libero posuere "
               "efficitur. Pellentesque volutpat eu massa in sollicitudin. Suspendisse "
               "vehicula nisi libero, in mattis odio laoreet id.\n"
               "~!@#$%^&*()_+=-0987654321`\\\t\r\n?/.,';][}{|";
        ssin.write(text.data(),text.size());
    }

protected:
    PublicKey pubKey;
    PrivateKey privKey;
    std::string text;
    std::stringstream ssin;
    std::stringstream ssout, validout;
};

TEST_F(TErrorHandling, BooleanReturn)
{
    errorHandling(BOOLEAN_RETURN);
    ASSERT_NO_THROW( ASSERT_FALSE(privKey.isValid()) );
    ASSERT_NO_THROW( ASSERT_FALSE(privKey.signWithAppendix(ssin, ssout)) );
    ASSERT_NO_THROW( ASSERT_FALSE(privKey.signWithRecovery(ssin, ssout)) );
    ASSERT_NO_THROW( ASSERT_FALSE(pubKey.encrypt(ssin, ssout)) );
    ASSERT_NO_THROW( ASSERT_FALSE(pubKey.verifyWithAppendix(ssin, ssout)) );
    ASSERT_TRUE(privKey.create());
}

TEST_F(TErrorHandling, StdErr)
{
    errorHandling(STDERR_OUT);
    {
        cerr_redirect cr;
        ASSERT_NO_THROW( ASSERT_FALSE(privKey.isValid()) );
        ASSERT_TRUE(cr.getString().empty());
    }
    {
        cerr_redirect cr;
        ASSERT_NO_THROW( ASSERT_FALSE(privKey.signWithAppendix(ssin, ssout)) );
        ASSERT_NE(cr.getString().find("Error:"), std::string::npos);
    }
    {
        cerr_redirect cr;
        ASSERT_NO_THROW( ASSERT_FALSE(privKey.signWithRecovery(ssin, ssout)) );
        ASSERT_NE(cr.getString().find("Error:"), std::string::npos);
    }
    {
        cerr_redirect cr;
        ASSERT_NO_THROW( ASSERT_FALSE(pubKey.encrypt(ssin, ssout)) );
        ASSERT_NE(cr.getString().find("Error:"), std::string::npos);
    }
    {
        cerr_redirect cr;
        ASSERT_NO_THROW( ASSERT_FALSE(pubKey.verifyWithAppendix(ssin, ssout)) );
        ASSERT_NE(cr.getString().find("Error:"), std::string::npos);
    }
    {
        cerr_redirect cr;
        ASSERT_NO_THROW( ASSERT_FALSE(pubKey.verifyWithRecovery(ssin, ssout)) );
        ASSERT_NE(cr.getString().find("Error:"), std::string::npos);
    }
    {
        cerr_redirect cr;
        ASSERT_NO_THROW( ASSERT_FALSE(pubKey.assignFrom(privKey)) );
        ASSERT_NE(cr.getString().find("Error:"), std::string::npos);
    }

    ASSERT_TRUE(privKey.create(2048));
    ASSERT_TRUE(pubKey.assignFrom(privKey));

    PrivateKey privKey2;
    PublicKey pubKey2;
    ASSERT_TRUE(privKey2.create(2048));
    ASSERT_TRUE(pubKey2.assignFrom(privKey2));

    {
        cerr_redirect cr; std::stringstream in(text);
        ASSERT_NO_THROW( ASSERT_TRUE(privKey.signWithAppendix(in, validout)) );
        ASSERT_TRUE(cr.getString().empty());
    }

    {
        cerr_redirect cr; std::stringstream in(validout.str()), out;
        ASSERT_NO_THROW( ASSERT_TRUE(pubKey.verifyWithAppendix(in, out)) );
        ASSERT_TRUE(cr.getString().empty());
    }

    {
        cerr_redirect cr; std::stringstream in(validout.str()), out;
        ASSERT_NO_THROW( ASSERT_FALSE(pubKey2.verifyWithAppendix(in, out)) );
        ASSERT_NE(cr.getString().find("Error:"), std::string::npos);
    }

    {
        cerr_redirect cr;
        std::string t(pubKey.maxPlainTextLength(),'A');
        ASSERT_NO_THROW( ASSERT_TRUE(pubKey.encrypt(t)) );
        ASSERT_TRUE(cr.getString().empty());
    }

    {
        cerr_redirect cr;
        std::string t(pubKey.maxPlainTextLength()+1,'A');
        ASSERT_NO_THROW( ASSERT_FALSE(pubKey.encrypt(t)) );
        ASSERT_NE(cr.getString().find("Error:"), std::string::npos);
    }
}

TEST_F(TErrorHandling, ThrowException)
{
    errorHandling(THROW_EXCEPTION);
    ASSERT_NO_THROW( ASSERT_FALSE(privKey.isValid()) );

    ASSERT_THROW( ASSERT_FALSE(privKey.signWithAppendix(ssin, ssout)), LimeCrypt::Exception );
    ASSERT_THROW( ASSERT_FALSE(privKey.signWithRecovery(ssin, ssout)), LimeCrypt::Exception );
    ASSERT_THROW( ASSERT_FALSE(pubKey.encrypt(ssin, ssout)), LimeCrypt::Exception );
    ASSERT_THROW( ASSERT_FALSE(pubKey.verifyWithAppendix(ssin, ssout)), LimeCrypt::Exception );
    ASSERT_THROW( ASSERT_FALSE(pubKey.verifyWithRecovery(ssin, ssout)), LimeCrypt::Exception );
    ASSERT_THROW( ASSERT_FALSE(pubKey.assignFrom(privKey)), LimeCrypt::Exception );

    ASSERT_TRUE(privKey.create(2048));
    ASSERT_TRUE(pubKey.assignFrom(privKey));

    PrivateKey privKey2;
    PublicKey pubKey2;
    ASSERT_TRUE(privKey2.create(2048));
    ASSERT_TRUE(pubKey2.assignFrom(privKey2));

    {
        cerr_redirect cr; std::stringstream in(text);
        ASSERT_NO_THROW( ASSERT_TRUE(privKey.signWithAppendix(in, validout)) );
        ASSERT_TRUE(cr.getString().empty());
    }

    {
        cerr_redirect cr; std::stringstream in(validout.str()), out;
        ASSERT_NO_THROW( ASSERT_TRUE(pubKey.verifyWithAppendix(in, out)) );
        ASSERT_TRUE(cr.getString().empty());
    }

    {
        cerr_redirect cr; std::stringstream in(validout.str()), out;
        ASSERT_THROW( ASSERT_FALSE(pubKey2.verifyWithAppendix(in, out)), LimeCrypt::Exception );
        ASSERT_TRUE(cr.getString().empty());
    }

    {
        cerr_redirect cr;
        std::string t(pubKey.maxPlainTextLength(),'A');
        ASSERT_NO_THROW( ASSERT_TRUE(pubKey.encrypt(t)) );
        ASSERT_TRUE(cr.getString().empty());
    }

    {
        cerr_redirect cr;
        std::string t(pubKey.maxPlainTextLength()+1,'A');
        ASSERT_THROW( ASSERT_FALSE(pubKey.encrypt(t)), LimeCrypt::Exception );
        ASSERT_TRUE(cr.getString().empty());
    }

}



