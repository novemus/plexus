#include <boost/test/unit_test.hpp>
#include "../utils.h"

BOOST_AUTO_TEST_CASE(smime)
{
    std::string message = "Hello, Plexus!";

    BOOST_REQUIRE_NO_THROW(
        std::string signed_smime = plexus::utils::smime_sign(message, "./certs/client.crt", "./certs/client.key");
        std::string encrypted_smime = plexus::utils::smime_encrypt(signed_smime, "./certs/server.crt");
        std::string decrypted_smime = plexus::utils::smime_decrypt(encrypted_smime, "./certs/server.crt", "./certs/server.key");
        BOOST_REQUIRE_EQUAL(plexus::utils::smime_verify(decrypted_smime, "./certs/client.crt", "./certs/ca.crt"), message);
    );
}
