#include <boost/test/unit_test.hpp>
#include "../utils.h"

BOOST_AUTO_TEST_CASE(smime)
{
    std::string message = "Hello, Plexus!";
    std::string verified_smime;
    std::string signed_smime;
    std::string encrypted_smime;
    std::string decrypted_smime;

    BOOST_REQUIRE_NO_THROW(signed_smime = plexus::utils::smime_sign(message, "./certs/client.crt", "./certs/client.key"));
    BOOST_REQUIRE_NO_THROW(encrypted_smime = plexus::utils::smime_encrypt(signed_smime, "./certs/server.crt"));

    BOOST_REQUIRE_NO_THROW(decrypted_smime = plexus::utils::smime_decrypt(encrypted_smime, "./certs/server.crt", "./certs/server.key"));
    BOOST_REQUIRE_NO_THROW(verified_smime = plexus::utils::smime_verify(decrypted_smime, "./certs/client.crt", "./certs/ca.crt"));
    
    BOOST_REQUIRE_EQUAL(verified_smime, message);

    BOOST_REQUIRE_THROW(plexus::utils::smime_sign(message, "./certs/client.crt", "./certs/server.key"), std::runtime_error);
    BOOST_REQUIRE_THROW(plexus::utils::smime_encrypt(signed_smime, "./certs/server.key"), std::runtime_error);
    BOOST_REQUIRE_THROW(plexus::utils::smime_decrypt(encrypted_smime, "./certs/client.crt", "./certs/client.key"), std::runtime_error);
    BOOST_REQUIRE_THROW(plexus::utils::smime_verify(decrypted_smime, "./certs/server.crt", "./certs/ca.crt"), std::runtime_error);
}
