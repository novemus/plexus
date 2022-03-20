#define BOOST_TEST_MODULE plexus_tests
#define BOOST_TEST_DYN_LINK

#include <boost/test/unit_test.hpp>
#include "../utils.h"

BOOST_AUTO_TEST_CASE(hexadecimal)
{
    const uint8_t value[] = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef };
    BOOST_CHECK_EQUAL(plexus::utils::to_hexadecimal(value, sizeof(value)), "1234567890abcdef");
}

BOOST_AUTO_TEST_CASE(base64)
{
    const std::string raw = "Lorem ipsum dolor sit amet.<<?!?!?>>";
    const std::string base64 = "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQuPDw/IT8hPz4+";
    const std::string base64nl = "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQuPDw/IT8hPz4+\n";
    const std::string base64url = "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQuPDw_IT8hPz4-";

    BOOST_CHECK_EQUAL(plexus::utils::to_base64(raw.c_str(), raw.size()), base64nl);
    BOOST_CHECK_EQUAL(plexus::utils::to_base64_no_nl(raw.c_str(), raw.size()), base64);
    BOOST_CHECK_EQUAL(plexus::utils::to_base64_url(raw.c_str(), raw.size()), base64url);

    BOOST_CHECK_EQUAL(plexus::utils::from_base64(base64.c_str(), base64.size()), raw);
    BOOST_CHECK_EQUAL(plexus::utils::from_base64(base64nl.c_str(), base64nl.size()), raw);
    BOOST_CHECK_EQUAL(plexus::utils::from_base64_url(base64url.c_str(), base64url.size()), raw);
}

BOOST_AUTO_TEST_CASE(format)
{
    boost::posix_time::ptime time(boost::gregorian::date(2022, boost::gregorian::Mar, 20), boost::posix_time::time_duration(1, 2, 3, 456789));
    BOOST_CHECK_EQUAL(plexus::utils::format("%d-%m-%Y %H:%M:%S.%f", time), "20-03-2022 01:02:03.456789");
    BOOST_CHECK_EQUAL(plexus::utils::format("Epoch: %d-%m-%Y %H:%M:%S", std::chrono::system_clock::time_point()), "Epoch: 01-01-1970 00:00:00");
    BOOST_CHECK_EQUAL(plexus::utils::format("%d %f %x %s", 1, 2.3f, 15, "string"), "1 2.300000 f string");
}
