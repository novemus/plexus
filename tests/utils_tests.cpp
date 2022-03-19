#define BOOST_TEST_MODULE plexus_tests
#define BOOST_TEST_DYN_LINK

#include <boost/test/unit_test.hpp>
#include "../utils.h"

BOOST_AUTO_TEST_CASE(hexadecimal)
{
    const uint8_t value[] = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef };
    BOOST_CHECK_EQUAL(plexus::utils::to_hexadecimal(value, sizeof(value)), "1234567890abcdef");
}
