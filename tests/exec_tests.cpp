#include <boost/test/unit_test.hpp>
#include <fstream>
#include <string>
#include "../features.h"

BOOST_AUTO_TEST_CASE(exec)
{
#ifdef _WIN32
    BOOST_REQUIRE_NO_THROW(plexus::exec("C:\\Windows\\System32\\cmd.exe", "/c echo line> out.txt"));
#else
    BOOST_REQUIRE_NO_THROW(plexus::exec("echo", "line> out.txt"));
#endif

    std::ifstream file("out.txt");
    std::string text((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    BOOST_REQUIRE_EQUAL(text, "line\n");

    file.close();
    std::remove("out.txt");
}

