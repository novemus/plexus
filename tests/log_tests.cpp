#include <boost/test/unit_test.hpp>
#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include "../log.h"

std::regex pattern("\\d{4}-\\w{2,3}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d{1,6} \\[\\d+\\] INFO: line 1\n"
                   "\\d{4}-\\w{2,3}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d{1,6} \\[\\d+\\] WARN: line 2\n"
                   "\\d{4}-\\w{2,3}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d{1,6} \\[\\d+\\] ERROR: line 3\n"
                   "\\d{4}-\\w{2,3}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d{1,6} \\[\\d+\\] FATAL: line 4\n");

BOOST_AUTO_TEST_CASE(stdlog)
{
    plexus::log::set(plexus::log::severity::info);

    std::stringstream out;
    std::streambuf *coutbuf = std::cout.rdbuf();
    std::cout.rdbuf(out.rdbuf());

    _inf_ << "line " << 1;
    _wrn_ << "line " << 2;
    _err_ << "line " << 3;
    _ftl_ << "line " << 4;
    _dbg_ << "line " << 5;
    _trc_ << "line " << 6;

    std::smatch match;
    std::string text = out.str();
    out.clear();
    std::cout.rdbuf(coutbuf);

    BOOST_CHECK(std::regex_match(text, match, pattern));
}

BOOST_AUTO_TEST_CASE(filelog)
{
    plexus::log::set(plexus::log::severity::info, "log.txt");

    _inf_ << "line " << 1;
    _wrn_ << "line " << 2;
    _err_ << "line " << 3;
    _ftl_ << "line " << 4;
    _dbg_ << "line " << 5;
    _trc_ << "line " << 6;

    std::smatch match;
    std::ifstream file("log.txt");
    std::string text((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    BOOST_CHECK(std::regex_match(text, match, pattern));
    
    std::remove("log.txt");
}
