#pragma once

#include <boost/asio.hpp>

namespace plexus { namespace dev {

struct asio_reactor
{
    virtual ~asio_reactor() {}
    virtual boost::asio::io_context& get_context() = 0;
};

asio_reactor* create_asio_reactor(size_t threads = std::thread::hardware_concurrency());

}}
