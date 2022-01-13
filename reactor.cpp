#include <iostream>
#include <thread>
#include <memory>
#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include "dev.h"

namespace plexus { namespace dev {

class asio_reactor_impl : public asio_reactor
{
    struct context
    {
        boost::asio::io_context io;
        std::unique_ptr<boost::asio::io_context::work> work;
        boost::thread_group pool;

        void activate(size_t threads) 
        {
            work.reset(new boost::asio::io_context::work(io));

            for (std::size_t i = 0; i < threads; ++i)
            {
                pool.create_thread([this]() {
                    boost::system::error_code code;
                    io.run(code);
                    if (code)
                        std::cerr << __FUNCTION__  << ": " << code.message() << std::endl;
                });
            }
        }

        void terminate()
        {
            try
            {
                work.reset();
                io.stop();
                pool.join_all();
            }
            catch (const std::exception& e)
            {
                std::cerr << __FUNCTION__  << ": " << e.what() << std::endl;
            }
        }
    };

    std::shared_ptr<context> m_context;

public:

    asio_reactor_impl(size_t threads) : m_context(new context())
    {
        m_context->activate(threads);
    }

    ~asio_reactor_impl()
    {
        auto context = m_context;
        boost::thread([context]() {
            context->terminate();
        }).detach();
    }

    boost::asio::io_context& get_context() override
    {
        return m_context->io;
    }
};

asio_reactor* create_asio_reactor(size_t threads)
{
    return new asio_reactor_impl(threads);
}

}}
