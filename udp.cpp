#include <map>
#include <iostream>
#include <mutex>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include "network.h"


namespace plexus { namespace network {

class asio_udp_client : public udp_client, public std::enable_shared_from_this<asio_udp_client>
{
    typedef std::map<std::pair<std::string, std::string>, boost::asio::ip::udp::endpoint> endpoint_cache_t;

    boost::asio::io_service      m_io;
    boost::asio::ip::udp::socket m_socket;
    boost::asio::deadline_timer  m_timer;
    endpoint_cache_t             m_remotes;
    std::mutex                   m_mutex;

    void check_deadline(const boost::system::error_code& error)
    {
        if(error)
        {
            if (error != boost::asio::error::operation_aborted)
                std::cerr << error.message() << std::endl;

            return;
        }

        if (m_timer.expires_at() <= boost::asio::deadline_timer::traits_type::now())
        {
            try
            {
                m_socket.cancel();
            }
            catch (const std::exception &ex)
            {
                std::cerr << ex.what() << std::endl;
            }
        }

        m_timer.async_wait(boost::bind(&asio_udp_client::check_deadline, shared_from_this(), boost::asio::placeholders::error));
    }

    typedef std::function<void(const boost::system::error_code&, size_t)> async_io_callback_t;
    typedef std::function<void(const async_io_callback_t&)> async_io_call_t;

    size_t exec(const async_io_call_t& async_io_call, long timeout)
    {
        m_timer.expires_from_now(boost::posix_time::milliseconds(timeout));
        m_timer.async_wait(boost::bind(&asio_udp_client::check_deadline, shared_from_this(), boost::asio::placeholders::error));

        boost::system::error_code code = boost::asio::error::would_block;
        size_t length = 0;

        async_io_call([&code, &length](const boost::system::error_code& c, size_t l) {
            code = c;
            length = l;
        });

        do {
            m_io.run_one(); 
        } while (code == boost::asio::error::would_block);

        if (code)
            throw boost::system::system_error(code);

        return length;
    }

    boost::asio::ip::udp::endpoint resolve_endpoint(const std::string& host, const std::string& service)
    {
        auto key = std::make_pair(host, service);
        {
            std::lock_guard<std::mutex> lock(m_mutex);

            auto iter = m_remotes.find(key);
            if (iter != m_remotes.end())
                return iter->second;
        }

        boost::asio::ip::udp::resolver resolver(m_io);
        boost::asio::ip::udp::resolver::query query(host, service);
        boost::asio::ip::udp::endpoint endpoint = *resolver.resolve(query);

        std::lock_guard<std::mutex> lock(m_mutex);
        m_remotes.insert(std::make_pair(key, endpoint));
        return endpoint;
    }

public:

    asio_udp_client(const std::string& address, unsigned short port)
        : m_socket(m_io)
        , m_timer(m_io)
    {
        boost::asio::ip::udp::endpoint endpoint(boost::asio::ip::address::from_string(address), port);

        m_socket.open(endpoint.protocol());

        static const size_t SOCKET_BUFFER_SIZE = 1048576;

        m_socket.non_blocking(true);
        m_socket.set_option(boost::asio::socket_base::send_buffer_size(SOCKET_BUFFER_SIZE));
        m_socket.set_option(boost::asio::socket_base::receive_buffer_size(SOCKET_BUFFER_SIZE));

        m_socket.bind(endpoint);
    }

    ~asio_udp_client()
    {
        if (m_socket.is_open())
        {
            boost::system::error_code ec;
            m_socket.shutdown(boost::asio::ip::udp::socket::shutdown_both, ec);
            m_socket.close(ec);
        }
    }

    std::future<size_t> receive(transfer_ptr data, long timeout) noexcept(false) override
    {
        auto keeper = shared_from_this();
        return std::async(std::launch::async, [&, keeper]()
        {
            boost::asio::ip::udp::endpoint endpoint;
            size_t size = exec([&](const async_io_callback_t& callback)
            {
                m_socket.async_receive_from(boost::asio::buffer(data->buffer), endpoint, callback);
            }, timeout);

            data->host = endpoint.address().to_string();
            data->service = std::to_string(endpoint.port());

            return size;
        });
    }

    std::future<size_t> send(transfer_ptr data, long timeout) noexcept(false) override
    {
        auto keeper = shared_from_this();
        return std::async(std::launch::async, [&, keeper]()
        {
            auto endpoint = resolve_endpoint(
                data->host,
                data->service
                );

            size_t size = exec([&](const async_io_callback_t& callback)
            {
                m_socket.async_send_to(boost::asio::buffer(data->buffer), endpoint, callback);
            }, timeout);

            return size;
        });
    }
};

std::shared_ptr<udp_client> create_udp_client(const std::string& address, unsigned short port)
{
    return std::make_shared<asio_udp_client>(address, port);
}

}}
