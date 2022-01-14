#include <iostream>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include "network.h"


namespace plexus { namespace network {

class asio_udp_channel : public channel
{
    boost::asio::io_context        m_io;
    boost::asio::deadline_timer    m_timer;
    boost::asio::ip::udp::socket   m_socket;
    boost::asio::ip::udp::endpoint m_src;
    boost::asio::ip::udp::endpoint m_dst;
    boost::posix_time::seconds     m_timeout;

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

            m_timer.expires_at(boost::posix_time::pos_infin);
        }

        m_timer.async_wait(boost::bind(&asio_udp_channel::check_deadline, this, boost::asio::placeholders::error));
    }

    typedef std::function<void(const boost::system::error_code&, size_t)> async_callback_t;
    typedef std::function<void(const async_callback_t&)> async_call_t;

    size_t exec(const async_call_t& async_call) noexcept(false)
    {
        m_timer.expires_from_now(m_timeout);
        m_timer.async_wait(boost::bind(&asio_udp_channel::check_deadline, this, boost::asio::placeholders::error));

        boost::system::error_code code = boost::asio::error::would_block;
        size_t length = 0;

        async_call([&code, &length](const boost::system::error_code& c, size_t l) {
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

public:

    asio_udp_channel(const std::string& dst_ip, unsigned short dst_port, const std::string& src_ip, unsigned short src_port, long timeout)
        : m_timer(m_io)
        , m_socket(m_io)
        , m_timeout(timeout)
    {
        m_src = boost::asio::ip::udp::endpoint(boost::asio::ip::make_address(src_ip), src_port);

        boost::asio::ip::udp::resolver resolver(m_io);
        boost::asio::ip::udp::resolver::query query(dst_ip, std::to_string(dst_port));
        m_dst = *resolver.resolve(query);
    }

    void close() noexcept(false) override
    {
        if (m_socket.is_open())
        {
            m_socket.shutdown(boost::asio::ip::udp::socket::shutdown_both);
            m_socket.close();
        }
    }

    void open() noexcept(false) override
    {
        m_socket.open(m_src.protocol());

        static const size_t SOCKET_BUFFER_SIZE = 1048576;

        m_socket.non_blocking(true);
        m_socket.set_option(boost::asio::socket_base::send_buffer_size(SOCKET_BUFFER_SIZE));
        m_socket.set_option(boost::asio::socket_base::receive_buffer_size(SOCKET_BUFFER_SIZE));

        m_socket.bind(m_src);
    }

    size_t read(char* buffer, size_t len) noexcept(false) override
    {
        return exec([&, this](const async_callback_t& callback)
        {
            m_socket.async_receive_from(boost::asio::buffer(buffer, len), m_dst, callback);
        });
    }

    size_t write(const char* buffer, size_t len) noexcept(false) override
    {
        return exec([&, this](const async_callback_t& callback)
        {
            m_socket.async_send_to(boost::asio::buffer(buffer, len), m_dst, callback);
        });
    }
};

channel* create_udp_channel(const std::string& dst_ip, unsigned short dst_port, const std::string& src_ip, unsigned short src_port, long timeout)
{
    return new asio_udp_channel(dst_ip, dst_port, src_ip, src_port, timeout);
}

}}
