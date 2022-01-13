#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/thread.hpp>
#include <functional>
#include <memory>
#include <mutex>
#include "dev.h"
#include "network.h"


namespace plexus { namespace network {

class asio_udp_channel : public channel
{
    std::shared_ptr<dev::asio_reactor>  m_reactor;
    boost::asio::ip::udp::socket        m_socket;
    boost::asio::ip::udp::endpoint      m_src;
    boost::asio::ip::udp::endpoint      m_dst;
    std::mutex                          m_mutex;

public:

    asio_udp_channel(const std::string& dst_ip, unsigned short dst_port, const std::string& src_ip, unsigned short src_port, long timeout)
        : m_reactor(dev::create_asio_reactor(1))
        , m_socket(m_reactor->get_context())
    {
        m_src = boost::asio::ip::udp::endpoint(boost::asio::ip::make_address(src_ip), src_port);

        boost::asio::ip::udp::resolver resolver(m_reactor->get_context());
        boost::asio::ip::udp::resolver::query query(dst_ip, std::to_string(dst_port));
        m_dst = *resolver.resolve(query);

        static const size_t SOCKET_BUFFER_SIZE = 1048576;

        m_socket.non_blocking(false);
        m_socket.set_option(boost::asio::socket_base::send_buffer_size(SOCKET_BUFFER_SIZE));
        m_socket.set_option(boost::asio::socket_base::receive_buffer_size(SOCKET_BUFFER_SIZE));
        m_socket.set_option(boost::asio::detail::socket_option::integer<SOL_SOCKET, SO_RCVTIMEO>(timeout));
        m_socket.set_option(boost::asio::detail::socket_option::integer<SOL_SOCKET, SO_SNDTIMEO>(timeout));
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
        m_socket.bind(m_src);
    }

    int read(char* buffer, int len) noexcept(false) override
    {
        return (int)m_socket.receive_from(boost::asio::buffer(buffer, len), m_dst);
    }

    int write(const char* buffer, int len) noexcept(false) override
    {
        return (int)m_socket.send_to(boost::asio::buffer(buffer, len), m_dst);
    }
};

channel* create_udp_channel(const std::string& dst_ip, unsigned short dst_port, const std::string& src_ip, unsigned short src_port, long timeout)
{
    return new asio_udp_channel(dst_ip, dst_port, src_ip, src_port, timeout);
}

}}
