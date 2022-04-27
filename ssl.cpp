#include <cstdlib>
#include <iostream>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/lexical_cast.hpp>
#include "network.h"
#include "log.h"
#include "utils.h"

namespace plexus { namespace network {

class asio_ssl_client : public plexus::network::ssl
{
    typedef std::function<void(const boost::system::error_code&, size_t)> async_io_callback_t;
    typedef std::function<void(const async_io_callback_t&)> async_io_call_t;
    typedef std::shared_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> ssl_stream_socket_ptr;

    boost::asio::io_service         m_io;
    boost::asio::ssl::context       m_ssl;
    ssl_stream_socket_ptr           m_socket;
    boost::asio::deadline_timer     m_timer;
    boost::asio::ip::tcp::endpoint  m_endpoint;
    boost::posix_time::seconds      m_timeout;

    size_t exec(const async_io_call_t& async_io_call)
    {
        m_timer.expires_from_now(m_timeout);
        m_timer.async_wait([&](const boost::system::error_code& error) {
            if(error)
            {
                if (error == boost::asio::error::operation_aborted)
                    return;

                _err_ << error.message();
            }

            try
            {
                m_socket->lowest_layer().cancel();
            }
            catch (const std::exception &ex)
            {
                _err_ << ex.what();
            }
        });

        boost::system::error_code code = boost::asio::error::would_block;
        size_t length = 0;

        async_io_call([&code, &length](const boost::system::error_code& c, size_t l) {
            code = c;
            length = l;
        });

        do {
            m_io.run_one();
        } while (code == boost::asio::error::would_block);

        m_io.reset();

        if (code)
            throw boost::system::system_error(code);

        return length;
    }

public:

    asio_ssl_client(const std::string& address, uint16_t port, const std::string& cert, const std::string& key, const std::string& ca, int64_t timeout)
        : m_ssl(boost::asio::ssl::context::sslv23)
        , m_timer(m_io)
        , m_endpoint(boost::asio::ip::address::from_string(address), port)
        , m_timeout(timeout)
    {
        m_ssl.set_options(boost::asio::ssl::context::default_workarounds | boost::asio::ssl::context::sslv23_client);
        if (!cert.empty() && !key.empty())
        {
            m_ssl.use_certificate_file(cert, boost::asio::ssl::context::pem);
            m_ssl.use_private_key_file(key, boost::asio::ssl::context::pem);
        }

        if (!ca.empty())
        {
            m_ssl.set_verify_mode(boost::asio::ssl::verify_peer | boost::asio::ssl::verify_fail_if_no_peer_cert | boost::asio::ssl::verify_client_once );
            m_ssl.load_verify_file(ca);
        }

        m_socket = std::make_shared<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>(m_io, m_ssl);
    }

    void connect() noexcept(false) override
    {
        m_socket->lowest_layer().connect(m_endpoint);
        m_socket->handshake(boost::asio::ssl::stream_base::client);
    }

    void shutdown() noexcept(true) override
    {
        if (m_socket->lowest_layer().is_open())
        {
            boost::system::error_code ec;
            m_socket->lowest_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
            m_socket->lowest_layer().close(ec);
        }
    }

    size_t read(uint8_t* buffer, size_t len) noexcept(false) override
    {
        size_t size = exec([&](const async_io_callback_t& callback)
        {
            m_socket->async_read_some(boost::asio::buffer(buffer, len), callback);
        });

        _trc_ << " <<<<< " << utils::to_hexadecimal(buffer, size);

        if (size == 0)
            throw std::runtime_error("can't read data");

        return size;
    }

    size_t write(const uint8_t* buffer, size_t len) noexcept(false) override
    {
        size_t size = exec([&](const async_io_callback_t& callback)
        {
            m_socket->async_write_some(boost::asio::buffer(buffer, len), callback);
        });

        _trc_ << " >>>>> " << utils::to_hexadecimal(buffer, size);

        if (size < len)
            throw std::runtime_error("can't write data");

        return size;
    }
};

std::shared_ptr<ssl> create_ssl_client(const std::string& server, uint16_t port, const std::string& cert, const std::string& key, const std::string& ca, int64_t timeout)
{
    return std::make_shared<asio_ssl_client>(server, port, cert, key, ca, timeout);
}

}}
