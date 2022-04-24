#include <future>
#include <mutex>
#include <iostream>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <boost/test/unit_test.hpp>
#include "../network.h"

std::string get_last_error()
{
    std::string ssl = ERR_error_string(ERR_get_error(), NULL);
    std::string sys = strerror(errno);
    if (ssl.empty())
        return sys;
    if (sys.empty())
        return ssl;
    return ssl + "\n" + sys;
}

class ssl_echo_server
{
    SSL_CTX* m_context = 0;
    int m_socket = -1;
    std::future<void> m_work;

public:

    ssl_echo_server()
    {
    }

    ~ssl_echo_server()
    {
        stop();
    }

    void start(uint16_t port, const std::string& cert, const std::string& key, const std::string& ca = "")
    {
        m_context = SSL_CTX_new(SSLv23_server_method());
        if (!m_context)
            throw std::runtime_error(get_last_error());
        
        if (!SSL_CTX_use_certificate_file(m_context, cert.c_str(), SSL_FILETYPE_PEM))
            throw std::runtime_error(get_last_error());

        if (!SSL_CTX_use_PrivateKey_file(m_context, key.c_str(), SSL_FILETYPE_PEM))
            throw std::runtime_error(get_last_error());

        if (!SSL_CTX_check_private_key(m_context))
            throw std::runtime_error(get_last_error());

        if (!ca.empty())
        {
            SSL_CTX_set_verify(m_context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);

            if (!SSL_CTX_load_verify_locations(m_context, ca.c_str(), NULL))
                throw std::runtime_error(get_last_error());
        }

        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);

        m_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (m_socket < 0)
            throw std::runtime_error(strerror(errno));

        int enable = 1;
        if (setsockopt(m_socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
            throw std::runtime_error(strerror(errno));

        if (bind(m_socket, (sockaddr*)&addr, sizeof(addr)) < 0)
            throw std::runtime_error(strerror(errno));

        if (listen(m_socket, 1) < 0)
            throw std::runtime_error(strerror(errno));

        m_work = std::async(std::launch::async, [this]()
        {
            try
            { 
                do
                {
                    sockaddr_in addr;
                    unsigned int len = sizeof(addr);
                    int client = accept(m_socket, (sockaddr*)&addr, &len);
                    if (client < 0)
                    {
                        int err = errno;
                        if(err == EINVAL || err == EBADF)
                            return;

                        std::cerr << "unable to accept: " << strerror(err) << std::endl;
                        return;
                    }

                    SSL* ssl = SSL_new(m_context);
                    SSL_set_fd(ssl, client);

                    if (SSL_accept(ssl) <= 0)
                    {
                        std::cerr << get_last_error() << std::endl;
                        return;
                    }

                    char buffer[1024];
                    do
                    {
                        int size = SSL_read(ssl, buffer, 1024);
                        if (size <= 0)
                        {
                            int err = SSL_get_error(ssl, size);
                            if (err == SSL_ERROR_ZERO_RETURN)
                            {
                                break;
                            }
                            else if (err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL)
                            {
                                std::cerr << get_last_error() << std::endl;
                                return;
                            }
                        }
                        else
                        {
                            // std::cout << buffer << std::endl;
                            size = SSL_write(ssl, buffer, size);
                            if (size < 0)
                            {
                                std::cerr << get_last_error() << std::endl;
                                return;
                            }
                        }
                    }
                    while (true);

                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                    close(client);
                }
                while (true);
            }
            catch(const std::exception& e)
            {
                std::cerr << e.what() << std::endl;
            }
        });
    }

    void stop()
    {
        if (m_socket >= 0)
        {
            shutdown(m_socket, SHUT_RDWR);
            close(m_socket);
            m_socket = -1;

            SSL_CTX_free(m_context);
            m_context = 0;

            if (m_work.valid())
                m_work.wait();
        }
    }
};


BOOST_AUTO_TEST_CASE(no_check_certs)
{
    ssl_echo_server server;
    BOOST_REQUIRE_NO_THROW(server.start(4433, "./certs/server.crt", "./certs/server.key"));

    std::shared_ptr<plexus::network::ssl> client(
        plexus::network::create_ssl_client("127.0.0.1:4433")
        );
    BOOST_REQUIRE_NO_THROW(client->connect());

    char buffer[1024];

    std::strcpy(buffer, "hello");
    BOOST_REQUIRE_NO_THROW(BOOST_CHECK_EQUAL(client->write((uint8_t*)buffer, strlen(buffer) + 1), strlen(buffer) + 1));
    BOOST_REQUIRE_NO_THROW(BOOST_CHECK_EQUAL(client->read((uint8_t*)buffer, sizeof(buffer)), strlen(buffer) + 1));
    BOOST_CHECK_EQUAL(std::strncmp(buffer, "hello", 1024), 0);

    std::strcpy(buffer, "bye bye");
    BOOST_REQUIRE_NO_THROW(BOOST_CHECK_EQUAL(client->write((uint8_t*)buffer, strlen(buffer) + 1), strlen(buffer) + 1));
    BOOST_REQUIRE_NO_THROW(BOOST_CHECK_EQUAL(client->read((uint8_t*)buffer, sizeof(buffer)), strlen(buffer) + 1));
    BOOST_CHECK_EQUAL(std::strncmp(buffer, "bye bye", 1024), 0);

    BOOST_REQUIRE_NO_THROW(client->shutdown());
    BOOST_REQUIRE_NO_THROW(server.stop());
}

BOOST_AUTO_TEST_CASE(check_certs)
{
    ssl_echo_server server;
    BOOST_REQUIRE_NO_THROW(server.start(4433, "./certs/server.crt", "./certs/server.key", "./certs/ca.crt"));
    
    std::shared_ptr<plexus::network::ssl> client(
        plexus::network::create_ssl_client("127.0.0.1:4433", "./certs/client.crt", "./certs/client.key", "./certs/ca.crt")
        );
    BOOST_REQUIRE_NO_THROW(client->connect());

    char buffer[1024];
    std::strcpy(buffer, "hello");
    BOOST_REQUIRE_NO_THROW(BOOST_CHECK_EQUAL(client->write((uint8_t*)buffer, strlen(buffer) + 1), strlen(buffer) + 1));
    BOOST_REQUIRE_NO_THROW(BOOST_CHECK_EQUAL(client->read((uint8_t*)buffer, sizeof(buffer)), strlen(buffer) + 1));
    BOOST_CHECK_EQUAL(std::strncmp(buffer, "hello", 1024), 0);

    std::strcpy(buffer, "bye bye");
    BOOST_REQUIRE_NO_THROW(BOOST_CHECK_EQUAL(client->write((uint8_t*)buffer, strlen(buffer) + 1), strlen(buffer) + 1));
    BOOST_REQUIRE_NO_THROW(BOOST_CHECK_EQUAL(client->read((uint8_t*)buffer, sizeof(buffer)), strlen(buffer) + 1));
    BOOST_CHECK_EQUAL(std::strncmp(buffer, "bye bye", 1024), 0);

    BOOST_REQUIRE_NO_THROW(client->shutdown());
    BOOST_REQUIRE_NO_THROW(server.stop());
}

BOOST_AUTO_TEST_CASE(wrong_server)
{
    std::shared_ptr<plexus::network::ssl> client(
        plexus::network::create_ssl_client("127.0.0.1:4422")
        );
    BOOST_REQUIRE_THROW(client->connect(), std::exception);
    BOOST_REQUIRE_NO_THROW(client->shutdown());
}

BOOST_AUTO_TEST_CASE(timeout)
{
    ssl_echo_server server;
    BOOST_REQUIRE_NO_THROW(server.start(4433, "./certs/server.crt", "./certs/server.key"));
    
    std::shared_ptr<plexus::network::ssl> client(
        plexus::network::create_ssl_client("127.0.0.1:4433")
        );
    BOOST_REQUIRE_NO_THROW(client->connect());

    char buffer[1024];
    std::strcpy(buffer, "hello");
    BOOST_REQUIRE_NO_THROW(BOOST_CHECK_EQUAL(client->write((uint8_t*)buffer, strlen(buffer) + 1), strlen(buffer) + 1));
    BOOST_REQUIRE_NO_THROW(BOOST_CHECK_EQUAL(client->read((uint8_t*)buffer, sizeof(buffer)), strlen(buffer) + 1));
    BOOST_CHECK_EQUAL(std::strncmp(buffer, "hello", 1024), 0);

    BOOST_REQUIRE_NO_THROW(server.stop());

    std::strcpy(buffer, "bye bye");
    BOOST_REQUIRE_THROW(client->write((uint8_t*)buffer, strlen(buffer) + 1), std::exception);

    BOOST_REQUIRE_NO_THROW(client->shutdown());
}
