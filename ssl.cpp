#include <iostream>
#include <cstring>
#include <thread>
#include <mutex>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include "network.h"
#include "log.h"

namespace plexus { namespace network {

std::string get_last_error(const std::string& comment = "")
{
    auto ssl = ERR_get_error();
    if (ssl != 0)
        return comment + ": " + ERR_error_string(ssl, NULL);
    
    auto sys = errno;
    if (sys != 0)
        return comment + ": " + strerror(errno);

    return comment;
}

void init_openssl()
{
    static std::once_flag flag;

    std::call_once(flag, []()
    {
        OPENSSL_malloc_init();
        SSL_library_init();
        SSL_load_error_strings();
        ERR_load_BIO_strings();
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
    });
}

class openssl_client : public ssl
{
    const std::string m_url;
    const std::string m_cert;
    const std::string m_key;
    const std::string m_ca;
    const int64_t m_timeout;
    std::shared_ptr<BIO> m_bio;

    enum io_kind { IO_READ, IO_WRITE };

public:

    openssl_client(const std::string& url, const std::string& cert, const std::string& key, const std::string& ca, int64_t timeout)
        : m_url(url)
        , m_cert(cert)
        , m_key(key)
        , m_ca(ca)
        , m_timeout(timeout)
    {
        init_openssl();
    }

    void connect() noexcept(false) override
    {
        SSL* ssl;
        SSL_CTX* ctx = SSL_CTX_new(SSLv23_client_method());

        if (!m_ca.empty())
        {
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
            if (!SSL_CTX_load_verify_locations(ctx, m_ca.c_str(), NULL))
                throw std::runtime_error(get_last_error("SSL_CTX_load_verify_locations failed"));
        }

        m_bio.reset(BIO_new_ssl_connect(ctx), BIO_free_all);

        BIO_get_ssl(m_bio.get(), &ssl);

        if (!m_cert.empty() && !m_key.empty())
        {
            if (!SSL_use_certificate_file(ssl, m_cert.c_str(), SSL_FILETYPE_PEM))
                throw std::runtime_error(get_last_error("SSL_use_certificate_file failed"));
            if (!SSL_use_PrivateKey_file(ssl, m_key.c_str(), SSL_FILETYPE_PEM))
                throw std::runtime_error(get_last_error("SSL_use_PrivateKey_file failed"));
            if (!SSL_check_private_key(ssl))
                throw std::runtime_error(get_last_error("SSL_check_private_key failed"));
        }

        SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

        BIO_set_conn_hostname(m_bio.get(), m_url.c_str());
        BIO_set_nbio(m_bio.get(), 1);

        while (true)
        {
            int res = BIO_do_connect(m_bio.get());
            if (res <= 0)
            {
                if (BIO_should_retry(m_bio.get()))
                {
                    if (wait(IO_WRITE) == 0)
                        throw timeout_error();
                }
                else
                {
                    throw std::runtime_error(get_last_error("BIO_do_connect failed"));
                }
            }
            else
                break;
        }
    }

    void shutdown() noexcept(false) override
    {
        BIO_ssl_shutdown(m_bio.get());
        m_bio.reset();
    }

    size_t write(const uint8_t* buffer, size_t len) noexcept(false) override
    {
        return static_cast<size_t>(do_write(buffer, static_cast<int>(len)));
    }

    size_t read(uint8_t* buffer, size_t len) noexcept(false) override
    {
        return static_cast<size_t>(do_read(buffer, static_cast<int>(len)));
    }

private:

    int wait(io_kind io) const
    {
        int fd;
        BIO_get_fd(m_bio.get(), &fd);

        fd_set fds;
        FD_ZERO(&fds);

        FD_SET(fd, &fds);

        struct timeval timeout;
        timeout.tv_usec = 0;
        timeout.tv_sec = m_timeout;

        return select(fd + 1, io == IO_READ ? &fds : 0, io == IO_READ ? 0 : &fds, NULL, &timeout);
    }

    int do_read(void* buf, int len) const
    {
        int res = -1;
        while (true)
        {
            res = BIO_read(m_bio.get(), buf, len);
            if (res < 0)
            {
                if (BIO_should_retry(m_bio.get()))
                {
                    if (wait(IO_READ) == 0)
                        throw timeout_error();
                }
                else
                {
                    throw std::runtime_error(get_last_error("BIO_read failed"));
                }
            }
            else
            {
                break;
            }
        }

        return res;
    }

    int do_write(const void* buf, int len) const
    {
        int res = -1;
        while (true)
        {
            res = BIO_write(m_bio.get(), buf, len);
            if (res < 0)
            {
                if (BIO_should_retry(m_bio.get()))
                {
                    if (wait(IO_WRITE) == 0)
                        throw timeout_error();
                }
                else
                {
                    throw std::runtime_error(get_last_error("BIO_write failed"));
                }
            }
            else
            {
                break;
            }
        }

        return res;
    }
};

std::shared_ptr<ssl> create_ssl_client(const std::string& url, const std::string& cert, const std::string& key, const std::string& ca, int64_t timeout)
{
    return std::make_shared<openssl_client>(url, cert, key, ca, timeout);
}

}}