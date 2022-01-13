#include <iostream>
#include <cstring>
#include <thread>
#include <mutex>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include "network.h"

namespace plexus { namespace network {

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

class openssl_channel : public channel
{
    const std::string m_url;
    const std::string m_cert;
    const std::string m_key;
    const long m_timeout;
    std::shared_ptr<BIO> m_bio;

    enum io_kind { IO_READ, IO_WRITE };

public:

    openssl_channel(const std::string& url, const std::string& cert, const std::string& key, long timeout)
        : m_url(url)
        , m_cert(cert)
        , m_key(key)
        , m_timeout(timeout)
    {
        init_openssl();
    }

    void open() noexcept(false) override
    {
        SSL* ssl;
        SSL_CTX* ctx = SSL_CTX_new(SSLv23_client_method());
        m_bio.reset(BIO_new_ssl_connect(ctx), BIO_free_all);

        if (!m_cert.empty() && !m_key.empty())
        {
            SSL_CTX_use_certificate_file(ctx, m_cert.c_str(), SSL_FILETYPE_PEM);
            SSL_CTX_use_PrivateKey_file(ctx, m_key.c_str(), SSL_FILETYPE_PEM);
        }

        BIO_get_ssl(m_bio.get(), &ssl);
        SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

        BIO_set_conn_hostname(m_bio.get(), m_url.c_str());
        BIO_set_nbio(m_bio.get(), 1);

        while (true)
        {
            int res = BIO_do_connect(m_bio.get());
            if (res <= 0 && BIO_should_retry(m_bio.get()))
            {
                if (wait(IO_WRITE) == 0)
                    throw std::runtime_error("can't connect server");
            }
            else
                break;
        }
    }

    void close() noexcept(false) override
    {
        BIO_ssl_shutdown(m_bio.get());
        m_bio.reset();
    }

    int write(const char* buffer, int len) noexcept(false) override
    {
        auto size = do_write(buffer, len);
        if (size < 0)
            throw std::runtime_error("can't write data");
        return size;
    }

    int read(char* buffer, int len) noexcept(false) override
    {
        auto size = do_read(buffer, len);
        if (size < 0)
            throw std::runtime_error("can't read data");
        return size;
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

    int do_read(char* buf, int len) const
    {
        int res = -1;
        while (true)
        {
            res = BIO_read(m_bio.get(), buf, len);
            if (res < 0 && BIO_should_retry(m_bio.get()))
            {
                if (wait(IO_READ) == 0)
                    break;
            }
            else
            {
                return res;
            }
        }

        std::cout << "read error: " << res << std::endl;

        return res;
    }

    int do_write(const char* buf, int len) const
    {
        int res = -1;
        while (true)
        {
            res = BIO_write(m_bio.get(), buf, len);
            if (res < 0 && BIO_should_retry(m_bio.get()))
            {
                if (wait(IO_WRITE) == 0)
                    break;
            }
            else
            {
                return res;
            }
        }

        std::cout << "write error: " << res << std::endl;

        return res;
    }
};

channel* create_ssl_channel(const std::string& url, const std::string& cert, const std::string& key, long timeout)
{
    return new openssl_channel(url, cert, key, timeout);
}

}}