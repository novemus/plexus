#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include "utils.h"

namespace plexus { namespace utils {
    
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

    std::string smime_sign(const std::string& msg, const std::string& cert, const std::string& key)
    {
        int flags = PKCS7_DETACHED | PKCS7_STREAM | PKCS7_NOCERTS;

        std::shared_ptr<BIO> cert_bio(BIO_new_file(cert.c_str(), "r"), BIO_free);
        if (!cert_bio)
            throw std::runtime_error(get_last_error());

        std::shared_ptr<X509> pcert(PEM_read_bio_X509(cert_bio.get(), NULL, 0, NULL), X509_free);

        std::shared_ptr<BIO> key_bio(BIO_new_file(key.c_str(), "r"), BIO_free);
        if (!key_bio)
            throw std::runtime_error(get_last_error());

        std::shared_ptr<EVP_PKEY> pkey(PEM_read_bio_PrivateKey(key_bio.get(), NULL, 0, NULL), EVP_PKEY_free);

        if (!pcert || !pkey)
            throw std::runtime_error(get_last_error());

        std::shared_ptr<BIO> in(BIO_new_mem_buf(msg.c_str(), msg.size()), BIO_free);

        if (!in)
            throw std::runtime_error(get_last_error());

        std::shared_ptr<PKCS7> p7(PKCS7_sign(pcert.get(), pkey.get(), NULL, in.get(), flags), PKCS7_free);

        if (!p7)
            throw std::runtime_error(get_last_error());

        std::shared_ptr<BIO> out(BIO_new(BIO_s_mem()), BIO_free);
        if (!out)
            throw std::runtime_error(get_last_error());

        if (!SMIME_write_PKCS7(out.get(), p7.get(), in.get(), flags))
            throw std::runtime_error(get_last_error());

        char *ptr;
        long len = BIO_get_mem_data(out.get(), &ptr);
        std::string data(ptr, len);

        return data;
    }

    std::string smime_encrypt(const std::string& msg, const std::string& cert)
    {
        int flags = PKCS7_STREAM;

        std::shared_ptr<BIO> tbio(BIO_new_file(cert.c_str(), "r"), BIO_free);

        if (!tbio)
            throw std::runtime_error(get_last_error());

        std::shared_ptr<X509> pcert(PEM_read_bio_X509(tbio.get(), NULL, 0, NULL), X509_free);

        if (!pcert)
            throw std::runtime_error(get_last_error());

        STACK_OF(X509) *recips = sk_X509_new_null();

        if (!recips || !sk_X509_push(recips, pcert.get()))
            throw std::runtime_error(get_last_error());

        std::shared_ptr<BIO> in(BIO_new_mem_buf(msg.c_str(), msg.size()), BIO_free);

        if (!in)
            throw std::runtime_error(get_last_error());

        std::shared_ptr<PKCS7> p7(PKCS7_encrypt(recips, in.get(), EVP_des_ede3_cbc(), flags), PKCS7_free);

        if (!p7)
            throw std::runtime_error(get_last_error());

        std::shared_ptr<BIO> out(BIO_new(BIO_s_mem()), BIO_free);
        if (!out)
            throw std::runtime_error(get_last_error());

        if (!SMIME_write_PKCS7(out.get(), p7.get(), in.get(), flags))
            throw std::runtime_error(get_last_error());

        char *ptr;
        long len = BIO_get_mem_data(out.get(), &ptr);
        std::string data(ptr, len);

        return data;
    }

    std::string smime_decrypt(const std::string& msg, const std::string& cert, const std::string& key)
    {
        std::shared_ptr<BIO> cert_bio(BIO_new_file(cert.c_str(), "r"), BIO_free);
        if (!cert_bio)
            throw std::runtime_error(get_last_error());

        std::shared_ptr<X509> pcert(PEM_read_bio_X509(cert_bio.get(), NULL, 0, NULL), X509_free);

        std::shared_ptr<BIO> key_bio(BIO_new_file(key.c_str(), "r"), BIO_free);
        if (!key_bio)
            throw std::runtime_error(get_last_error());

        std::shared_ptr<EVP_PKEY> pkey(PEM_read_bio_PrivateKey(key_bio.get(), NULL, 0, NULL), EVP_PKEY_free);

        if (!pcert || !pkey)
            throw std::runtime_error(get_last_error());

        std::shared_ptr<BIO> in(BIO_new_mem_buf(msg.c_str(), msg.size()), BIO_free);

        if (!in)
            throw std::runtime_error(get_last_error());

        std::shared_ptr<PKCS7> p7(SMIME_read_PKCS7(in.get(), NULL), PKCS7_free);

        if (!p7)
            throw std::runtime_error(get_last_error());

        std::shared_ptr<BIO> out(BIO_new(BIO_s_mem()), BIO_free);
        if (!out)
            throw std::runtime_error(get_last_error());

        if (!PKCS7_decrypt(p7.get(), pkey.get(), pcert.get(), out.get(), 0))
            throw std::runtime_error(get_last_error());

        char *ptr;
        long len = BIO_get_mem_data(out.get(), &ptr);
        std::string data(ptr, len);

        return data;
    }

    std::string smime_verify(const std::string& msg, const std::string& cert, const std::string& ca)
    {
        std::shared_ptr<X509_STORE> st(X509_STORE_new(), X509_STORE_free);
        if (st == NULL)
            throw std::runtime_error(get_last_error());

        X509_STORE_set_purpose(st.get(), X509_PURPOSE_ANY);

        STACK_OF(X509) *certs = sk_X509_new_null();
        if (certs == NULL)
            throw std::runtime_error(get_last_error());

        std::shared_ptr<BIO> cert_bio(BIO_new_file(cert.c_str(), "r"), BIO_free);
        if (!cert_bio)
            throw std::runtime_error(get_last_error());

        std::shared_ptr<X509> sign_cert(PEM_read_bio_X509(cert_bio.get(), NULL, 0, NULL), X509_free);

        if (!sign_cert)
            throw std::runtime_error(get_last_error());

        sk_X509_push(certs, sign_cert.get());

        std::shared_ptr<BIO> ca_bio(BIO_new_file(ca.c_str(), "r"), BIO_free);
        if (!ca_bio)
            throw std::runtime_error(get_last_error());

        std::shared_ptr<X509> ca_cert(PEM_read_bio_X509(ca_bio.get(), NULL, 0, NULL), X509_free);

        if (!ca_cert)
            throw std::runtime_error(get_last_error());

        if (!X509_STORE_add_cert(st.get(), ca_cert.get()))
            throw std::runtime_error(get_last_error());

        std::shared_ptr<BIO> in(BIO_new_mem_buf(msg.c_str(), msg.size()), BIO_free);

        if (!in)
            throw std::runtime_error(get_last_error());

        BIO* cont = nullptr;
        std::shared_ptr<PKCS7> p7(SMIME_read_PKCS7(in.get(), &cont), PKCS7_free);

        if (p7 == NULL)
            throw std::runtime_error(get_last_error());

        std::shared_ptr<BIO> out(BIO_new(BIO_s_mem()), BIO_free);
        if (!out)
            throw std::runtime_error(get_last_error());

        if (!PKCS7_verify(p7.get(), certs, st.get(), cont, out.get(), 0))
            throw std::runtime_error(get_last_error());

        char *ptr;
        long len = BIO_get_mem_data(out.get(), &ptr);
        std::string data(ptr, len);

        return data;
    }
}}
