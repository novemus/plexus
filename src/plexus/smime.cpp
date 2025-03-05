/*
 * Copyright (c) 2022 Novemus Band. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 */

#include <plexus/features.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

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
        if (cert.empty() || key.empty())
            return msg;

        int flags = PKCS7_DETACHED | PKCS7_STREAM | PKCS7_NOCERTS;

        std::shared_ptr<BIO> cert_bio(BIO_new_file(cert.c_str(), "r"), BIO_free);
        if (!cert_bio)
            throw plexus::context_error(__FUNCTION__, get_last_error());

        std::shared_ptr<X509> pcert(PEM_read_bio_X509(cert_bio.get(), NULL, 0, NULL), X509_free);

        std::shared_ptr<BIO> key_bio(BIO_new_file(key.c_str(), "r"), BIO_free);
        if (!key_bio)
            throw plexus::context_error(__FUNCTION__, get_last_error());

        std::shared_ptr<EVP_PKEY> pkey(PEM_read_bio_PrivateKey(key_bio.get(), NULL, 0, NULL), EVP_PKEY_free);

        if (!pcert || !pkey)
            throw plexus::context_error(__FUNCTION__, get_last_error());

        std::shared_ptr<BIO> in(BIO_new_mem_buf(msg.c_str(), (int)msg.size()), BIO_free);

        if (!in)
            throw plexus::context_error(__FUNCTION__, get_last_error());

        std::shared_ptr<PKCS7> p7(PKCS7_sign(pcert.get(), pkey.get(), NULL, in.get(), flags), PKCS7_free);

        if (!p7)
            throw plexus::context_error(__FUNCTION__, get_last_error());

        std::shared_ptr<BIO> out(BIO_new(BIO_s_mem()), BIO_free);
        if (!out)
            throw plexus::context_error(__FUNCTION__, get_last_error());

        if (!SMIME_write_PKCS7(out.get(), p7.get(), in.get(), flags))
            throw plexus::context_error(__FUNCTION__, get_last_error());

        char *ptr;
        long len = BIO_get_mem_data(out.get(), &ptr);
        std::string data(ptr, len);

        return std::regex_replace(data, std::regex("\\n"), "\r\n");
    }

    std::string smime_encrypt(const std::string& msg, const std::string& cert)
    {
        if (cert.empty())
            throw plexus::context_error(__FUNCTION__, "no certificate");

        int flags = PKCS7_STREAM;

        std::shared_ptr<BIO> tbio(BIO_new_file(cert.c_str(), "r"), BIO_free);

        if (!tbio)
            throw plexus::context_error(__FUNCTION__, get_last_error());

        std::shared_ptr<X509> pcert(PEM_read_bio_X509(tbio.get(), NULL, 0, NULL), X509_free);

        if (!pcert)
            throw plexus::context_error(__FUNCTION__, get_last_error());

        STACK_OF(X509) *recips = sk_X509_new_null();

        if (!recips || !sk_X509_push(recips, pcert.get()))
            throw plexus::context_error(__FUNCTION__, get_last_error());

        std::shared_ptr<BIO> in(BIO_new_mem_buf(msg.c_str(), (int)msg.size()), BIO_free);

        if (!in)
            throw plexus::context_error(__FUNCTION__, get_last_error());

        std::shared_ptr<PKCS7> p7(PKCS7_encrypt(recips, in.get(), EVP_des_ede3_cbc(), flags), PKCS7_free);

        if (!p7)
            throw plexus::context_error(__FUNCTION__, get_last_error());

        std::shared_ptr<BIO> out(BIO_new(BIO_s_mem()), BIO_free);
        if (!out)
            throw plexus::context_error(__FUNCTION__, get_last_error());

        if (!SMIME_write_PKCS7(out.get(), p7.get(), in.get(), flags))
            throw plexus::context_error(__FUNCTION__, get_last_error());

        char *ptr;
        long len = BIO_get_mem_data(out.get(), &ptr);
        std::string data(ptr, len);

        return std::regex_replace(data, std::regex("\\n"), "\r\n");
    }

    std::string smime_decrypt(const std::string& msg, const std::string& cert, const std::string& key)
    {
        if (cert.empty())
            throw plexus::context_error(__FUNCTION__, "no certificate");
        if (key.empty())
            throw plexus::context_error(__FUNCTION__, "no private key");

        std::shared_ptr<BIO> cert_bio(BIO_new_file(cert.c_str(), "r"), BIO_free);
        if (!cert_bio)
            throw plexus::context_error(__FUNCTION__, get_last_error());

        std::shared_ptr<X509> pcert(PEM_read_bio_X509(cert_bio.get(), NULL, 0, NULL), X509_free);

        std::shared_ptr<BIO> key_bio(BIO_new_file(key.c_str(), "r"), BIO_free);
        if (!key_bio)
            throw plexus::context_error(__FUNCTION__, get_last_error());

        std::shared_ptr<EVP_PKEY> pkey(PEM_read_bio_PrivateKey(key_bio.get(), NULL, 0, NULL), EVP_PKEY_free);

        if (!pcert || !pkey)
            throw plexus::context_error(__FUNCTION__, get_last_error());

        std::string m = std::regex_replace(msg, std::regex("\\r\\n"), "\n");
        std::shared_ptr<BIO> in(BIO_new_mem_buf(m.c_str(), (int)m.size()), BIO_free);

        if (!in)
            throw plexus::context_error(__FUNCTION__, get_last_error());

        std::shared_ptr<PKCS7> p7(SMIME_read_PKCS7(in.get(), NULL), PKCS7_free);

        if (!p7)
            throw plexus::context_error(__FUNCTION__, get_last_error());

        std::shared_ptr<BIO> out(BIO_new(BIO_s_mem()), BIO_free);
        if (!out)
            throw plexus::context_error(__FUNCTION__, get_last_error());

        if (!PKCS7_decrypt(p7.get(), pkey.get(), pcert.get(), out.get(), 0))
            throw plexus::context_error(__FUNCTION__, get_last_error());

        char *ptr;
        long len = BIO_get_mem_data(out.get(), &ptr);
        std::string data(ptr, len);

        return data;
    }

    std::string smime_verify(const std::string& msg, const std::string& cert, const std::string& ca)
    {
        if (cert.empty())
            return msg;

        STACK_OF(X509) *certs = sk_X509_new_null();
        if (certs == NULL)
            throw plexus::context_error(__FUNCTION__, get_last_error());

        std::shared_ptr<BIO> cert_bio(BIO_new_file(cert.c_str(), "r"), BIO_free);
        if (!cert_bio)
            throw plexus::context_error(__FUNCTION__, get_last_error());

        std::shared_ptr<X509> sign_cert(PEM_read_bio_X509(cert_bio.get(), NULL, 0, NULL), X509_free);

        if (!sign_cert)
            throw plexus::context_error(__FUNCTION__, get_last_error());

        sk_X509_push(certs, sign_cert.get());

        std::shared_ptr<BIO> ca_bio;
        std::shared_ptr<X509> ca_cert;
        std::shared_ptr<X509_STORE> st;

        if (!ca.empty())
        {
            ca_bio.reset(BIO_new_file(ca.c_str(), "r"), BIO_free);
            if (!ca_bio)
                throw plexus::context_error(__FUNCTION__, get_last_error());

            ca_cert.reset(PEM_read_bio_X509(ca_bio.get(), NULL, 0, NULL), X509_free);
            if (!ca_cert)
                throw plexus::context_error(__FUNCTION__, get_last_error());

            st.reset(X509_STORE_new(), X509_STORE_free);
            if (st == NULL)
                throw plexus::context_error(__FUNCTION__, get_last_error());

            X509_STORE_set_purpose(st.get(), X509_PURPOSE_ANY);

            if (!X509_STORE_add_cert(st.get(), ca_cert.get()))
                throw plexus::context_error(__FUNCTION__, get_last_error());
        }

        std::string m = std::regex_replace(msg, std::regex("\\r\\n"), "\n");
        std::shared_ptr<BIO> in(BIO_new_mem_buf(m.c_str(), (int)m.size()), BIO_free);

        if (!in)
            throw plexus::context_error(__FUNCTION__, get_last_error());

        BIO* cont = nullptr;
        std::shared_ptr<PKCS7> p7(SMIME_read_PKCS7(in.get(), &cont), PKCS7_free);

        if (p7 == NULL)
            throw plexus::context_error(__FUNCTION__, get_last_error());

        std::shared_ptr<BIO> out(BIO_new(BIO_s_mem()), BIO_free);
        if (!out)
            throw plexus::context_error(__FUNCTION__, get_last_error());

        if (!PKCS7_verify(p7.get(), certs, st.get(), cont, out.get(), st ? 0 : PKCS7_NOVERIFY))
            throw plexus::context_error(__FUNCTION__, get_last_error());

        char *ptr;
        long len = BIO_get_mem_data(out.get(), &ptr);
        std::string data(ptr, len);

        return data;
    }
}}
