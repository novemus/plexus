/*
 * Copyright (c) 2022 Novemus Band. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 */

#include "features.h"
#include "network.h"
#include "utils.h"
#include <filesystem>
#include <logger.h>
#include <limits>
#include <stdexcept>
#include <string>
#include <iostream>
#include <cstring>
#include <memory>
#include <regex>
#include <functional>

namespace plexus {

const int64_t response_timeout = plexus::utils::getenv<int64_t>("PLEXUS_RESPONSE_TIMEOUT", 60000);
const int64_t max_polling_timeout = plexus::utils::getenv<int64_t>("PLEXUS_MAX_POLLING_TIMEOUT", 30000);
const int64_t min_polling_timeout = plexus::utils::getenv<int64_t>("PLEXUS_MIN_POLLING_TIMEOUT", 10000);

namespace email {

struct config
{
    boost::asio::ip::tcp::endpoint smtp;
    boost::asio::ip::tcp::endpoint imap;
    std::string login;
    std::string passwd;
    std::string cert;
    std::string key;
    std::string ca;
    std::string app;
    std::string repo;
    subscriber host;
    subscriber peer;

    bool is_absent() const
    {
        return host.first.empty() || host.second.empty() || peer.first.empty() || peer.second.empty();
    }

    bool is_permissible() const
    {
        return !is_absent()
            && std::filesystem::exists(std::filesystem::path(std::filesystem::path(repo) / host.first / host.second))
            && std::filesystem::exists(std::filesystem::path(std::filesystem::path(repo) / peer.first / peer.second));
    }

    bool is_encryptable() const
    {
        return std::filesystem::exists(std::filesystem::path(std::filesystem::path(repo) / host.first / host.second / "cert.crt"))
            && std::filesystem::exists(std::filesystem::path(std::filesystem::path(repo) / host.first / host.second / "private.key"))
            && std::filesystem::exists(std::filesystem::path(std::filesystem::path(repo) / peer.first / peer.second / "cert.crt"));
    }

    std::string get_host_cert() const 
    {
        std::filesystem::path cert(std::filesystem::path(repo) / host.first / host.second / "cert.crt");
        return std::filesystem::exists(cert) ? cert.generic_u8string() : "";
    }

    std::string get_host_key() const 
    {
        std::filesystem::path key(std::filesystem::path(repo) / host.first / host.second / "private.key");
        return std::filesystem::exists(key) ? key.generic_u8string() : "";
    }

    std::string get_peer_cert() const 
    {
        std::filesystem::path cert(std::filesystem::path(repo) / peer.first / peer.second / "cert.crt");
        return std::filesystem::exists(cert) ? cert.generic_u8string() : "";
    }

    std::string get_peer_ca() const 
    {
        std::filesystem::path ca(std::filesystem::path(repo) / peer.first / peer.second / "ca.crt");
        return std::filesystem::exists(ca) ? ca.generic_u8string() : "";
    }
};

class channel
{
    static const size_t BUFFER_SIZE = 8192;

public:

    channel(const boost::asio::ip::tcp::endpoint& remote, const std::string& cert, const std::string& key, const std::string& ca)
        : m_ssl(network::create_ssl_client(remote, cert, key, ca))
    {
    }

    typedef std::function<bool(const std::string&)> response_parser_t;

    void connect(const response_parser_t& parse)
    {
        m_ssl->connect();

        std::string response;
        do {
			size_t read = m_ssl->read(m_buffer, BUFFER_SIZE);
            response.append((char*)m_buffer, read);
        } while (!parse(response));

        _trc_ << ">>>>>\n" << response << "\n*****";
    }

    void request(const std::string& request, const response_parser_t& parse, bool prolonged = false)
    {
        _trc_ << "<<<<<\n" << request << "\n*****";

		size_t written = 0;
        do {
            written += m_ssl->write((const uint8_t*)request.c_str() + written, request.size() - written);
        } while (written < request.size());

        std::string response;
        do {
			size_t read = m_ssl->read(m_buffer, BUFFER_SIZE, prolonged ? std::numeric_limits<int64_t>::max() : network::default_tcp_timeout_ms);
            response.append((char*)m_buffer, read);
        } while (!parse(response));

        _trc_ << ">>>>>\n" << response << "\n*****";
    }

    void snooze(int64_t timeout)
    {
        try
        {
            m_ssl->wait(boost::asio::socket_base::wait_read, timeout);
        }
        catch (const boost::system::system_error& ex)
        {
            if (ex.code() != boost::asio::error::operation_aborted)
                throw;
        }
    }

private:

    uint8_t m_buffer[BUFFER_SIZE];
    std::shared_ptr<network::tcp> m_ssl;
};

class smtp
{
    typedef channel::response_parser_t response_parser_t;
    
    const response_parser_t code_checker(unsigned int code) const
    {
        return [code](const std::string& response) -> bool {
            std::smatch match;
            bool done = std::regex_search(response, match, std::regex("^(\\d+)\\s+.*\\r\\n$"));
            if (done && match[1] != std::to_string(code))
                throw std::runtime_error(response);
            return done;
        };
    }

    std::string build_data(const std::string& message, uint8_t variant)
    {
        if (!m_config.is_encryptable())
        {
            static const char* SIMPLE_EMAIL =
                "X-Sender: %s\r\n"
                "X-Variant: %u\r\n"
                "X-Source: %s\r\n"
                "X-Target: %s\r\n"
                "From: %s\r\n"
                "To: %s\r\n"
                "Subject: plexus\r\n"
                "\r\n"
                "%s\r\n"
                ".\r\n";

            return utils::format(
                SIMPLE_EMAIL,
                m_config.app.c_str(),
                variant,
                m_config.host.second.c_str(),
                m_config.peer.second.c_str(),
                m_config.host.first.c_str(),
                m_config.peer.first.c_str(),
                message.c_str()
                );
        }

        static const char* MULTIPART_EMAIL =
            "X-Sender: %s\r\n"
            "X-Variant: %u\r\n"
            "X-Source: %s\r\n"
            "X-Target: %s\r\n"
            "From: %s\r\n"
            "To: %s\r\n"
            "Subject: plexus\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: multipart/mixed; boundary=----%s\r\n"
            "\r\n"
            "------%s\r\n"
            "%s\r\n"
            "------%s--\r\n"
            ".\r\n";

        std::string bound = plexus::utils::to_hexadecimal(m_config.host.first.data(), m_config.host.first.size());
        std::string content = plexus::utils::smime_encrypt(
            plexus::utils::smime_sign(message, m_config.get_host_cert(), m_config.get_host_key()),
            m_config.get_peer_cert()
            );

        return utils::format(
            MULTIPART_EMAIL,
            m_config.app.c_str(),
            variant,
            m_config.host.second.c_str(),
            m_config.peer.second.c_str(),
            m_config.host.first.c_str(),
            m_config.peer.first.c_str(),
            bound.c_str(),
            bound.c_str(),
            content.c_str(),
            bound.c_str()
            );
    }

public:
    
    smtp(const config& conf) : m_config(conf)
    {
    }

    void push(const std::string& message, uint8_t variant) noexcept(false)
    {
        std::unique_ptr<channel> session = std::make_unique<channel>(
            m_config.smtp,
            m_config.cert,
            m_config.key,
            m_config.ca
        );

        session->connect(code_checker(220));
        session->request("HELO smtp\r\n", code_checker(250));
        session->request("AUTH LOGIN\r\n", code_checker(334));
        session->request(utils::format("%s\r\n", utils::to_base64_no_nl(m_config.login.c_str(), m_config.login.size()).c_str()), code_checker(334));
        session->request(utils::format("%s\r\n", utils::to_base64_no_nl(m_config.passwd.c_str(), m_config.passwd.size()).c_str()), code_checker(235));
        session->request(utils::format("MAIL FROM: %s\r\n", m_config.host.first.c_str()), code_checker(250));
        session->request(utils::format("RCPT TO: %s\r\n", m_config.peer.first.c_str()), code_checker(250));
        session->request("DATA\r\n", code_checker(354));
        session->request(build_data(message, variant), code_checker(250));
    }

private:

    config m_config;
};

class imap : public listener
{
    typedef channel::response_parser_t response_parser_t;
    
    struct bad_command : public std::runtime_error { bad_command() : std::runtime_error("bad command") {} };

    const response_parser_t connect_checker = [](const std::string& response) -> bool {
            std::smatch match;
            bool done = std::regex_search(response, match, std::regex("^\\* +(OK|NO) +.*\\r\\n$"));
            if (done && match[1] != "OK")
                throw std::runtime_error(response);
            return done;
        };

    const response_parser_t success_checker = [](const std::string& response) -> bool {
        std::smatch match;
        bool done = std::regex_search(response, match, std::regex("(.*\\r\\n)?\\d+ +(OK|NO) +.*\\r\\n$"));
        if (done && match[2] != "OK")
            throw std::runtime_error(response);
        return done;
    };

    const response_parser_t select_parser = [this](const std::string& response) -> bool {
        if (success_checker(response))
        {
            std::smatch match;
            if (std::regex_search(response, match, std::regex(".*\\r\\n\\* +OK +\\[UIDVALIDITY +(\\d+)\\].*")))
            {
                std::stringstream ss;
                ss << match[1].str();

                uint64_t validity;
                ss >> validity;

                if (validity != m_validity)
                    m_uid = 0;

                m_validity = validity;
            }
            return true;
        }
        return false;
    };

    const response_parser_t search_parser = [this](const std::string& response) -> bool {
        if (success_checker(response))
        {
            std::smatch match;
            if (std::regex_search(response, match, std::regex("^\\* +SEARCH +([\\d ]+)\\r\\n.*")))
            {
                std::stringstream stream;
                stream << match[1].str();

                uint64_t uid = 0;
                while (stream >> uid)
                {
                    if (uid > m_uid)
                        m_uid = uid;
                }
            }
            return true;
        }
        return false;
    };

    const response_parser_t uid_parser = [this](const std::string& response) -> bool {
        if (success_checker(response))
        {
            std::smatch match;
            if (std::regex_search(response, match, std::regex("^\\* +\\d+ +FETCH +\\(UID +(\\d+)\\)\\r\\n.*")))
            {
                std::stringstream ss;
                ss << match[1].str();
                ss >> m_uid;
            }
            return true;
        }
        return false;
    };

    const response_parser_t idle_parser = [](const std::string& response) -> bool {
        std::smatch match;
        if (std::regex_search(response, match, std::regex("(.*\\r\\n)?\\d+ +(NO|BAD) +.*\\r\\n$")))
        {
            if (match[1] != "BAD")
                throw bad_command();
            throw std::runtime_error(response);
        }
        return std::regex_search(response, match, std::regex("^\\+ +idling(\\r\\n.*)+\\* +\\d+ +EXISTS(\\r\\n.*)*\\r\\n$"));
    };


    const response_parser_t listen_parser = [&](const std::string& response) -> bool
    {
        if (success_checker(response))
        {
            static const std::regex pattern("^[^\\(\\r\\n]+\\([^\\r\\n]+\\r\\n"
                                            "From: +([^\\r\\n]+)\\r\\n\\r\\n"
                                            "[^\\r\\n]+\\r\\n"
                                            "X-Source: +([^\\r\\n]+)\\r\\n\\r\\n"
                                            "[^\\r\\n]+\\r\\n"
                                            "To: +([^\\r\\n]+)\\r\\n\\r\\n"
                                            "[^\\r\\n]+\\r\\n"
                                            "X-Target: +([^\\r\\n]+)\\r\\n\\r\\n"
                                            "\\)\\r\\n.*");

            std::smatch match;
            if (std::regex_search(response, match, pattern))
            {
                m_config.peer = std::make_pair(match[1].str(), match[2].str());
                m_config.host = std::make_pair(match[3].str(), match[4].str());

                if (!m_config.is_permissible())
                {
                    m_config.peer = subscriber();
                    m_config.host = subscriber();
                }
            }
            return true;
        }
        return false;
    };

    const response_parser_t fetch_parser = [&](const std::string& response) -> bool
    {
        if (success_checker(response))
        {
            std::smatch match;
            if (std::regex_search(response, match, std::regex("^[^\\r\\n]+\\r\\n([\\s\\S]+)\\r\\n\\)\\r\\n.*")))
            {
                try
                {
                    if (m_config.is_encryptable())
                    {
                        m_message = plexus::utils::smime_verify(
                            plexus::utils::smime_decrypt(match[1].str(), m_config.get_host_cert(), m_config.get_host_key()),
                            m_config.get_peer_cert(),
                            m_config.get_peer_ca()
                            );
                    }
                    else
                    {
                        m_message = match[1].str();
                    }
                }
                catch(const std::exception& ex)
                {
                    _err_ << ex.what();
                }
            }
            return true;
        }
        return false;
    };

public:

    imap(const config& conf) : m_config(conf)
    {
        if (m_config.is_absent())
        {
            std::unique_ptr<channel> session = std::make_unique<channel>(
                m_config.imap,
                m_config.cert,
                m_config.key,
                m_config.ca
            );

            session->connect(connect_checker);
            session->request(utils::format("%u LOGIN %s %s\r\n", ++m_seqno, m_config.login.c_str(), m_config.passwd.c_str()), success_checker);
            session->request(utils::format("%u SELECT INBOX\r\n", ++m_seqno), select_parser);
            session->request(utils::format("%u FETCH * UID\r\n", ++m_seqno), uid_parser);
        }
    }

    void listen() noexcept(false) override
    {
        std::unique_ptr<channel> session = std::make_unique<channel>(
            m_config.imap,
            m_config.cert,
            m_config.key,
            m_config.ca
        );

        m_config.peer = subscriber();
        m_config.host = subscriber();

        session->connect(connect_checker);
        session->request(utils::format("%u LOGIN %s %s\r\n", ++m_seqno, m_config.login.c_str(), m_config.passwd.c_str()), success_checker);

        do
        {
            uint64_t last = m_uid;

            session->request(utils::format("%u SELECT INBOX\r\n", ++m_seqno), select_parser);
            session->request(utils::format("%u UID SEARCH (SINCE %s) (HEADER X-Sender %s) (HEADER X-Variant 0)\r\n",
                    ++m_seqno,
                    utils::format("%d-%b-%Y", std::chrono::system_clock::now()).c_str(), m_config.app.c_str()
                ),
                search_parser
            );

            if (last == m_uid)
            {
                try
                {
                    session->request(utils::format("%u IDLE\r\n", ++m_seqno), idle_parser, true);
                    session->request("DONE\r\n", success_checker);
                }
                catch (const bad_command&)
                {
                    session->snooze(max_polling_timeout);
                }
            }
            else
            {
                session->request(
                    utils::format("%u UID FETCH %d (BODY[HEADER.FIELDS (From)] BODY[HEADER.FIELDS (X-Source)] BODY[HEADER.FIELDS (To)] BODY[HEADER.FIELDS (X-Target)])\r\n", ++m_seqno, m_uid),
                    listen_parser
                );
            }
        }
        while (m_config.is_absent());
    }

    std::string pull(uint8_t variant) noexcept(false)
    {
        auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        std::unique_ptr<channel> session = std::make_unique<channel>(
            m_config.imap,
            m_config.cert,
            m_config.key,
            m_config.ca
        );

        session->connect(connect_checker);
        session->request(utils::format("%u LOGIN %s %s\r\n", ++m_seqno, m_config.login.c_str(), m_config.passwd.c_str()), success_checker);

        uint64_t last = m_uid;
        do
        {
            if (timer().total_milliseconds() > response_timeout)
                throw plexus::timeout_error();

            session->request(utils::format("%u SELECT INBOX\r\n", ++m_seqno), select_parser);
            session->request(utils::format("%u UID SEARCH (SINCE %s) (HEADER X-Sender %s) (HEADER X-Variant %u) (From %s) (To %s) (HEADER X-Source %s) (HEADER X-Target %s)\r\n",
                    ++m_seqno,
                    utils::format("%d-%b-%Y", std::chrono::system_clock::now()).c_str(), 
                    m_config.app.c_str(), variant,
                    m_config.peer.first.c_str(),
                    m_config.host.first.c_str(),
                    m_config.peer.second.c_str(),
                    m_config.host.second.c_str()
                ),
                search_parser
            );

            if (last == m_uid)
                session->snooze(min_polling_timeout);
        }
        while (last == m_uid);

        session->request(
            utils::format("%u UID FETCH %d (BODY.PEEK[TEXT])\r\n", ++m_seqno, m_uid), fetch_parser
            );

        return std::move(m_message);
    }

    subscriber host() const noexcept(true) override
    {
        return m_config.host;
    }

    subscriber peer() const noexcept(true) override
    {
        return m_config.peer;
    }

private:

    config m_config;
    uint8_t m_seqno = 0;
    uint64_t m_validity = 0;
    uint64_t m_uid = 0;
    std::string m_message;
};


class mediator_impl : public mediator
{
    smtp m_smtp;
    imap m_imap;

    static constexpr uint8_t request_transaction = 0;
    static constexpr uint8_t response_transaction = 1;

    reference receive(const std::regex& pattern, uint8_t variant)
    {
        std::smatch match;
        std::string message = m_imap.pull(variant);
        if (std::regex_match(message, match, pattern))
        {
            return std::make_pair(
                utils::parse_endpoint<boost::asio::ip::udp::endpoint>(match[1].str(), match[2].str()),
                boost::lexical_cast<uint64_t>(match[3].str())
            );
        }

        throw plexus::bad_message();
    }

public:

    mediator_impl(const config& conf) : m_smtp(conf), m_imap(conf)
    {
    }

    reference pull_request() noexcept(false) override
    {
        _inf_ << "waiting plexus request...";

        reference peer = receive(std::regex("^PLEXUS\\s+3.0\\s+0\\s+(\\S+)\\s+(\\d+)\\s+(\\d+)$"), request_transaction);

        _inf_ << "received plexus request " << peer.first;
        return peer;
    }

    reference pull_response() noexcept(false) override
    {
        _inf_ << "waiting plexus response...";

        reference peer = receive(std::regex("^PLEXUS\\s+3.0\\s+1\\s+(\\S+)\\s+(\\d+)\\s+(\\d+)$"), response_transaction);

        _inf_ << "received plexus response " << peer.first;
        return peer;
    }

    void push_request(const reference& host) noexcept(false) override
    {
        _inf_ << "sending plexus request...";

        m_smtp.push(plexus::utils::format("PLEXUS 3.0 0 %s %u %llu", host.first.address().to_string().c_str(), host.first.port(), host.second), request_transaction);

        _inf_ << "sent plexus request " << host.first;
    }

    void push_response(const reference& host) noexcept(false) override
    {
        _inf_ << "sending plexus response...";

        m_smtp.push(plexus::utils::format("PLEXUS 3.0 1 %s %u %llu", host.first.address().to_string().c_str(), host.first.port(), host.second), response_transaction);

        _inf_ << "sent plexus response " << host.first;
    }
};

}

std::shared_ptr<listener> create_email_listener(const boost::asio::ip::tcp::endpoint& imap,
                                                const std::string& login,
                                                const std::string& passwd,
                                                const std::string& cert,
                                                const std::string& key,
                                                const std::string& ca,
                                                const std::string& app,
                                                const std::string& repo)
{
    _dbg_ << "imap server: " << imap;

    return std::make_shared<email::imap>(email::config{{}, imap, login, passwd, cert, key, ca, app, repo, {}, {}});
}

std::shared_ptr<mediator> create_email_mediator(const boost::asio::ip::tcp::endpoint& smtp,
                                                const boost::asio::ip::tcp::endpoint& imap,
                                                const std::string& login,
                                                const std::string& passwd,
                                                const std::string& cert,
                                                const std::string& key,
                                                const std::string& ca,
                                                const std::string& app,
                                                const std::string& repo,
                                                const subscriber& host,
                                                const subscriber& peer)
{
    _dbg_ << "smtp server: " << smtp;
    _dbg_ << "imap server: " << imap;

    return std::make_shared<email::mediator_impl>(email::config{smtp, imap, login, passwd, cert, key, ca, app, repo, host, peer});
}

}
