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

const int64_t RESPONSE_TIMEOUT = plexus::utils::getenv<int64_t>("PLEXUS_RESPONSE_TIMEOUT", 60000);
const int64_t MAX_POLLING_TIMEOUT = plexus::utils::getenv<int64_t>("PLEXUS_MAX_POLLING_TIMEOUT", 30000);
const int64_t MIN_POLLING_TIMEOUT = plexus::utils::getenv<int64_t>("PLEXUS_MIN_POLLING_TIMEOUT", 5000);

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
    std::string app_id;
    std::string cred_repo;

    bool is_exists(const abonent& info) const
    {
        return std::filesystem::exists(std::filesystem::path(std::filesystem::path(cred_repo) / info.first / info.second));
    }

    std::string get_cert(const abonent& info) const 
    {
        std::filesystem::path cert(std::filesystem::path(cred_repo) / info.first / info.second / "cert.crt");
        return std::filesystem::exists(cert) ? cert.generic_u8string() : "";
    }

    std::string get_ca(const abonent& info) const 
    {
        std::filesystem::path ca(std::filesystem::path(cred_repo) / info.first / info.second / "ca.crt");
        return std::filesystem::exists(ca) ? ca.generic_u8string() : "";
    }
        
    std::string get_key(const abonent& info) const 
    {
        std::filesystem::path key(std::filesystem::path(cred_repo) / info.first / info.second / "private.key");
        return std::filesystem::exists(key) ? key.generic_u8string() : "";
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

std::string get_address(const std::string& email)
{
    std::smatch match;
    if (std::regex_search(email, match, std::regex("[\\w\\s]*\\<([^\\<]+@[^\\>]+)\\>\\s*")))
    {
        return match[1].str();
    }
    return email;
}

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

    std::string build_data(const abonent& from, const abonent& to, const std::string& message)
    {
        static const char* MULTIPART_EMAIL =
            "X-Sender: %s\r\n"
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

        std::string bound = plexus::utils::to_hexadecimal(from.first.data(), from.first.size());
        std::string content = plexus::utils::smime_encrypt(
            plexus::utils::smime_sign(message, m_config.get_cert(from), m_config.get_key(from)),
            m_config.get_cert(to)
            );

        return utils::format(
            MULTIPART_EMAIL,
            m_config.app_id.c_str(),
            from.second.c_str(),
            to.second.c_str(),
            from.first.c_str(),
            to.first.c_str(),
            bound.c_str(),
            bound.c_str(),
            message.c_str(),
            bound.c_str()
            );
    }

public:
    
    smtp(const config& conf) : m_config(conf)
    {
    }

    void push(const abonent& from, const abonent& to, const std::string& message) noexcept(false)
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
        session->request(utils::format("MAIL FROM: %s\r\n", get_address(from.first).c_str()), code_checker(250));
        session->request(utils::format("RCPT TO: %s\r\n", get_address(to.first).c_str()), code_checker(250));
        session->request("DATA\r\n", code_checker(354));
        session->request(build_data(from, to, message), code_checker(250));
    }

private:

    config m_config;
};

class imap
{
    typedef channel::response_parser_t response_parser_t;
    
    struct bad_command : public std::runtime_error { bad_command() : std::runtime_error("bad command") {} };

    const response_parser_t connect_checker = [](const std::string& response) -> bool {
            std::smatch match;
            bool done = std::regex_search(response, match, std::regex("^\\*\\s+(OK|NO)\\s+.*\\r\\n$"));
            if (done && match[1] != "OK")
                throw std::runtime_error(response);
            return done;
        };

    const response_parser_t success_checker = [](const std::string& response) -> bool {
        std::smatch match;
        bool done = std::regex_search(response, match, std::regex("(.*\\r\\n)?x\\s+(OK|NO)\\s+.*\\r\\n$"));
        if (done && match[2] != "OK")
            throw std::runtime_error(response);
        return done;
    };

    const response_parser_t select_parser = [this](const std::string& response) -> bool {
        if (success_checker(response))
        {
            std::smatch match;
            if (std::regex_search(response, match, std::regex(".*\\n\\*\\s+OK\\s+\\[UIDVALIDITY\\s+(\\d+)\\]$.*")))
            {
                std::stringstream ss;
                ss << match[1].str();

                uint64_t validity;
                ss >> validity;

                if (validity != m_validity)
                {
                    m_last = 0;
                    m_unseen.clear();
                }

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
            if (std::regex_search(response, match, std::regex("^\\*\\s+SEARCH\\s+([\\d\\f\\t\\v ]+).*")))
            {
                std::stringstream stream;
                stream << match[1].str();

                uint64_t uid = 0;
                while (stream >> uid)
                {
                    if (uid > m_last)
                        m_unseen.push_back(uid);
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
            if (std::regex_search(response, match, std::regex("^\\*\\s+\\d+\\s+FETCH\\s+\\(UID\\s+(\\d+)\\)\\r\\n.*")))
            {
                std::stringstream ss;
                ss << match[1].str();
                ss >> m_last;
            }
            return true;
        }
        return false;
    };

    const response_parser_t idle_parser = [](const std::string& response) -> bool {
        std::smatch match;
        if (std::regex_search(response, match, std::regex("(.*\\r\\n)?x\\s+(NO|BAD)\\s+.*\\r\\n$")))
        {
            if (match[1] != "BAD")
                throw bad_command();
            throw std::runtime_error(response);
        }
        return std::regex_search(response, match, std::regex("^\\+\\s+idling(\\r\\n.*)+\\*\\s+\\d+\\s+EXISTS(\\r\\n.*)*\\r\\n$"));
    };

    const response_parser_t fetch_parser(abonent& from, abonent& whom)
    {
        return [&](const std::string& response) -> bool
        {
            if (success_checker(response))
            {
                std::regex pattern(utils::format("^[^\\(\\r\\n]+\\([^\\r\\n]+\\r\\n"
                                                "X-Source:\\s+(%s)\\r\\n\\r\\n"
                                                "[^\\r\\n]+\\r\\n"
                                                "X-Target:\\s+(%s)\\r\\n\\r\\n"
                                                "[^\\r\\n]+\\r\\n"
                                                "From:\\s+(%s)\\r\\n\\r\\n"
                                                "[^\\r\\n]+\\r\\n"
                                                "To:\\s+(%s)\\r\\n\\r\\n"
                                                "[^\\r\\n]+\\r\\n"
                                                "(.*)\\r\\n\\r\\n"
                                                "\\)\\r\\n.*",
                                                from.second.empty() ? "[^\\r\\n]+" : from.second.c_str(),
                                                whom.second.empty() ? "[^\\r\\n]+" : whom.second.c_str(),
                                                from.first.empty() ? "[^\\r\\n]+" : from.first.c_str(),
                                                whom.first.empty() ? "[^\\r\\n]+" : whom.first.c_str(),
                                                m_config.passwd.c_str()));

                std::smatch match;
                if (std::regex_search(response, match, pattern))
                {
                    from = std::make_pair(match[1].str(), match[3].str());
                    whom = std::make_pair(match[2].str(), match[4].str());
                    if (m_config.is_exists(from) && m_config.is_exists(whom))
                    {
                        try
                        {
                            m_message = plexus::utils::smime_verify(
                                plexus::utils::smime_decrypt(match[5].str(), m_config.get_cert(whom), m_config.get_key(whom)),
                                m_config.get_cert(from),
                                m_config.get_ca(from)
                                );
                        }
                        catch(const std::exception& ex)
                        {
                            _err_ << ex.what();
                        }
                    }
                }
                return true;
            }
            return false;
        };
    }

public:

    imap(const config& conf) : m_config(conf)
    {
        std::unique_ptr<channel> session = std::make_unique<channel>(
            m_config.imap,
            m_config.cert,
            m_config.key,
            m_config.ca
        );

        session->connect(connect_checker);
        session->request(utils::format("x LOGIN %s %s\r\n", m_config.login.c_str(), m_config.passwd.c_str()), success_checker);
        session->request("x SELECT INBOX\r\n", select_parser);
        session->request("x FETCH * UID\r\n", uid_parser);
    }

    std::string pull(abonent& from, abonent& whom, int64_t deadline) noexcept(false)
    {
        auto clock = [start = boost::posix_time::microsec_clock::universal_time()]()
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
        session->request(utils::format("x LOGIN %s %s\r\n", m_config.login.c_str(), m_config.passwd.c_str()), success_checker);
        session->request("x SELECT INBOX\r\n", select_parser);

        do
        {
            auto time = std::chrono::system_clock::now();
            while (m_unseen.empty())
            {
                session->request(
                    utils::format("x UID SEARCH (SINCE %s) (X-Sender %s)\r\n", utils::format("%d-%b-%Y", time).c_str(), m_config.app_id.c_str()),
                    search_parser
                    );

                if (m_unseen.empty())
                {
                    if (deadline == std::numeric_limits<int64_t>::max())
                    {
                        try
                        {
                            session->request("x IDLE\r\n", idle_parser, true);
                            session->request("DONE\r\n", success_checker);
                        }
                        catch (const bad_command&)
                        {
                            session->snooze(MAX_POLLING_TIMEOUT);
                        }
                    }
                    else
                    {
                        session->snooze(MIN_POLLING_TIMEOUT);
                    }
                }
            }

            while (m_message.empty() && !m_unseen.empty())
            {
                auto uid = m_unseen.front();
                session->request(
                    utils::format("x UID FETCH %d (BODY.PEEK[TEXT])\r\n", uid), fetch_parser(from, whom)
                );

                m_unseen.pop_front();
                m_last = uid;
            }
        }
        while (m_message.empty() && clock().total_milliseconds() < deadline);

        if (m_message.empty())
            throw plexus::timeout_error();

        return std::move(m_message);
    }

private:

    config m_config;
    std::string m_message;
    std::list<uint64_t> m_unseen;
    uint64_t m_validity = 0;
    uint64_t m_last = 0;
};

}

using namespace email;

class email_mediator : public mediator
{
    smtp m_smtp;
    imap m_imap;

    reference receive(abonent& from, abonent& whom, const std::regex& pattern, int64_t deadline = std::numeric_limits<int64_t>::max())
    {
        std::smatch match;
        std::string message = m_imap.pull(from, whom, deadline);
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

    email_mediator(const config& conf)
        : m_smtp(conf)
        , m_imap(conf)
    {
    }

    reference receive_request(abonent& from, abonent& whom) noexcept(false) override
    {
        _inf_ << "waiting plexus request...";

        reference peer = receive(from, whom, std::regex("^PLEXUS\\s+2.1\\s+request\\s+(\\S+)\\s+(\\d+)\\s+(\\d+)$"));

        _inf_ << "received plexus request " << peer.first;
        return peer;
    }

    reference receive_response(abonent& from, abonent& whom) noexcept(false) override
    {
        _inf_ << "waiting plexus response...";

        reference peer = receive(from, whom, std::regex("^PLEXUS\\s+2.1\\s+response\\s+(\\S+)\\s+(\\d+)\\s+(\\d+)$"), RESPONSE_TIMEOUT);

        _inf_ << "received plexus response " << peer.first;
        return peer;
    }

    void dispatch_request(const abonent& from, const abonent& to, const reference& host) noexcept(false) override
    {
        _inf_ << "sending plexus request...";

        m_smtp.push(from, to, plexus::utils::format("PLEXUS 2.1 request %s %u %llu", host.first.address().to_string().c_str(), host.first.port(), host.second));

        _inf_ << "sent plexus request " << host.first;
    }

    void dispatch_response(const abonent& from, const abonent& to, const reference& host) noexcept(false) override
    {
        _inf_ << "sending plexus response...";

        m_smtp.push(from, to, plexus::utils::format("PLEXUS 2.1 response %s %u %llu", host.first.address().to_string().c_str(), host.first.port(), host.second));

        _inf_ << "sent plexus response " << host.first;
    }
};

std::shared_ptr<mediator> create_email_mediator(const boost::asio::ip::tcp::endpoint& smtp,
                                                const boost::asio::ip::tcp::endpoint& imap,
                                                const std::string& login,
                                                const std::string& passwd,
                                                const std::string& cert,
                                                const std::string& key,
                                                const std::string& ca,
                                                const std::string& app_id,
                                                const std::string& cred_repo)
{
    _dbg_ << "smtp server: " << smtp;
    _dbg_ << "imap server: " << imap;

    return std::make_shared<email_mediator>(config{smtp, imap, login, passwd, cert, key, ca, app_id, cred_repo});
}

}
