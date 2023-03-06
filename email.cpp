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
#include <logger.h>
#include <string>
#include <list>
#include <iostream>
#include <sstream>
#include <cstring>
#include <memory>
#include <regex>
#include <functional>
#include <thread>

namespace plexus {

const bool ENABLE_IMAP_IDLE = plexus::utils::getenv<int64_t>("ENABLE_IMAP_IDLE", true);
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
    std::string from;
    std::string to;
    std::string host_id;
    std::string peer_id;
    std::string cert;
    std::string key;
    std::string ca;

    struct
    {
        std::string peer;
        std::string cert;
        std::string key;
        std::string ca;
    } smime;
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
			size_t read = m_ssl->read(m_buffer, BUFFER_SIZE, prolonged);
            response.append((char*)m_buffer, read);
        } while (!parse(response));

        _trc_ << ">>>>>\n" << response << "\n*****";
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

    std::string build_data(const std::string& data)
    {
        if (m_config.smime.peer.empty())
        {
            static const char* SIMPLE_EMAIL =
                "From: %s\r\n"
                "To: %s\r\n"
                "Subject: %s\r\n"
                "\r\n"
                "%s\r\n"
                ".\r\n";

            return utils::format(
                SIMPLE_EMAIL,
                m_config.from.c_str(),
                m_config.to.c_str(),
                m_config.host_id.c_str(),
                data.c_str()
                );
        }

        static const char* MULTIPART_EMAIL =
            "From: %s\r\n"
            "To: %s\r\n"
            "Subject: %s\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: multipart/mixed; boundary=----%s\r\n"
            "\r\n"
            "------%s\r\n"
            "%s\r\n"
            "------%s--\r\n"
            ".\r\n";

        std::string bound = plexus::utils::to_hexadecimal(m_config.to.data(), m_config.to.size());
        std::string content = plexus::utils::smime_encrypt(
            plexus::utils::smime_sign(data, m_config.smime.cert, m_config.smime.key),
            m_config.smime.peer
            );

        return utils::format(
            MULTIPART_EMAIL,
            m_config.from.c_str(),
            m_config.to.c_str(),
            m_config.host_id.c_str(),
            bound.c_str(),
            bound.c_str(),
            content.c_str(),
            bound.c_str()
            );
    }

public:
    
    smtp(const config& conf)
        : m_config(conf)
    {
    }

    void push(const std::string& data) noexcept(false)
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
        session->request(utils::format("MAIL FROM: %s\r\n", get_address(m_config.from).c_str()), code_checker(250));
        session->request(utils::format("RCPT TO: %s\r\n", get_address(m_config.to).c_str()), code_checker(250));
        session->request("DATA\r\n", code_checker(354));
        session->request(build_data(data), code_checker(250));
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
                    m_last_seen = 0;
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
                    if (uid > m_last_seen)
                        m_unseen.push_back(uid);
                }
            }
            return true;
        }
        return false;
    };

    const response_parser_t fetch_parser = [this](const std::string& response) -> bool {
        if (success_checker(response))
        {
            std::smatch match;
            if (std::regex_search(response, match, std::regex("^[^\\r\\n]+\\r\\n([\\s\\S]+)\\r\\n\\)\\r\\n.*")))
            {
                std::string raw = match[1].str();
                if (m_config.smime.peer.empty())
                {
                    m_data = match[1].str();
                }
                else
                {
                    try
                    {
                        m_data = plexus::utils::smime_verify(
                            plexus::utils::smime_decrypt(match[1].str(), m_config.smime.cert, m_config.smime.key),
                            m_config.smime.peer,
                            m_config.smime.ca
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

    const response_parser_t uid_parser = [this](const std::string& response) -> bool {
        if (success_checker(response))
        {
            std::smatch match;
            if (std::regex_search(response, match, std::regex("^\\*\\s+\\d+\\s+FETCH\\s+\\(UID\\s+(\\d+)\\)\\r\\n.*")))
            {
                std::stringstream ss;
                ss << match[1].str();
                ss >> m_last_seen;
            }
            return true;
        }
        return false;
    };

    const response_parser_t idle_parser = [this](const std::string& response) -> bool {
        std::smatch match;
        if (std::regex_search(response, match, std::regex("(.*\\r\\n)?x\\s+(NO|BAD)\\s+.*\\r\\n$")))
        {
            if (match[1] != "BAD")
                throw bad_command();
            throw std::runtime_error(response);
        }
        return std::regex_search(response, match, std::regex("^\\+\\s+idling(\\r\\n.*)+\\*\\s+\\d+\\s+EXISTS(\\r\\n.*)*\\r\\n$"));
    };

    inline std::string pull_data()
    {
        std::string data;
        std::swap(data, m_data);
        return data;
    }

public:

    imap(const config& conf)
        : m_config(conf)
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

    std::string pull(bool idle = false) noexcept(false)
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

        auto time = std::chrono::system_clock::now();
        do
        {
            session->request(utils::format("x UID SEARCH (SINCE %s) (From %s) (To %s) (Subject \"%s\")\r\n",
                utils::format("%d-%b-%Y", time).c_str(),
                get_address(m_config.from).c_str(),
                get_address(m_config.to).c_str(),
                m_config.peer_id.c_str()
            ), search_parser);

            if (m_unseen.empty() && idle)
            {
                try
                {
                    session->request("x IDLE\r\n", idle_parser, true);
                    session->request("DONE\r\n", success_checker);
                }
                catch (const bad_command&)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(MAX_POLLING_TIMEOUT));
                }
            }
        }
        while (m_unseen.empty() && idle);

        std::string data;
        while (data.empty() && !m_unseen.empty())
        {
            auto uid = m_unseen.front();
            session->request(
                utils::format("x UID FETCH %d (BODY.PEEK[TEXT])\r\n", uid), fetch_parser
            );
            
            m_unseen.pop_front();
            m_last_seen = uid;

            data = pull_data();
        }

        return data;
    }

private:

    config m_config;
    std::list<uint64_t> m_unseen;
    std::string m_data;
    uint64_t m_last_seen = 0;
    uint64_t m_validity = 0;
};

}

using namespace email;

class email_mediator : public mediator
{
    smtp m_smtp;
    imap m_imap;

    reference receive(const std::regex& pattern, int64_t deadline = std::numeric_limits<int64_t>::max())
    {
        bool idle = ENABLE_IMAP_IDLE && deadline == std::numeric_limits<int64_t>::max();
        int64_t timeout = std::max<int64_t>(MIN_POLLING_TIMEOUT, std::min<int64_t>(MAX_POLLING_TIMEOUT, deadline / 12));

        auto clock = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        reference peer;
        do
        {
            std::string message = m_imap.pull(idle);

            while (!message.empty())
            {
                std::smatch match;
                if (std::regex_search(message, match, pattern))
                {
                    peer = std::make_pair(
                        utils::parse_endpoint<boost::asio::ip::udp::endpoint>(match[1].str(), match[2].str()),
                        boost::lexical_cast<uint64_t>(match[3].str())
                    );
                }

                message = m_imap.pull();
            }

            if (!peer.first.address().is_unspecified())
                return peer;

            if (!idle)
                std::this_thread::sleep_for(std::chrono::milliseconds(timeout));
        }
        while (clock().total_milliseconds() < deadline);

        throw plexus::timeout_error();
    }

public:

    email_mediator(const config& conf)
        : m_smtp(conf)
        , m_imap(conf)
    {
    }
    
    reference receive_request() noexcept(false)
    {
        _inf_ << "waiting plexus request...";

        reference peer = receive(std::regex("^PLEXUS\\s+2.1\\s+request\\s+(\\S+)\\s+(\\d+)\\s+(\\d+)$"));

        _inf_ << "received plexus request " << peer.first;
        return peer;
    }

    reference receive_response() noexcept(false)
    {
        _inf_ << "waiting plexus response...";

        reference peer = receive(std::regex("^PLEXUS\\s+2.1\\s+response\\s+(\\S+)\\s+(\\d+)\\s+(\\d+)$"), RESPONSE_TIMEOUT);

        _inf_ << "received plexus response " << peer.first;
        return peer;
    }

    void dispatch_request(const reference& host) noexcept(false) override
    {
        _inf_ << "sending plexus request...";

        m_smtp.push(plexus::utils::format("PLEXUS 2.1 request %s %u %llu", host.first.address().to_string().c_str(), host.first.port(), host.second));

        _inf_ << "sent plexus request " << host.first;
    }

    void dispatch_response(const reference& host) noexcept(false) override
    {
        _inf_ << "sending plexus response...";

        m_smtp.push(plexus::utils::format("PLEXUS 2.1 response %s %u %llu", host.first.address().to_string().c_str(), host.first.port(), host.second));
        
        _inf_ << "sent plexus response " << host.first;
    }
};

std::shared_ptr<mediator> create_email_mediator(const std::string& host_id,
                                                const std::string& peer_id,
                                                const std::string& smtp,
                                                const std::string& imap,
                                                const std::string& login,
                                                const std::string& passwd,
                                                const std::string& from,
                                                const std::string& to,
                                                const std::string& cert,
                                                const std::string& key,
                                                const std::string& ca,
                                                const std::string& smime_peer,
                                                const std::string& smime_cert,
                                                const std::string& smime_key,
                                                const std::string& smime_ca)
{
    return std::make_shared<email_mediator>(config{
        utils::parse_endpoint<boost::asio::ip::tcp::endpoint>(smtp, "smtps"),
        utils::parse_endpoint<boost::asio::ip::tcp::endpoint>(imap, "imaps"),
        login, passwd,
        from, to, host_id, peer_id,
        cert, key, ca,
        { smime_peer, smime_cert, smime_key, smime_ca }});
}

}
