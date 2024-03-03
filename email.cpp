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
#include <cstdint>
#include <filesystem>
#include <logger.h>
#include <string>
#include <iostream>
#include <memory>
#include <regex>
#include <functional>

namespace plexus {

const int64_t response_timeout = plexus::utils::getenv<int64_t>("PLEXUS_RESPONSE_TIMEOUT", 60000);
const int64_t max_polling_timeout = plexus::utils::getenv<int64_t>("PLEXUS_MAX_POLLING_TIMEOUT", 30000);
const int64_t min_polling_timeout = plexus::utils::getenv<int64_t>("PLEXUS_MIN_POLLING_TIMEOUT", 10000);
const std::string invite_token = plexus::utils::getenv<std::string>("PLEXUS_INVITE_TOKEN", "invite");
const std::string accept_token = plexus::utils::getenv<std::string>("PLEXUS_ACCEPT_TOKEN", "accept");

std::ostream& operator<<(std::ostream& stream, const reference& value)
{
    if (stream.rdbuf())
        return stream << value.endpoint << "/" << value.puzzle;
    return stream;
}

std::ostream& operator<<(std::ostream& stream, const identity& value)
{
    if (stream.rdbuf())
        return stream << value.owner << "/" << value.pin;
    return stream;
}

std::istream& operator>>(std::istream& in, reference& value)
{
    std::string str;
    in >> str;

    std::smatch match;
    if (std::regex_match(str, match, std::regex("^([\\S]*)/([\\S]*)$")))
    {
        value.endpoint = plexus::utils::parse_endpoint<boost::asio::ip::udp::endpoint>(match[1].str(), "");
        value.puzzle = boost::lexical_cast<uint64_t>(match[2].str());
        return in;
    }

    throw boost::bad_lexical_cast();
}

std::istream& operator>>(std::istream& in, identity& value)
{
    std::string str;
    in >> str;

    std::smatch match;
    if (std::regex_match(str, match, std::regex("^([\\S]*)/([\\S]*)$")))
    {
        value.owner = match[1].str();
        value.pin = match[2].str();
    }
    else
    {
        value.owner = str;
        value.pin = "";
    }
    return in;
}

namespace email {

using namespace wormhole;

struct context
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

    bool is_defined(const identity& host, const identity& peer) const
    {
        return !host.owner.empty() && !host.pin.empty() && !peer.owner.empty() && !peer.pin.empty();
    }

    bool is_existent(const identity& host, const identity& peer) const
    {
        return is_defined(host, peer)
            && std::filesystem::exists(std::filesystem::path(std::filesystem::path(repo) / host.owner / host.pin))
            && std::filesystem::exists(std::filesystem::path(std::filesystem::path(repo) / peer.owner / peer.pin));
    }

    bool is_encryptable(const identity& host, const identity& peer) const
    {
        return std::filesystem::exists(std::filesystem::path(std::filesystem::path(repo) / host.owner / host.pin / "cert.crt"))
            && std::filesystem::exists(std::filesystem::path(std::filesystem::path(repo) / host.owner / host.pin / "private.key"))
            && std::filesystem::exists(std::filesystem::path(std::filesystem::path(repo) / peer.owner / peer.pin / "cert.crt"));
    }

    std::string get_cert(const identity& info) const 
    {
        std::filesystem::path cert(std::filesystem::path(repo) / info.owner / info.pin / "cert.crt");
        return std::filesystem::exists(cert) ? cert.generic_u8string() : "";
    }

    std::string get_key(const identity& info) const 
    {
        std::filesystem::path key(std::filesystem::path(repo) / info.owner / info.pin / "private.key");
        return std::filesystem::exists(key) ? key.generic_u8string() : "";
    }

    std::string get_ca(const identity& info) const 
    {
        std::filesystem::path ca(std::filesystem::path(repo) / info.owner / info.pin / "ca.crt");
        return std::filesystem::exists(ca) ? ca.generic_u8string() : "";
    }
};

class channel
{
    static const size_t BUFFER_SIZE = 8192;

public:

    channel(boost::asio::io_service& io, const boost::asio::ip::tcp::endpoint& remote, const std::string& cert, const std::string& key, const std::string& ca)
        : m_ssl(network::create_ssl_client(io, remote, cert, key, ca))
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

    void request(const std::string& request, const response_parser_t& parse, int64_t timeout = 0)
    {
        _trc_ << "<<<<<\n" << request << "\n*****";

		size_t written = 0;
        do {
            written += m_ssl->write((const uint8_t*)request.c_str() + written, request.size() - written);
        } while (written < request.size());

        std::string response;
        try
        {

            do {
                size_t read = m_ssl->read(m_buffer, BUFFER_SIZE, timeout == 0 ? network::default_tcp_timeout_ms : timeout);
                response.append((char*)m_buffer, read);
            } while (!parse(response));
        }
        catch (const boost::system::system_error& ex)
        {
            if (timeout == 0 || ex.code() != boost::asio::error::operation_aborted)
                throw;
        }

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

    std::string build_data(const std::string& subject, const std::string& message)
    {
        if (!m_config.is_encryptable(m_host, m_peer))
        {
            static const char* SIMPLE_EMAIL =
                "From: %s <%s>\r\n"
                "To: %s <%s>\r\n"
                "Subject: %s %s\r\n"
                "\r\n"
                "%s\r\n"
                ".\r\n";

            return utils::format(
                SIMPLE_EMAIL,
                m_host.pin.c_str(),
                m_host.owner.c_str(),
                m_peer.pin.c_str(),
                m_peer.owner.c_str(),
                m_config.app.c_str(),
                subject.c_str(),
                message.c_str()
                );
        }

        static const char* MULTIPART_EMAIL =
            "From: %s <%s>\r\n"
            "To: %s <%s>\r\n"
            "Subject: %s %s\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: multipart/mixed; boundary=----%s\r\n"
            "\r\n"
            "------%s\r\n"
            "%s\r\n"
            "------%s--\r\n"
            ".\r\n";

        std::string bound = plexus::utils::to_hexadecimal(m_host.owner.data(), m_host.owner.size());
        std::string content = plexus::utils::smime_encrypt(
            plexus::utils::smime_sign(message, m_config.get_cert(m_host), m_config.get_key(m_host)),
            m_config.get_cert(m_peer)
            );

        return utils::format(
            MULTIPART_EMAIL,
            m_host.pin.c_str(),
            m_host.owner.c_str(),
            m_peer.pin.c_str(),
            m_peer.owner.c_str(),
            m_config.app.c_str(),
            subject.c_str(),
            bound.c_str(),
            bound.c_str(),
            content.c_str(),
            bound.c_str()
            );
    }

public:
    
    smtp(boost::asio::io_service& io, const context& conf, const identity& host, const identity& peer)
        : m_io(io)
        , m_config(conf)
        , m_host(host)
        , m_peer(peer)
    {
    }

    void push(const std::string& subject, const reference& data) noexcept(false)
    {
        if (!m_config.is_defined(m_host, m_peer))
            throw bad_identity();

        std::unique_ptr<channel> session = std::make_unique<channel>(
            m_io,
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
        session->request(utils::format("MAIL FROM: %s\r\n", m_host.owner.c_str()), code_checker(250));
        session->request(utils::format("RCPT TO: %s\r\n", m_peer.owner.c_str()), code_checker(250));
        session->request("DATA\r\n", code_checker(354));
        session->request(build_data(subject, plexus::utils::format("PLEXUS 3.0 %s %u %llu", data.endpoint.address().to_string().c_str(), data.endpoint.port(), data.puzzle)), code_checker(250));
        session->request("QUIT\r\n", code_checker(221));
    }

    const identity& host() const noexcept(true)
    {
        return m_host;
    }

    const identity& peer() const noexcept(true)
    {
        return m_peer;
    }

    void host(const identity& info) noexcept(true)
    {
        m_host = info;
    }

    void peer(const identity& info) noexcept(true)
    {
        m_peer = info;
    }

private:

    boost::asio::io_service& m_io;
    context m_config;
    identity m_host;
    identity m_peer;
};

class imap
{
    typedef channel::response_parser_t response_parser_t;

    const response_parser_t connect_checker = [](const std::string& response) -> bool {
            std::smatch match;
            bool done = std::regex_search(response, match, std::regex("^\\* (OK|NO) .*\\r\\n$"));
            if (done && match[1] != "OK")
                throw std::runtime_error(response);
            return done;
        };

    const response_parser_t success_checker = [](const std::string& response) -> bool {
        std::smatch match;
        bool done = std::regex_search(response, match, std::regex("(.*\\r\\n)?\\d+ (OK|NO) .*\\r\\n$"));
        if (done && match[2] != "OK")
            throw std::runtime_error(response);
        return done;
    };

    const response_parser_t login_parser = [this](const std::string& response) -> bool {
        if (success_checker(response))
        {
            std::smatch match;
            m_idle = std::regex_search(response, match, std::regex("\\* CAPABILITY[^\\r\\n]+IDLE.*"));
            return true;
        }
        return false;
    };

    const response_parser_t select_parser = [this](const std::string& response) -> bool {
        if (success_checker(response))
        {
            std::smatch match;
            if (std::regex_search(response, match, std::regex("\\[UIDVALIDITY (\\d+)\\]")))
            {
                std::stringstream ss;
                ss << match[1].str();

                uint64_t validity;
                ss >> validity;

                if (validity != m_validity)
                    m_position = 0;

                m_validity = validity;
            }
            return true;
        }
        return false;
    };

    const response_parser_t search_parser = [=](const std::string& response) -> bool {
        if (success_checker(response))
        {
            std::smatch match;
            if (std::regex_search(response, match, std::regex("\\* SEARCH ([\\d ]+)\\r\\n.*")))
            {
                std::stringstream stream;
                stream << match[1].str();

                uint64_t uid = 0;
                while (stream >> uid)
                {
                    if (uid > m_position)
                    {
                        m_position = uid;
                        break;
                    }
                }
            }
            return true;
        }
        return false;
    };

    const response_parser_t end_parser = [this](const std::string& response) -> bool {
        if (success_checker(response))
        {
            std::smatch match;
            if (std::regex_search(response, match, std::regex("\\* \\d+ FETCH +\\(UID (\\d+)\\)\\r\\n.*")))
            {
                std::stringstream ss;
                ss << match[1].str();
                ss >> m_position;
            }
            return true;
        }
        return false;
    };

    const response_parser_t idle_parser = [](const std::string& response) -> bool {
        std::smatch match;
        if (std::regex_search(response, match, std::regex("(.*\\r\\n)?\\d+ (NO|BAD) .*\\r\\n")))
            throw std::runtime_error(response);
        return std::regex_search(response, match, std::regex("\\+ idling\\r\\n.+\\r\\n"));
    };

    const response_parser_t fetch_parser = [&](const std::string& response) -> bool
    {
        if (success_checker(response))
        {
            static const std::regex pattern(".*\\r\\nFrom: ([^\\r\\n]+) <([^\\r\\n]+)>\\r\\n\\r\\n"
                                            ".*\\r\\nTo: ([^\\r\\n]+) <([^\\r\\n]+)>\\r\\n\\r\\n"
                                            "[^\\r\\n]+\\r\\n([\\s\\S]+)\\r\\n\\)\\r\\n.*");

            std::smatch match;
            if (std::regex_search(response, match, pattern))
            {
                identity peer = { match[1].str(), match[2].str() };
                identity host = { match[3].str(), match[4].str() };

                if (m_config.is_defined(m_host, m_peer) || m_config.is_existent(host, peer))
                {
                    std::string message;
                    if (m_config.is_encryptable(host, peer))
                    {
                        message = plexus::utils::smime_verify(
                            plexus::utils::smime_decrypt(match[1].str(), m_config.get_cert(m_host), m_config.get_key(m_host)),
                            m_config.get_cert(m_peer),
                            m_config.get_ca(m_peer)
                            );
                    }
                    else
                    {
                        message = match[1].str();
                    }

                    if (std::regex_match(message, match, std::regex("^PLEXUS 3.0 (\\S+) (\\d+) (\\d+)$")))
                    {
                        m_data.endpoint = utils::parse_endpoint<boost::asio::ip::udp::endpoint>(match[1].str(), match[2].str());
                        m_data.puzzle = boost::lexical_cast<uint64_t>(match[3].str());
                        m_host = host;
                        m_peer = peer;
                    }
                }
            }
            return true;
        }
        return false;
    };

     std::string make_filter(const std::string& subject)
    {
        std::string filter = utils::format("(UID %d:*) (Subject %s) (Subject %s)", m_position + 1, m_config.app.c_str(), subject.c_str());

        if (!m_peer.pin.empty())
            filter += utils::format(" (From %s)", m_peer.pin.c_str());
        if (!m_peer.owner.empty())
            filter += utils::format(" (From %s)", m_peer.owner.c_str());
        if (!m_host.pin.empty())
            filter += utils::format(" (To %s)", m_host.pin.c_str());
        if (!m_host.owner.empty())
            filter += utils::format(" (To %s)", m_host.owner.c_str());

        return filter;
    }

public:

    imap(boost::asio::io_service& io, const context& conf, const identity& host, const identity& peer)
        : m_io(io)
        , m_config(conf)
        , m_host(host)
        , m_peer(peer)
    {
        std::unique_ptr<channel> session = std::make_unique<channel>(
            m_io,
            m_config.imap,
            m_config.cert,
            m_config.key,
            m_config.ca
        );

        uint8_t seq = 0;
        session->connect(connect_checker);
        session->request(utils::format("%u LOGIN %s %s\r\n", ++seq, m_config.login.c_str(), m_config.passwd.c_str()), login_parser);
        session->request(utils::format("%u SELECT INBOX\r\n", ++seq), select_parser);
        session->request(utils::format("%u FETCH * UID\r\n", ++seq), end_parser);
        session->request(utils::format("%u LOGOUT\r\n", ++seq), success_checker);
    }

    void wait(const std::string& subject, bool infinite = true) noexcept(false)
    {
        m_data = {};

        auto elapsed = [infinite, start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return infinite == false && (boost::posix_time::microsec_clock::universal_time() - start).total_milliseconds() > response_timeout;
        };

        std::unique_ptr<channel> session = std::make_unique<channel>(
            m_io,
            m_config.imap,
            m_config.cert,
            m_config.key,
            m_config.ca
        );

        uint8_t seq = 0;
        session->connect(connect_checker);
        session->request(utils::format("%u LOGIN %s %s\r\n", ++seq, m_config.login.c_str(), m_config.passwd.c_str()), login_parser);
        session->request(utils::format("%u SELECT INBOX\r\n", ++seq), select_parser);

        if (m_position == 0)
            session->request(utils::format("%u FETCH * UID\r\n", ++seq), end_parser);

        do
        {
            uint64_t end = m_position;
            session->request(utils::format("%u UID SEARCH %s\r\n", ++seq, make_filter(subject).c_str()), search_parser);

            if (m_position == end)
            {
                if (elapsed())
                    throw timeout_error();

                if (m_idle)
                {
                    session->request(utils::format("%u IDLE\r\n", ++seq), idle_parser, infinite ? max_polling_timeout : min_polling_timeout);
                    session->request("DONE\r\n", success_checker);
                }
                else
                {
                    session->snooze(infinite ? max_polling_timeout : min_polling_timeout);
                }
            }
            else
            {
                session->request(
                    utils::format("%u UID FETCH %d (BODY[HEADER.FIELDS (From)] BODY[HEADER.FIELDS (To)] BODY.PEEK[TEXT])\r\n", ++seq, m_position),
                    fetch_parser
                );
            }
        }
        while (m_data.endpoint.port() == 0);

        session->request(utils::format("%u UID STORE %d +flags \\DELETED\r\n", ++seq, m_position), success_checker);
        session->request(utils::format("%u LOGOUT\r\n", ++seq), success_checker);
    }

    const reference& pull(const std::string& subject)
    {
        if (m_data.endpoint.port() == 0)
            wait(subject, false);

        return m_data;
    }

    const identity& host() const noexcept(true)
    {
        return m_host;
    }

    const identity& peer() const noexcept(true)
    {
        return m_peer;
    }

    void host(const identity& info) noexcept(true)
    {
        m_host = info;
        m_data = {};
    }

    void peer(const identity& info) noexcept(true)
    {
        m_peer = info;
        m_data = {};
    }

private:

    boost::asio::io_service& m_io;
    context m_config;
    bool m_idle = false;
    uint64_t m_validity = 0;
    uint64_t m_position = 0;
    identity m_host;
    identity m_peer;
    reference m_data;
};

class pipe_impl : public pipe
{
    smtp m_pusher;
    imap m_puller;

public:

    pipe_impl(const smtp& pusher, const imap& puller) : m_pusher(pusher), m_puller(puller)
    {
    }

    const reference& pull_request() noexcept(false) override
    {
        const reference& faraway = m_puller.pull(invite_token);
        _inf_ << "pulled request " << faraway;
        return faraway;
    }

    const reference& pull_response() noexcept(false) override
    {
        const reference& faraway = m_puller.pull(accept_token);
        _inf_ << "pulled response " << faraway;
        return faraway;
    }

    void push_request(const reference& gateway) noexcept(false) override
    {
        m_pusher.push(invite_token, gateway);
        _inf_ << "pushed request " << gateway;
    }

    void push_response(const reference& gateway) noexcept(false) override
    {
        m_pusher.push(accept_token, gateway);
        _inf_ << "pushed response " << gateway;
    }

    const identity& host() const noexcept(true) override
    {
        return m_pusher.host();
    }

    const identity& peer() const noexcept(true) override
    {
        return m_puller.peer();
    }
};

class broker_impl : public broker
{
    boost::asio::io_service& m_io;
    smtp m_smtp;
    imap m_imap;
    identity m_host;
    identity m_peer;

public:

    broker_impl(boost::asio::io_service& io, const context& conf, const identity& host, const identity& peer)
        : m_io(io)
        , m_smtp(io, conf, host, peer)
        , m_imap(io, conf, host, peer)
        , m_host(host)
        , m_peer(peer)
    {
    }

    void accept(const broker_handler& handler) noexcept(false) override
    {
        try
        {
            do
            {
                m_imap.wait(invite_token);

                m_smtp.host(m_imap.host());
                m_smtp.peer(m_imap.peer());

                m_io.post([handler, pipe = std::make_shared<pipe_impl>(m_smtp, m_imap)]()
                {
                    try
                    {
                        _inf_ << "accepting peer=" << pipe->peer() << " for host=" << pipe->host();

                        handler(pipe);
                    }
                    catch (const std::exception &e)
                    {
                        _err_ << e.what();
                    }
                });

                m_imap.host(m_host);
                m_imap.peer(m_peer);
            }
            while (true);
        }
        catch (const std::exception &e)
        {
            _err_ << e.what();
        }
    }

    void invite(const broker_handler& handler) noexcept(false) override
    {
        m_io.post([handler, pipe = std::make_shared<pipe_impl>(m_smtp, m_imap)]()
        {
            try
            {
                _inf_ << "infiting peer=" << pipe->peer() << " for host=" << pipe->host();

                handler(pipe);
            }
            catch (const std::exception& e)
            {
                _err_ << e.what();
            }
        });
    }
};

}

std::shared_ptr<broker> create_email_broker(boost::asio::io_service& io,
                                            const boost::asio::ip::tcp::endpoint& smtp,
                                            const boost::asio::ip::tcp::endpoint& imap,
                                            const std::string& login,
                                            const std::string& passwd,
                                            const std::string& cert,
                                            const std::string& key,
                                            const std::string& ca,
                                            const std::string& app,
                                            const std::string& repo,
                                            const identity& host,
                                            const identity& peer)
{
    _dbg_ << "smtp server: " << smtp;
    _dbg_ << "imap server: " << imap;

    return std::make_shared<email::broker_impl>(io, email::context{smtp, imap, login, passwd, cert, key, ca, app, repo}, host, peer);
}

}
