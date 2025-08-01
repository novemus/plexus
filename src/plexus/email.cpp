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
#include <plexus/network.h>
#include <plexus/utils.h>
#include <wormhole/logger.h>
#include <boost/asio/spawn.hpp>
#include <string>
#include <iostream>
#include <memory>
#include <regex>
#include <functional>

namespace plexus { namespace email {

const int64_t response_timeout = plexus::utils::getenv<int64_t>("PLEXUS_RESPONSE_TIMEOUT", 60000);
const int64_t max_polling_timeout = plexus::utils::getenv<int64_t>("PLEXUS_MAX_POLLING_TIMEOUT", 30000);
const int64_t min_polling_timeout = plexus::utils::getenv<int64_t>("PLEXUS_MIN_POLLING_TIMEOUT", 10000);
const std::string invite_token = plexus::utils::getenv<std::string>("PLEXUS_INVITE_TOKEN", "invite");
const std::string accept_token = plexus::utils::getenv<std::string>("PLEXUS_ACCEPT_TOKEN", "accept");
const std::string advent_token = plexus::utils::getenv<std::string>("PLEXUS_ACCEPT_TOKEN", "advent");

class channel
{
    static constexpr size_t BUFFER_SIZE = 4096;

    std::shared_ptr<network::ssl_socket> m_ssl;

public:

    channel(boost::asio::io_context& io, const boost::asio::ip::tcp::endpoint& remote, const std::string& cert, const std::string& key, const std::string& ca)
    {
        try
        {
            m_ssl = network::create_ssl_client(io, remote, cert, key, ca);
        }
        catch (const boost::system::system_error& ex)
        {
            throw plexus::context_error(__FUNCTION__, ex.code());
        }
    }

    typedef std::function<bool(const std::string&)> response_parser_t;

    void connect(boost::asio::yield_context yield, const response_parser_t& parse)
    {
        try
        {
            m_ssl->connect(yield);
            m_ssl->handshake(boost::asio::ssl::stream_base::client, yield);

            std::string response;
            do
            {
                auto end = response.size();
                response.resize(end + BUFFER_SIZE);
                response.resize(end + m_ssl->read_some(boost::asio::buffer(response.data() + end, BUFFER_SIZE), yield));
            } 
            while (!parse(response));

            _trc_ << ">>>>>\n" << response << "\n*****";
        }
        catch (const boost::system::system_error& ex)
        {
            throw plexus::context_error(__FUNCTION__, ex.code());
        }
    }

    void request(boost::asio::yield_context yield, const std::string& request, const response_parser_t& parse, int64_t timeout = 0)
    {
        _trc_ << "<<<<<\n" << request << "\n*****";

        try
        {
            m_ssl->write(boost::asio::buffer(request), yield);
        }
        catch (const boost::system::system_error& ex)
        {
            throw plexus::context_error(__FUNCTION__, ex.code());
        }

        std::string response;
        try
        {
            do
            {
                auto end = response.size();
                response.resize(end + BUFFER_SIZE);
                response.resize(end + m_ssl->read_some(boost::asio::buffer(response.data() + end, BUFFER_SIZE), yield, timeout == 0 ? network::default_tcp_timeout_ms : timeout));
            }
            while (!parse(response));

            _trc_ << ">>>>>\n" << response << "\n*****";
        }
        catch (const boost::system::system_error& ex)
        {
            if (timeout == 0 || ex.code() != boost::asio::error::operation_aborted)
                throw plexus::context_error(__FUNCTION__, ex.code());
        }
    }

    void snooze(boost::asio::yield_context yield, int64_t timeout)
    {
        try
        {
            m_ssl->wait(boost::asio::socket_base::wait_read, yield, timeout);
        }
        catch (const boost::system::system_error& ex)
        {
            if (ex.code() != boost::asio::error::operation_aborted)
                throw plexus::context_error(__FUNCTION__, ex.code());
        }
    }
};

using context = context<plexus::emailer>;

class smtp
{
    typedef channel::response_parser_t response_parser_t;
    
    const response_parser_t code_checker(unsigned int code) const
    {
        return [code](const std::string& response) -> bool {
            std::smatch match;
            bool done = std::regex_search(response, match, std::regex("^(\\d+)\\s+.*\\r\\n$"));
            if (done && match[1] != std::to_string(code))
                throw plexus::context_error(__FUNCTION__, response);
            return done;
        };
    }

    std::string build_data(const std::string& subject, const std::string& message)
    {
        if (!m_config.are_encryptable(m_host, m_peer))
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
    
    smtp(boost::asio::io_context& io, const context& conf, const identity& host, const identity& peer)
        : m_io(io)
        , m_config(conf)
        , m_host(host)
        , m_peer(peer)
    {
        _dbg_ << "smtp server: " << m_config.smtp;
    }

    void push(boost::asio::yield_context yield, const std::string& subject, const reference& data) noexcept(false)
    {
        if (!m_config.are_defined(m_host, m_peer))
            throw plexus::context_error(__FUNCTION__, "bad identity");

        std::unique_ptr<channel> session = std::make_unique<channel>(
            m_io,
            m_config.smtp,
            m_config.cert,
            m_config.key,
            m_config.ca
        );

        session->connect(yield, code_checker(220));
        session->request(yield, "HELO smtp\r\n", code_checker(250));
        session->request(yield, "AUTH LOGIN\r\n", code_checker(334));
        session->request(yield, utils::format("%s\r\n", utils::to_base64_no_nl(m_config.login.c_str(), m_config.login.size()).c_str()), code_checker(334));
        session->request(yield, utils::format("%s\r\n", utils::to_base64_no_nl(m_config.password.c_str(), m_config.password.size()).c_str()), code_checker(235));
        session->request(yield, utils::format("MAIL FROM: %s\r\n", m_host.owner.c_str()), code_checker(250));
        session->request(yield, utils::format("RCPT TO: %s\r\n", m_peer.owner.c_str()), code_checker(250));
        session->request(yield, "DATA\r\n", code_checker(354));
        session->request(yield, build_data(subject, plexus::utils::format("PLEXUS 3.0 %s %u %llu", data.endpoint.address().to_string().c_str(), data.endpoint.port(), data.puzzle)), code_checker(250));
        session->request(yield, "QUIT\r\n", code_checker(221));
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

    boost::asio::io_context& m_io;
    context m_config;
    identity m_host;
    identity m_peer;
};

class imap
{
    typedef channel::response_parser_t response_parser_t;

    response_parser_t connect_checker;
    response_parser_t success_checker;
    response_parser_t idle_parser;
    response_parser_t login_parser;
    response_parser_t select_parser;
    response_parser_t search_parser;
    response_parser_t end_parser;
    response_parser_t fetch_parser;

    void make_parsers()
    {
        connect_checker = [](const std::string& response) -> bool {
                std::smatch match;
                bool done = std::regex_search(response, match, std::regex("^\\* (OK|NO) .*\\r\\n$"));
                if (done && match[1] != "OK")
                    throw plexus::context_error(__FUNCTION__, response);
                return done;
            };

        success_checker = [](const std::string& response) -> bool {
            std::smatch match;
            bool done = std::regex_search(response, match, std::regex("(.*\\r\\n)?\\d+ (OK|NO) .*\\r\\n$"));
            if (done && match[2] != "OK")
                throw plexus::context_error(__FUNCTION__, response);
            return done;
        };

        idle_parser = [](const std::string& response) -> bool {
            std::smatch match;
            if (std::regex_search(response, match, std::regex("(.*\\r\\n)?\\d+ (NO|BAD) .*\\r\\n")))
                throw plexus::context_error(__FUNCTION__, response);
            return std::regex_search(response, match, std::regex("\\+ idling\\r\\n.+\\r\\n"));
        };

        login_parser = [this](const std::string& response) -> bool {
            if (success_checker(response))
            {
                std::smatch match;
                m_idle = std::regex_search(response, match, std::regex("\\* CAPABILITY[^\\r\\n]+IDLE.*"));
                return true;
            }
            return false;
        };

        select_parser = [this](const std::string& response) -> bool {
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

        search_parser = [this](const std::string& response) -> bool {
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

        end_parser = [this](const std::string& response) -> bool {
            if (success_checker(response))
            {
                m_position = 0;
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

        fetch_parser = [this](const std::string& response) -> bool {
            if (success_checker(response))
            {
                static const std::regex pattern("From: ([^\\r\\n]+) <([^\\r\\n]+)>\\r\\nTo: ([^\\r\\n]+) <([^\\r\\n]+)>");

                std::smatch match;
                if (std::regex_search(response, match, pattern))
                {
                    identity peer = { match.str(2), match.str(1) };
                    identity host = { match.str(4), match.str(3) };

                    if (m_config.are_defined(m_host, m_peer) || m_config.are_allowed(host, peer))
                    {
                        static const std::regex pattern("BODY\\[TEXT\\] \\{(\\d+)\\}\\r\\n");

                        auto iter = std::sregex_iterator(response.begin(), response.end(), pattern);
                        if (iter == std::sregex_iterator())
                            return true;

                        std::string message = response.substr(iter->position() + iter->length(), boost::lexical_cast<size_t>(iter->str(1)));

                        if (m_config.are_encryptable(host, peer))
                        {
                            message = plexus::utils::smime_verify(
                                plexus::utils::smime_decrypt(message, m_config.get_cert(host), m_config.get_key(host)),
                                m_config.get_cert(peer),
                                m_config.get_ca(peer)
                                );
                        }

                        std::smatch match;
                        if (std::regex_match(message, match, std::regex("\\s*PLEXUS 3.0 (\\S+) (\\d+) (\\d+)\\s*")))
                        {
                            m_data.endpoint = utils::parse_endpoint<boost::asio::ip::udp::endpoint>(match.str(1), match.str(2));
                            m_data.puzzle = boost::lexical_cast<uint64_t>(match.str(3));
                            m_host = host;
                            m_peer = peer;
                        }
                    }
                }
                return true;
            }
            return false;
        };
    }

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

    imap(boost::asio::io_context& io, const context& conf, const identity& host, const identity& peer)
        : m_io(io)
        , m_config(conf)
        , m_host(host)
        , m_peer(peer)
    {
        _dbg_ << "imap server: " << m_config.imap;

        make_parsers();
    }

    imap(const imap& other)
        : m_io(other.m_io)
        , m_config(other.m_config)
        , m_idle(other.m_idle)
        , m_validity(other.m_validity)
        , m_position(other.m_position)
        , m_host(other.m_host)
        , m_peer(other.m_peer)
        , m_data(other.m_data)
    {
        make_parsers();
    }

    void init(boost::asio::yield_context yield)
    {
        std::unique_ptr<channel> session = std::make_unique<channel>(
            m_io,
            m_config.imap,
            m_config.cert,
            m_config.key,
            m_config.ca
        );

        uint8_t seq = 0;
        session->connect(yield, connect_checker);
        session->request(yield, utils::format("%u LOGIN %s %s\r\n", ++seq, m_config.login.c_str(), m_config.password.c_str()), login_parser);
        session->request(yield, utils::format("%u SELECT INBOX\r\n", ++seq), select_parser);
        session->request(yield, utils::format("%u FETCH * UID\r\n", ++seq), end_parser);
        session->request(yield, utils::format("%u LOGOUT\r\n", ++seq), success_checker);
    }

    void wait(boost::asio::yield_context yield, const std::string& subject, bool infinite = true) noexcept(false)
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

        uint64_t validity = m_validity;

        uint8_t seq = 0;
        session->connect(yield, connect_checker);
        session->request(yield, utils::format("%u LOGIN %s %s\r\n", ++seq, m_config.login.c_str(), m_config.password.c_str()), login_parser);
        session->request(yield, utils::format("%u SELECT INBOX\r\n", ++seq), select_parser);

        if (validity != m_validity)
             session->request(yield, utils::format("%u FETCH * UID\r\n", ++seq), end_parser);

        do
        {
            uint64_t end = m_position;
            session->request(yield, utils::format("%u UID SEARCH %s\r\n", ++seq, make_filter(subject).c_str()), search_parser);

            if (m_position == end)
            {
                if (elapsed())
                    throw plexus::timeout_error(__FUNCTION__);

                if (m_idle)
                {
                    session->request(yield, utils::format("%u IDLE\r\n", ++seq), idle_parser, infinite ? max_polling_timeout : min_polling_timeout);
                    session->request(yield, "DONE\r\n", success_checker);
                }
                else
                {
                    session->snooze(yield, infinite ? max_polling_timeout : min_polling_timeout);
                }
                session->request(yield, utils::format("%u NOOP\r\n", ++seq), success_checker);
            }
            else
            {
                session->request(yield,
                    utils::format("%u UID FETCH %d (BODY.PEEK[TEXT] BODY[HEADER.FIELDS (From To)])\r\n", ++seq, m_position),
                    fetch_parser
                );
            }
        }
        while (m_data.endpoint.port() == 0);

        session->request(yield, utils::format("%u UID STORE %d +flags \\DELETED\r\n", ++seq, m_position), success_checker);
        session->request(yield, utils::format("%u LOGOUT\r\n", ++seq), success_checker);
    }

    const reference& pull(boost::asio::yield_context yield, const std::string& subject)
    {
        if (m_data.endpoint.port() == 0)
            wait(yield, subject, false);

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

    boost::asio::io_context& m_io;
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

    reference pull_request(boost::asio::yield_context yield) noexcept(false) override
    {
        const reference& faraway = m_puller.pull(yield, invite_token);
        _inf_ << "pulled request " << faraway;
        return faraway;
    }

    reference pull_response(boost::asio::yield_context yield) noexcept(false) override
    {
        const reference& faraway = m_puller.pull(yield, accept_token);
        _inf_ << "pulled response " << faraway;
        return faraway;
    }

    void push_request(boost::asio::yield_context yield, const reference& gateway) noexcept(false) override
    {
        m_pusher.push(yield, invite_token, gateway);
        _inf_ << "pushed request " << gateway;
    }

    void push_response(boost::asio::yield_context yield, const reference& gateway) noexcept(false) override
    {
        m_pusher.push(yield, accept_token, gateway);
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

}

template<>
void spawn_accept(boost::asio::io_context& io, const email::context& conf, const identity& host, const identity& peer, const coroutine& handler) noexcept(true)
{
    boost::asio::spawn(io, [&io, conf, host, peer, handler](boost::asio::yield_context yield)
    {
        email::smtp pusher(io, conf, host, peer);
        email::imap puller(io, conf, host, peer);

        do
        {
            puller.wait(yield, email::invite_token);

            pusher.host(puller.host());
            pusher.peer(puller.peer());

            boost::asio::spawn(io, [pipe = std::make_shared<email::pipe_impl>(pusher, puller), handler](boost::asio::yield_context yield)
            {
                handler(yield, pipe);
            });

            puller.host(host);
            puller.peer(peer);
        }
        while (true);
    }, boost::asio::detached);
}

template<>
void spawn_invite(boost::asio::io_context& io, const email::context& conf, const identity& host, const identity& peer, const coroutine& handler) noexcept(true)
{
    boost::asio::spawn(io, [&io, conf, host, peer, handler](boost::asio::yield_context yield)
    {
        email::smtp pusher(io, conf, host, peer);
        email::imap puller(io, conf, host, peer);

        puller.init(yield);

        handler(yield, std::make_shared<email::pipe_impl>(pusher, puller));
    }, boost::asio::detached);
}

template<>
void forward_advent(boost::asio::io_context& io, const email::context& conf, const identity& host, const identity& peer, const observer& handler, const fallback& failure) noexcept(true)
{
    boost::asio::spawn(io, [&io, conf, host, peer, handler, failure](boost::asio::yield_context yield)
    {
        try
        {
            email::smtp pusher(io, conf, host, peer);
            pusher.push(yield, email::advent_token, reference { boost::asio::ip::udp::endpoint { boost::asio::ip::address { boost::asio::ip::address_v4 {} }, 1 }});

            handler(host, peer);

            _inf_ << "advent " << host << " -> " << peer;
        }
        catch(const std::exception& ex)
        {
            _err_ << "advent " << host << " -> " << peer << " failed: " << ex.what();
            failure(host, peer, ex.what());
        }
    }, boost::asio::detached);
}

template<>
void receive_advent(boost::asio::io_context& io, const email::context& conf, const identity& host, const identity& peer, const observer& handler, const fallback& failure) noexcept(true)
{
    boost::asio::spawn(io, [&io, conf, host, peer, handler, failure](boost::asio::yield_context yield)
    {
        try
        {
            email::imap puller(io, conf, host, peer);
            do
            {
                puller.wait(yield, email::advent_token);

                boost::asio::post(io, std::bind(handler, puller.host(), puller.peer()));

                _inf_ << "advent " << puller.host() << " <- " << puller.peer();

                puller.host(host);
                puller.peer(peer);
            }
            while (true);
        }
        catch(const std::exception& ex)
        {
            _err_ << "advent " << host << " <- " << peer << " failed: " << ex.what();
            failure(host, peer, ex.what());
        }
    }, boost::asio::detached);
}

}
