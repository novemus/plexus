/*
 * Copyright (c) 2022 Novemus Band. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 */

#include "plexus.h"
#include "features.h"
#include "utils.h"
#include <limits>
#include <logger.h>
#include <memory>
#include <mutex>
#include <opendht.h>
#include <opendht/crypto.h>
#include <boost/asio/spawn.hpp>
#include <boost/date_time/posix_time/posix_time_config.hpp>
#include <boost/date_time/posix_time/ptime.hpp>
#include <fstream>
#include <filesystem>
#include <regex>
#include <deque>
#include <map>

namespace plexus { namespace opendht {

const int64_t response_timeout = plexus::utils::getenv<int64_t>("PLEXUS_RESPONSE_TIMEOUT", 60000);
const int64_t hangup_timeout = plexus::utils::getenv<int64_t>("PLEXUS_HANGUP_TIMEOUT", 10000);
const std::string invite_token = plexus::utils::getenv<std::string>("PLEXUS_INVITE_TOKEN", "invite");
const std::string accept_token = plexus::utils::getenv<std::string>("PLEXUS_ACCEPT_TOKEN", "accept");

using context = context<plexus::dhtnode>;

class repository : public context
{
    std::map<dht::InfoHash, identity> m_index;
    std::shared_ptr<dht::DhtRunner>   m_node;

    static std::vector<uint8_t> load_file(const std::string& path) noexcept(false)
    {
        std::vector<uint8_t> buffer;
        std::ifstream file(path, std::ios::binary);
        if (!file)
            throw std::runtime_error("can't open file: " + path);
        file.seekg(0, std::ios::end);
        auto size = file.tellg();
        if (size == 0)
            throw std::runtime_error("file is empty: " + path);
        buffer.resize(size);
        file.seekg(0, std::ios::beg);
        if (!file.read((char*)buffer.data(), size))
            throw std::runtime_error("can't read file: " + path);
        return buffer;
    }

public:

    repository(const context& ctx) noexcept(false) : context(ctx)
    {
        for (auto const& iowner : std::filesystem::directory_iterator(std::filesystem::path(repo)))
        {
            if (!iowner.is_directory())
                continue;

            for (auto const& ipin : std::filesystem::directory_iterator(iowner.path()))
            {
                if (ipin.is_directory())
                    continue;

                identity info { iowner.path().filename().string(), ipin.path().filename().string() };
                if (!has_cert(info))
                    continue;

                try
                {
                    m_index.emplace(load_cert(info)->getId(), info);
                } 
                catch (const std::exception& ex)
                {
                    _err_ << ex.what();
                }
            }
        }

        static std::map<std::string, std::weak_ptr<dht::DhtRunner>> s_nodes;
        static std::mutex s_mutex;

        std::lock_guard<std::mutex> lock(s_mutex);

        auto key = bootstrap + std::to_string(port) + std::to_string(network);

        auto iter = s_nodes.find(key);
        if (iter != s_nodes.end())
        {
            m_node = iter->second.lock();
        }

        if (!m_node)
        {
            m_node = std::make_shared<dht::DhtRunner>();
            m_node->run(port, {}, true, network);
            m_node->bootstrap(bootstrap);
            
            _dbg_ << "run dht: node=" << m_node->getNodeId() << " port=" << port << " bootstrap=" << bootstrap << " network=" << network;

            s_nodes.emplace(key, m_node);
        }
    }

    repository(const repository& repo) noexcept(true) = default;
    repository& operator=(const repository& repo) noexcept(true) = default;

    std::shared_ptr<dht::crypto::PrivateKey> load_key(const identity& info) const noexcept(false)
    {
        return std::make_shared<dht::crypto::PrivateKey>(dht::crypto::PrivateKey(load_file(get_key(info))));
    }

    std::shared_ptr<dht::crypto::Certificate> load_cert(const identity& info) const noexcept(false) 
    {
        return std::make_shared<dht::crypto::Certificate>(load_file(get_cert(info)));
    }

    std::shared_ptr<dht::crypto::Certificate> load_ca(const identity& info) const noexcept(false) 
    {
        return std::make_shared<dht::crypto::Certificate>(load_file(get_ca(info)));
    }

    bool check_peer(const dht::InfoHash& id, identity& peer) const noexcept(true) 
    {
        auto iter = m_index.find(id);
        if (iter != m_index.end() && has_cert(iter->second))
        {
            peer = iter->second;
            return true;
        }
        return false;
    }

    std::shared_ptr<dht::DhtRunner> node() const noexcept(true)
    {
        return m_node;
    };
};

template<typename result> struct operation
{
    virtual ~operation() {}
    virtual result wait(boost::asio::yield_context yield) noexcept(false) = 0;
};

std::shared_ptr<operation<std::tuple<uint64_t, identity, identity>>> listen(boost::asio::io_service& io, const repository& repo, const identity& host, const identity& mask) noexcept(false)
{
    using invite = std::tuple<uint64_t, identity, identity>;

    class listen : public operation<invite>, public std::enable_shared_from_this<listen>
    {
        boost::asio::deadline_timer     m_timer;
        std::shared_ptr<dht::DhtRunner> m_node;
        dht::InfoHash                   m_hash;
        std::future<size_t>             m_token;
        std::deque<invite>              m_queue;
        std::mutex                      m_mutex;

    public:

        listen(boost::asio::io_service& io) noexcept(true)
            : m_timer(io)
        {}

        ~listen() override
        {
            m_node->cancelListen(m_hash, std::move(m_token));
        }

        void start(const repository& repo, const identity& host, const identity& mask) noexcept(false)
        {
            m_node = repo.node();
            m_hash = dht::InfoHash::get(repo.load_cert(host)->getId().toString() + repo.app + invite_token);
            
            auto match = [mask](const identity& info)
            {
                return (mask.owner.empty() || mask.owner == info.owner) && (mask.pin.empty() || mask.pin == info.pin);
            };

            m_timer.expires_from_now(boost::posix_time::time_duration(boost::posix_time::pos_infin));
            uint64_t id = std::time(nullptr);

            std::weak_ptr<listen> weak = shared_from_this();
            m_token = m_node->listen(m_hash, [=](const std::vector<std::shared_ptr<dht::Value>>& values)
            {
                auto ptr = weak.lock();
                if (not ptr)
                    return false;

                for (auto& value : values)
                {
                    _trc_ << "seen value " << value->id  << " on node " << m_node->getNodeId();
                    if (id > value->id)
                        continue;

                    identity peer;
                    if (!repo.check_peer(value->getOwner()->getId(), peer) || !match(peer))
                        continue;

                    std::lock_guard<std::mutex> lock(m_mutex);
                    m_queue.emplace_back(value->id, host, peer);

                    boost::system::error_code ec;
                    m_timer.cancel(ec);
                }
                return true;
            });
        }

        invite wait(boost::asio::yield_context yield) noexcept(false) override
        {
            boost::system::error_code ec;
            m_timer.async_wait(yield[ec]);

            std::lock_guard<std::mutex> lock(m_mutex);
            m_timer.expires_from_now(boost::posix_time::milliseconds(std::numeric_limits<int64_t>::max()));

            if (ec != boost::asio::error::operation_aborted)
                throw boost::system::system_error(ec);

            if (m_queue.empty())
                throw boost::system::system_error(boost::asio::error::broken_pipe);

            auto res = m_queue.front();
            m_queue.pop_front();

            return res;
        }
    };

    _dbg_ << "listen " << repo.app << "/invite on node " << repo.node()->getNodeId() << " for " << host;

    std::shared_ptr<listen> op = std::make_shared<listen>(io);
    op->start(repo, host, mask);
    return op;
}

std::shared_ptr<operation<reference>> acquire(boost::asio::io_service& io, const repository& repo, uint64_t id, const identity& host, const identity& peer, const std::string& subject) noexcept(false)
{
    class acquire : public operation<reference>, public std::enable_shared_from_this<acquire>
    {
        boost::asio::deadline_timer     m_timer;
        std::shared_ptr<dht::DhtRunner> m_node;
        dht::InfoHash                   m_hash;
        std::future<size_t>             m_token;
        reference                       m_data;

    public:

        acquire(boost::asio::io_service& io) noexcept(true)
            : m_timer(io)
        {
        }

        ~acquire() override
        {
            boost::system::error_code ec;
            m_timer.cancel(ec);
            m_node->cancelListen(m_hash, std::move(m_token));
        }

        void start(const repository& repo, uint64_t id, const identity& host, const identity& peer, const std::string& subject) noexcept(false)
        {
            m_node = repo.node();
            m_hash = dht::InfoHash::get(repo.load_cert(host)->getId().toString() + repo.app + subject);
            m_timer.expires_from_now(boost::posix_time::milliseconds(response_timeout));

            auto from = repo.load_cert(peer);
            auto key = repo.load_key(host);

            std::weak_ptr<acquire> weak = shared_from_this();
            m_token = m_node->listen(m_hash, [=](const std::vector<std::shared_ptr<dht::Value>>& values)
            {
                auto ptr = weak.lock();
                if (not ptr)
                    return false;

                for (auto& value : values)
                {
                    _trc_ << "peek value " << value->id  << " on node " << repo.node()->getNodeId();
                    if (value->getOwner()->getId() != from->getId())
                        continue;

                    if (!from->getPublicKey().checkSignature(value->getToSign(), value->signature))
                        continue;

                    auto message = dht::Value::unpack<std::string>(key->decrypt(value->data));
                    std::smatch match;
                    if (std::regex_match(message, match, std::regex("\\s*PLEXUS 3.0 (\\S+) (\\d+) (\\d+)\\s*")))
                    {
                        m_data = {
                            utils::parse_endpoint<boost::asio::ip::udp::endpoint>(match.str(1), match.str(2)),
                            boost::lexical_cast<uint64_t>(match.str(3))
                        };

                        boost::system::error_code ec;
                        m_timer.cancel(ec);

                        return false;
                    }
                }
                return true;
            }, dht::Value::IdFilter(id));
        }

        reference wait(boost::asio::yield_context yield) noexcept(false) override
        {
            boost::system::error_code ec;
            m_timer.async_wait(yield[ec]);

            if (!ec)
                throw boost::system::system_error(boost::asio::error::timed_out);
            else if (ec != boost::asio::error::operation_aborted)
                throw boost::system::system_error(ec);

            return m_data;
        }
    };

    _dbg_ << "acquire " << repo.app << "/" << subject << " on node " << repo.node()->getNodeId() << " for " << host << " from " << peer << " with id " << id;

    std::shared_ptr<acquire> op = std::make_shared<acquire>(io);
    op->start(repo, id, host, peer, subject);
    return op;
}

std::shared_ptr<operation<void>> forward(boost::asio::io_service& io, const repository& repo, uint64_t id, const identity& host, const identity& peer, const reference& gateway, const std::string& subject) noexcept(false)
{
    class forward : public operation<void>, public std::enable_shared_from_this<forward>
    {
        boost::asio::deadline_timer     m_timer;
        std::shared_ptr<dht::DhtRunner> m_node;
        dht::InfoHash                   m_hash;
        uint64_t                        m_id;

    public:

        forward(boost::asio::io_service& io) noexcept(true)
            : m_timer(io)
        {
        }

        ~forward() override
        {
            boost::system::error_code ec;
            m_timer.cancel(ec);
            m_node->cancelPut(m_hash, std::move(m_id));
        }

        void start(const repository& repo, uint64_t id, const identity& host, const identity& peer, const reference& gateway, const std::string& subject) noexcept(false)
        {
            m_node = repo.node();
            m_hash = dht::InfoHash::get(repo.load_cert(peer)->getId().toString() + repo.app + subject);
            m_timer.expires_from_now(boost::posix_time::milliseconds(hangup_timeout));

            auto message = plexus::utils::format("PLEXUS 3.0 %s %u %llu", gateway.endpoint.address().to_string().c_str(), gateway.endpoint.port(), gateway.puzzle);

            dht::Value value(dht::ValueType::USER_DATA.id, repo.load_cert(peer)->getPublicKey().encrypt(message), m_id);
            value.sign(*repo.load_key(host));

            std::weak_ptr<forward> weak = shared_from_this();
            m_node->put(m_hash, std::move(value), [=](bool ok)
            {
                auto ptr = weak.lock();
                if (not ptr)
                    return;

                _trc_ << (ok ? "sent" : "couldn't send") << " value " << m_id  << " by node " << repo.node()->getNodeId();

                m_id = ok ? m_id : 0;
                boost::system::error_code ec;
                m_timer.cancel(ec);
            });
        }

        void wait(boost::asio::yield_context yield) noexcept(false) override
        {
            boost::system::error_code ec;
            m_timer.async_wait(yield[ec]);

            if (!ec)
                throw boost::system::system_error(boost::asio::error::timed_out);
            else if (ec != boost::asio::error::operation_aborted)
                throw boost::system::system_error(ec);

            if (m_id == 0)
                throw boost::system::system_error(boost::asio::error::broken_pipe);
        }
    };

    _dbg_ << "forward " << repo.app << "/" << subject << " on node " << repo.node()->getNodeId() << " for " << host << " from " << peer << " with id " << id;

    std::shared_ptr<forward> op = std::make_shared<forward>(io);
    op->start(repo, id, host, peer, gateway, subject);

    return op;
}

class pipe_impl : public pipe
{
    boost::asio::io_service& m_io;
    repository               m_repo;
    uint64_t                 m_id;
    identity                 m_host;
    identity                 m_peer;

public:

    pipe_impl(boost::asio::io_service& io, const repository& repo, uint64_t id, const identity& host, const identity& peer) noexcept(true)
        : m_io(io)
        , m_repo(repo)
        , m_id(id)
        , m_host(host)
        , m_peer(peer)
    {
    }

    reference pull_request(boost::asio::yield_context yield) noexcept(false) override
    {
        auto op = opendht::acquire(m_io, m_repo, m_id, m_host, m_peer, invite_token);
        auto faraway = op->wait(yield);

        _inf_ << "pulled request " << faraway;
        return faraway;
    }

    reference pull_response(boost::asio::yield_context yield) noexcept(false) override
    {        
        auto op = opendht::acquire(m_io, m_repo, m_id, m_host, m_peer, accept_token);
        auto faraway = op->wait(yield);

        _inf_ << "pulled response " << faraway;
        return faraway;
    }

    void push_request(boost::asio::yield_context yield, const reference& gateway) noexcept(false) override
    {
        auto op = opendht::forward(m_io, m_repo, m_id, m_host, m_peer, gateway, invite_token);
        op->wait(yield);

        _inf_ << "pushed request " << gateway;
    }

    void push_response(boost::asio::yield_context yield, const reference& gateway) noexcept(false) override
    {
        auto op = opendht::forward(m_io, m_repo, m_id, m_host, m_peer, gateway, accept_token);
        op->wait(yield);

        _inf_ << "pushed response " << gateway;
    }

    const identity& host() const noexcept(true) override
    {
        return m_host;
    }

    const identity& peer() const noexcept(true) override
    {
        return m_peer;
    }
};

}

template<>
void spawn_accept(boost::asio::io_service& io, const opendht::context& ctx, const identity& host, const identity& peer, const coroutine& handler) noexcept(true)
{
    boost::asio::spawn(io, [&io, ctx, host, peer, handler](boost::asio::yield_context yield)
    {
        opendht::repository repo(ctx);
        auto op = opendht::listen(io, repo, host, peer);
        do
        {
            auto invite = op->wait(yield);
            boost::asio::spawn(io, [&io, repo, invite, handler](boost::asio::yield_context yield)
            {
                handler(yield, std::make_shared<opendht::pipe_impl>(io, repo, std::get<0>(invite), std::get<1>(invite), std::get<2>(invite)));
            });
        }
        while (true);
    });
}

template<>
void spawn_invite(boost::asio::io_service& io, const opendht::context& ctx, const identity& host, const identity& peer, const coroutine& handler) noexcept(true)
{
    boost::asio::spawn(io, [&io, ctx, host, peer, handler](boost::asio::yield_context yield)
    {
        opendht::repository repo(ctx);
        handler(yield, std::make_shared<opendht::pipe_impl>(io, repo, std::time(nullptr), host, peer));
    });
}

}
