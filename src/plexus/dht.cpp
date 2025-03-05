/*
 * Copyright (c) 2022 Novemus Band. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 */

#include <plexus/plexus.h>
#include <plexus/features.h>
#include <plexus/utils.h>
#include <wormhole/logger.h>
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
const int64_t hangup_timeout = plexus::utils::getenv<int64_t>("PLEXUS_HANGUP_TIMEOUT", 20000);
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
            throw std::runtime_error("can't open file (" + path + ")");
        file.seekg(0, std::ios::end);
        auto size = file.tellg();
        if (size == 0)
            throw std::runtime_error("file is empty (" + path + ")");
        buffer.resize(size);
        file.seekg(0, std::ios::beg);
        if (!file.read((char*)buffer.data(), size))
            throw std::runtime_error("can't read file (" + path + ")");
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
                if (!ipin.is_directory())
                    continue;

                identity info { iowner.path().filename().string(), ipin.path().filename().string() };
                if (!has_cert(info))
                    continue;

                try
                {
                    auto id = load_cert(info)->getId();

                    _trc_ << "found identity " << info << " with id " << id;

                    m_index.emplace(id, info);
                } 
                catch (const std::exception& ex)
                {
                    _err_ << ex.what();
                }
            }
        }

        static std::map<uint64_t, std::shared_ptr<dht::DhtRunner>> s_nodes;
        static std::mutex s_mutex;

        std::lock_guard<std::mutex> lock(s_mutex);

        auto key = uint64_t(port) << 32 | network;

        auto iter = s_nodes.find(key);
        if (iter != s_nodes.end())
            m_node = iter->second;

        try
        {
            if (!m_node)
            {
                m_node = std::make_shared<dht::DhtRunner>();
                m_node->run(port, {}, true, network);

                _dbg_ << "startup dht: node=" << m_node->getNodeId() << " port=" << port << " bootstrap=" << bootstrap << " network=" << network;

                m_node->bootstrap(bootstrap);
                s_nodes.emplace(key, m_node);
            }
            else
            {
                m_node->bootstrap(bootstrap);
                _dbg_ << "refresh dht: node=" << m_node->getNodeId() << " bootstrap=" << bootstrap;
            }
        }
        catch (const std::exception& ex)
        {
            throw plexus::context_error(__FUNCTION__, ex.what());
        }

        try
        {
            iter = s_nodes.begin();
            while (iter != s_nodes.end())
            {
                if (iter->second.use_count() == 1)
                {
                    _dbg_ << "shutdown dht: node=" << m_node->getNodeId();

                    iter->second->shutdown({}, true);
                    iter->second->join();

                    iter = s_nodes.erase(iter);
                }
                else
                    ++iter;
            }
        }
        catch (const std::exception& ex)
        {
            _err_ << ex.what();
        }
    }

    repository(const repository& repo) noexcept(true) = default;
    repository& operator=(const repository& repo) noexcept(true) = default;

    std::shared_ptr<dht::crypto::PrivateKey> load_key(const identity& info) const noexcept(false)
    {
        try
        {
            return std::make_shared<dht::crypto::PrivateKey>(dht::crypto::PrivateKey(load_file(get_key(info))));
        }
        catch (const std::exception& ex)
        {
            throw plexus::context_error(__FUNCTION__, ex.what());
        }
    }

    std::shared_ptr<dht::crypto::Certificate> load_cert(const identity& info) const noexcept(false) 
    {
        try
        {
            return std::make_shared<dht::crypto::Certificate>(load_file(get_cert(info)));
        }
        catch (const std::exception& ex)
        {
            throw plexus::context_error(__FUNCTION__, ex.what());
        }
    }

    std::shared_ptr<dht::crypto::Certificate> load_ca(const identity& info) const noexcept(false) 
    {
        try
        {
            return std::make_shared<dht::crypto::Certificate>(load_file(get_ca(info)));
        }
        catch (const std::exception& ex)
        {
            throw plexus::context_error(__FUNCTION__, ex.what());
        }
    }

    identity fetch_identity(const dht::InfoHash& id) const noexcept(true) 
    {
        auto iter = m_index.find(id);
        if (iter != m_index.end() && has_cert(iter->second))
            return iter->second;

        return identity();
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

using listen_ptr = std::shared_ptr<operation<std::tuple<uint64_t, identity, identity>>>;
using invite = std::tuple<uint64_t, identity, identity>;

class listen : public operation<invite>
{
    boost::asio::deadline_timer     timer;
    std::shared_ptr<dht::DhtRunner> node;
    dht::InfoHash                   hash;
    std::future<size_t>             token;
    std::deque<invite>              queue;
    std::mutex                      mutex;

protected:

    listen(boost::asio::io_service& io) noexcept(true)
        : timer(io)
    {}

public:

    ~listen() override
    {
        if (token.valid())
            node->cancelListen(hash, std::move(token));
    }

    invite wait(boost::asio::yield_context yield) noexcept(false) override
    {
        boost::system::error_code ec;
        timer.async_wait(yield[ec]);

        std::lock_guard<std::mutex> lock(mutex);
        timer.expires_from_now(boost::posix_time::time_duration(boost::posix_time::pos_infin));

        if (ec != boost::asio::error::operation_aborted)
            throw plexus::context_error(__FUNCTION__, ec.message());

        if (queue.empty())
            throw plexus::context_error(__FUNCTION__, "operation aborted");

        auto res = queue.front();
        queue.pop_front();

        return res;
    }

    static listen_ptr start(boost::asio::io_service& io, const repository& repo, const identity& host, const identity& peer) noexcept(false)
    {
        _dbg_ << "listen " << repo.app << "/invite for " << host;

        std::shared_ptr<listen> op(new listen(io));
        op->node = repo.node();
        op->hash = dht::InfoHash::get(repo.load_cert(host)->getId().toString() + repo.app + invite_token);

        auto match = [peer](const identity& info)
        {
            return !info.owner.empty() && !info.pin.empty() && (peer.owner.empty() || peer.owner == info.owner) && (peer.pin.empty() || peer.pin == info.pin);
        };

        op->timer.expires_from_now(boost::posix_time::time_duration(boost::posix_time::pos_infin));
        uint64_t id = std::time(nullptr);

        _trc_ << "listen values with key " << op->hash;

        std::weak_ptr<listen> weak = op;
        op->token = op->node->listen(op->hash, [weak, repo, id, host, match](const std::vector<std::shared_ptr<dht::Value>>& values)
        {
            auto ptr = weak.lock();
            if (not ptr)
                return false;

            for (auto& value : values)
            {
                if (id > value->id)
                    continue;

                _trc_ << "got value " << value->id << " with key " << ptr->hash << " from " << value->getOwner()->getId();

                auto peer = repo.fetch_identity(value->getOwner()->getId());
                if (not match(peer))
                    continue;

                std::lock_guard<std::mutex> lock(ptr->mutex);
                ptr->queue.emplace_back(value->id, host, peer);

                boost::system::error_code ec;
                ptr->timer.cancel(ec);
            }
            return true;
        });

        return op;
    }
};

using acquire_ptr = std::shared_ptr<operation<reference>>;

class acquire : public operation<reference>
{
    boost::asio::deadline_timer     timer;
    std::shared_ptr<dht::DhtRunner> node;
    dht::InfoHash                   hash;
    std::future<size_t>             token;
    reference                       data;

protected:

    acquire(boost::asio::io_service& io) noexcept(true)
        : timer(io)
    {
    }

public:

    ~acquire() override
    {
        boost::system::error_code ec;
        timer.cancel(ec);
        if (token.valid())
            node->cancelListen(hash, std::move(token));
    }

    reference wait(boost::asio::yield_context yield) noexcept(false) override
    {
        boost::system::error_code ec;
        timer.async_wait(yield[ec]);

        if (!ec)
            throw plexus::timeout_error(__FUNCTION__);
        else if (ec != boost::asio::error::operation_aborted)
            throw plexus::context_error(__FUNCTION__, ec);

        return data;
    }

    static acquire_ptr start(boost::asio::io_service& io, const repository& repo, const identity& host, const identity& peer, uint64_t id, const std::string& subject) noexcept(false)
    {
        _dbg_ << "acquire " << repo.app << "/" << subject << " for " << host << " from " << peer;

        std::shared_ptr<acquire> op(new acquire(io));

        op->node = repo.node();
        op->hash = dht::InfoHash::get(repo.load_cert(host)->getId().toString() + repo.app + subject);
        op->timer.expires_from_now(boost::posix_time::milliseconds(response_timeout));

        auto from = repo.load_cert(peer);
        auto to = repo.load_key(host);

        _trc_ << "acquire value " << id << " with key " << op->hash;

        std::weak_ptr<acquire> weak = op;
        op->token = op->node->listen(op->hash, [weak, from, to](const std::vector<std::shared_ptr<dht::Value>>& values)
        {
            auto ptr = weak.lock();
            if (not ptr)
                return false;

            for (auto& value : values)
            {
                _trc_ << "got value " << value->id << " with key " << ptr->hash << " from " << value->getOwner()->getId();

                if (value->getOwner()->getId() != from->getId())
                    continue;

                if (!from->getPublicKey().checkSignature(value->getToSign(), value->signature))
                    continue;

                auto message = dht::unpackMsg<std::string>(to->decrypt(value->data));
                std::smatch match;
                if (std::regex_match(message, match, std::regex("\\s*PLEXUS 3.0 (\\S+) (\\d+) (\\d+)\\s*")))
                {
                    ptr->data = {
                        utils::parse_endpoint<boost::asio::ip::udp::endpoint>(match.str(1), match.str(2)),
                        boost::lexical_cast<uint64_t>(match.str(3))
                    };

                    boost::system::error_code ec;
                    ptr->timer.cancel(ec);

                    return false;
                }
            }
            return true;
        }, dht::Value::IdFilter(id));

        return op;
    }
};

using forward_ptr = std::shared_ptr<operation<void>>;

class forward : public operation<void>
{
    boost::asio::deadline_timer     timer;
    std::shared_ptr<dht::DhtRunner> node;
    dht::InfoHash                   hash;
    uint64_t                        id = 0;

protected:

    forward(boost::asio::io_service& io) noexcept(true)
        : timer(io)
    {
    }

public:

    ~forward() override
    {
        boost::system::error_code ec;
        timer.cancel(ec);
        if (id)
            node->cancelPut(hash, id);
    }

    void wait(boost::asio::yield_context yield) noexcept(false) override
    {
        boost::system::error_code ec;
        timer.async_wait(yield[ec]);

        if (!ec)
            throw plexus::timeout_error(__FUNCTION__);
        else if (ec != boost::asio::error::operation_aborted)
            throw plexus::context_error(__FUNCTION__, ec);

        if (id == 0)
            throw plexus::context_error(__FUNCTION__, "operation aborted");
    }

    static forward_ptr start(boost::asio::io_service& io, const repository& repo, const identity& host, const identity& peer, uint64_t id, const std::string& subject, const reference& gateway) noexcept(false)
    {
        _dbg_ << "forward " << repo.app << "/" << subject << " for " << peer << " from " << host;

        std::shared_ptr<forward> op(new forward(io));

        auto to = repo.load_cert(peer);
        auto from = repo.load_key(host);

        op->node = repo.node();
        op->hash = dht::InfoHash::get(to->getId().toString() + repo.app + subject);
        op->timer.expires_from_now(boost::posix_time::milliseconds(hangup_timeout));

        auto message = plexus::utils::format("PLEXUS 3.0 %s %u %llu", gateway.endpoint.address().to_string().c_str(), gateway.endpoint.port(), gateway.puzzle);
        auto value = std::make_shared<dht::Value>(dht::ValueType::USER_DATA.id, to->getPublicKey().encrypt(dht::packMsg(message)), id);
        value->sign(*from);

        _trc_ << "forward value " << id << " with key " << op->hash << " from " << value->getOwner()->getId();

        std::weak_ptr<forward> weak = op;
        op->node->put(op->hash, value, [weak, id, value](bool ok)
        {
            auto ptr = weak.lock();
            if (not ptr)
                return;

            _trc_ << (ok ? "sent" : "couldn't send") << " value " << id << " with key " << ptr->hash << " from " << value->getOwner()->getId();

            ptr->id = ok ? id : 0;
            boost::system::error_code ec;
            ptr->timer.cancel(ec);
        });

        return op;
    }
};

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
        auto op = opendht::acquire::start(m_io, m_repo, m_host, m_peer, m_id, invite_token);
        auto faraway = op->wait(yield);

        _inf_ << "pulled request " << faraway;
        return faraway;
    }

    reference pull_response(boost::asio::yield_context yield) noexcept(false) override
    {        
        auto op = opendht::acquire::start(m_io, m_repo, m_host, m_peer, m_id, accept_token);
        auto faraway = op->wait(yield);

        _inf_ << "pulled response " << faraway;
        return faraway;
    }

    void push_request(boost::asio::yield_context yield, const reference& gateway) noexcept(false) override
    {
        auto op = opendht::forward::start(m_io, m_repo, m_host, m_peer, m_id, invite_token, gateway);
        boost::asio::spawn(m_io, [op](boost::asio::yield_context yield)
        {
            try
            {
                op->wait(yield);
            } 
            catch (const std::exception& ex) 
            {
                _err_ << ex.what();
            }
        });

        _inf_ << "pushed request " << gateway;
    }

    void push_response(boost::asio::yield_context yield, const reference& gateway) noexcept(false) override
    {
        auto op = opendht::forward::start(m_io, m_repo, m_host, m_peer, m_id, accept_token, gateway);
        boost::asio::spawn(m_io, [op](boost::asio::yield_context yield)
        {
            try
            {
                op->wait(yield);
            } 
            catch (const std::exception& ex) 
            {
                _err_ << ex.what();
            }
        });

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
        auto op = opendht::listen::start(io, repo, host, peer);
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
