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
#include <condition_variable>
#include <opendht.h>
#include <opendht/crypto.h>
#include <boost/asio/spawn.hpp>
#include <boost/date_time/posix_time/posix_time_config.hpp>
#include <boost/date_time/posix_time/ptime.hpp>
#include <boost/algorithm/string.hpp>
#include <fstream>
#include <filesystem>
#include <atomic>
#include <regex>
#include <deque>
#include <map>

namespace plexus { namespace opendht {

const int64_t await_timeout = plexus::utils::getenv<int64_t>("PLEXUS_DHT_AWAIT_TIMEOUT", 20000);
const int64_t delay_timeout = plexus::utils::getenv<int64_t>("PLEXUS_DHT_DELAY_TIMEOUT", 2000);
const int64_t response_timeout = plexus::utils::getenv<int64_t>("PLEXUS_RESPONSE_TIMEOUT", 60000);
const std::string invite_token = plexus::utils::getenv<std::string>("PLEXUS_INVITE_TOKEN", "invite");
const std::string accept_token = plexus::utils::getenv<std::string>("PLEXUS_ACCEPT_TOKEN", "accept");
const std::string advent_token = plexus::utils::getenv<std::string>("PLEXUS_ADVENT_TOKEN", "advent");

using context = context<plexus::dhtnode>;

class node_factory
{
    struct node_context
    {
        std::shared_ptr<dht::DhtRunner> node;
        std::set<std::pair<std::string, std::string>> peers;

        node_context() 
            : node(std::make_shared<dht::DhtRunner>())
        {}
    };

    std::map<uint64_t, node_context> m_nodes;
    std::thread m_thread;
    std::condition_variable m_waiter;
    std::atomic_bool m_alive;
    std::mutex m_mutex;

    std::shared_ptr<dht::DhtRunner> retrieve_node(uint16_t port, uint32_t network, const std::string& bootstrap)
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        
        auto key = uint64_t(port) << 32 | network;

        auto iter = m_nodes.find(key);
        if (iter == m_nodes.end())
            iter = m_nodes.emplace(key, node_context{}).first;

        auto node = iter->second.node;
        auto& peers = iter->second.peers;

        if (!node->isRunning())
        {
            node->run(port, {}, true, network);

            _dbg_ << "startup: node=" << node->getNodeId() << " port=" << port << " network=" << network;

            node->setOnStatusChanged([id = node->getNodeId()](dht::NodeStatus v4, dht::NodeStatus v6)
            {
                _dbg_ << "network: node=" << id << " v4=" << dht::statusToStr(v4) << " v6=" << dht::statusToStr(v6);
            });
        }
        else
        {
            node->connectivityChanged();
        }

        std::set<std::string> urls;
        boost::split(urls, bootstrap, boost::is_any_of(",;"));

        for(auto& url : urls)
        {
            auto ep = dht::splitPort(url);

            if (ep.second.empty())
                ep.second = std::to_string(dht::net::DHT_DEFAULT_PORT);

            if (peers.count(ep) == 0)
            {
                _dbg_ << "connect: node=" << node->getNodeId() << " url=" << url;

                node->bootstrap(ep.first, ep.second);
                peers.insert(ep);
            }
        }

        return node;
    }

public:

    node_factory() : m_alive(true)
    {
#ifdef _MSC_VER
        static std::shared_ptr<void> s_gnutls = []()
        {
            if (auto err = gnutls_global_init())
                throw plexus::context_error(__FUNCTION__, gnutls_strerror(err));

            return std::shared_ptr<void>(nullptr, [](void*)
            {
                gnutls_global_deinit();
            });
        }();
#endif
        m_thread = std::thread([this]()
        {
            std::unique_lock<std::mutex> lock(m_mutex);

            while (m_alive)
            {
                m_waiter.wait_for(lock, std::chrono::seconds(300));

                auto iter = m_nodes.begin();
                while (iter != m_nodes.end())
                {
                    if (iter->second.node.use_count() == 1)
                    {
                        _dbg_ << "destroy: node=" << iter->second.node->getNodeId();

                        iter->second.node->shutdown({}, true);
                        iter->second.node->join();

                        iter = m_nodes.erase(iter);
                    }
                    else 
                    {
                        ++iter;
                    }
                }
            }

            auto iter = m_nodes.begin();
            while (iter != m_nodes.end())
            {
                _dbg_ << "destroy: node=" << iter->second.node->getNodeId();

                iter->second.node->shutdown({}, true);
                iter->second.node->join();

                ++iter;
            }

            m_nodes.clear();
        });
    }

    ~node_factory()
    {
        m_alive = false;
        m_waiter.notify_all();
        m_thread.join();
    }

    static std::shared_ptr<dht::DhtRunner> create_node(uint16_t port, uint32_t network, const std::string& bootstrap)
    {
        static node_factory s_factory;
        return s_factory.retrieve_node(port, network, bootstrap);
    }
};

class repository : public context
{
    std::shared_ptr<dht::DhtRunner>   m_node;
    std::map<dht::InfoHash, identity> m_index;

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

    repository(const context& ctx) noexcept(false) 
        : context(ctx)
        , m_node(node_factory::create_node(port, network, bootstrap))
    {
        for (auto const& owner : std::filesystem::directory_iterator(std::filesystem::path(repo)))
        {
            if (!owner.is_directory())
                continue;

            for (auto const& pin : std::filesystem::directory_iterator(owner.path()))
            {
                if (!pin.is_directory())
                    continue;

                identity info { owner.path().filename().string(), pin.path().filename().string() };
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
using notice = std::tuple<uint64_t, identity, identity>;

class listen : public operation<notice>
{
    boost::asio::deadline_timer       timer;
    std::shared_ptr<dht::DhtRunner>   node;
    dht::InfoHash                     hash;
    std::future<size_t>               token;
    std::deque<notice>                queue;
    std::map<dht::InfoHash, uint64_t> recent;
    std::mutex                        mutex;

protected:

    listen(boost::asio::io_context& io, std::shared_ptr<dht::DhtRunner> node) noexcept(true)
        : timer(io)
        , node(node)
    {}

public:

    ~listen() override
    {
        if (token.valid())
            node->cancelListen(hash, std::move(token));
    }

    notice wait(boost::asio::yield_context yield) noexcept(false) override
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

    static listen_ptr start(boost::asio::io_context& io, const repository& repo, const identity& host, const identity& peer, const std::string& subject) noexcept(false)
    {
        std::shared_ptr<listen> op(new listen(io, repo.node()));
        op->hash = dht::InfoHash::get(repo.load_cert(host)->getId().toString() + repo.app + subject);

        auto match = [peer](const identity& info)
        {
            return !info.owner.empty() && !info.pin.empty() && (peer.owner.empty() || peer.owner == info.owner) && (peer.pin.empty() || peer.pin == info.pin);
        };

        op->timer.expires_from_now(boost::posix_time::time_duration(boost::posix_time::pos_infin));
        uint64_t id = std::time(nullptr);

        _dbg_ << "listen: subject=" << subject << " app=" << repo.app << " host=" << host << " peer=" << peer << " value=" << id << " hash=" << op->hash;

        std::weak_ptr<listen> weak = op;
        op->token = op->node->listen(op->hash, [weak, repo, id, host, match](const std::vector<std::shared_ptr<dht::Value>>& values) mutable
        {
            auto ptr = weak.lock();
            if (not ptr)
                return false;

            for (auto& value : values)
            {
                if (id > value->id) // skip stale messages
                    continue;

                _trc_ << "listen: value=" << value->id << " hash=" << ptr->hash << " owner=" << value->getOwner()->getId();

                auto owner = value->getOwner()->getId();

                auto peer = repo.fetch_identity(owner);
                if (not match(peer))
                    continue;

                std::lock_guard<std::mutex> lock(ptr->mutex);

                auto iter = ptr->recent.find(owner);
                if (iter != ptr->recent.end() && iter->second >= value->id) // skip duplicate and straggler messages
                    continue;

                ptr->recent[owner] = value->id;
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

    acquire(boost::asio::io_context& io, std::shared_ptr<dht::DhtRunner> node) noexcept(true)
        : timer(io)
        , node(node)
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

    static acquire_ptr start(boost::asio::io_context& io, const repository& repo, const identity& host, const identity& peer, uint64_t id, const std::string& subject) noexcept(false)
    {
        std::shared_ptr<acquire> op(new acquire(io, repo.node()));

        op->hash = dht::InfoHash::get(repo.load_cert(host)->getId().toString() + repo.app + subject);
        op->timer.expires_from_now(boost::posix_time::milliseconds(response_timeout));

        auto from = repo.load_cert(peer);
        auto to = repo.load_key(host);

        _dbg_ << "acquire: subject=" << subject << " app=" << repo.app << " host=" << host << " peer=" << peer << " value=" << id << " hash=" << op->hash;

        std::weak_ptr<acquire> weak = op;
        op->token = op->node->listen(op->hash, [weak, from, to](const std::vector<std::shared_ptr<dht::Value>>& values)
        {
            auto ptr = weak.lock();
            if (not ptr)
                return false;

            for (auto& value : values)
            {
                _trc_ << "acquire: value=" << value->id << " hash=" << ptr->hash << " owner=" << value->getOwner()->getId();

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

class forward : public operation<void>, public std::enable_shared_from_this<forward>
{
    boost::asio::io_context&        io;
    boost::asio::deadline_timer     timer;
    std::shared_ptr<dht::DhtRunner> node;
    dht::InfoHash                   hash;
    std::shared_ptr<dht::Value>     value;

protected:

    forward(boost::asio::io_context& io, std::shared_ptr<dht::DhtRunner> node) noexcept(true)
        : io(io)
        , timer(io)
        , node(node)
    {
    }

    void put()
    {
        std::weak_ptr<forward> weak = shared_from_this();
        node->put(hash, value, [weak](bool ok)
        {
            auto ptr = weak.lock();
            if (not ptr)
                return;

            _trc_ << "forward: value=" << ptr->value->id << " hash=" << ptr->hash << " owner=" << ptr->value->getOwner()->getId() << " ok=" << ok;

            if (ok)
            {
                boost::system::error_code ec;
                ptr->timer.cancel(ec);
            }
            else
            {
                boost::asio::spawn(ptr->io, [weak](boost::asio::yield_context yield)
                {
                    auto ptr = weak.lock();
                    if (not ptr)
                        return;

                    boost::asio::deadline_timer timer(ptr->io);
                    timer.expires_from_now(boost::posix_time::milliseconds(delay_timeout));

                    boost::system::error_code ec;
                    timer.async_wait(yield[ec]);

                    if (!ec)
                        ptr->put();
                }, boost::asio::detached);
            }
        });
    }

public:

    ~forward() override
    {
        boost::system::error_code ec;
        timer.cancel(ec);
        node->cancelPut(hash, value->id);
    }

    void wait(boost::asio::yield_context yield) noexcept(false) override
    {
        boost::system::error_code ec;
        timer.async_wait(yield[ec]);

        if (!ec)
            throw plexus::timeout_error(__FUNCTION__);
        else if (ec != boost::asio::error::operation_aborted)
            throw plexus::context_error(__FUNCTION__, ec);
    }

    static forward_ptr start(boost::asio::io_context& io, const repository& repo, const identity& host, const identity& peer, uint64_t id, const std::string& subject, const reference& gateway = {}) noexcept(false)
    {
        std::shared_ptr<forward> op(new forward(io, repo.node()));

        auto to = repo.load_cert(peer);
        auto from = repo.load_key(host);
        auto message = plexus::utils::format("PLEXUS 3.0 %s %u %llu", gateway.endpoint.address().to_string().c_str(), gateway.endpoint.port(), gateway.puzzle);

        op->hash = dht::InfoHash::get(to->getId().toString() + repo.app + subject);
        op->timer.expires_from_now(boost::posix_time::milliseconds(await_timeout));
        op->value = std::make_shared<dht::Value>(dht::ValueType::USER_DATA.id, to->getPublicKey().encrypt(dht::packMsg(message)), id);
        op->value->sign(*from);

        _dbg_ << "forward: subject=" << subject << " app=" << repo.app << " host=" << host << " peer=" << peer << " value=" << id << " hash=" << op->hash;

        op->put();

        return op;
    }
};

class pipe_impl : public pipe
{
    boost::asio::io_context& m_io;
    repository               m_repo;
    uint64_t                 m_id;
    identity                 m_host;
    identity                 m_peer;

public:

    pipe_impl(boost::asio::io_context& io, const repository& repo, uint64_t id, const identity& host, const identity& peer) noexcept(true)
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

        _inf_ << "pulled request " << faraway.endpoint;
        return faraway;
    }

    reference pull_response(boost::asio::yield_context yield) noexcept(false) override
    {        
        auto op = opendht::acquire::start(m_io, m_repo, m_host, m_peer, m_id, accept_token);
        auto faraway = op->wait(yield);

        _inf_ << "pulled response " << faraway.endpoint;
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
        }, boost::asio::detached);

        _inf_ << "pushed request " << gateway.endpoint;
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
        }, boost::asio::detached);

        _inf_ << "pushed response " << gateway.endpoint;
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
void spawn_accept(boost::asio::io_context& io, const opendht::context& ctx, const identity& host, const identity& peer, const coroutine& handler) noexcept(true)
{
    boost::asio::spawn(io, [&io, ctx, host, peer, handler](boost::asio::yield_context yield)
    {
        opendht::repository repo(ctx);
        auto op = opendht::listen::start(io, repo, host, peer, opendht::invite_token);
        do
        {
            auto invite = op->wait(yield);
            boost::asio::spawn(io, [&io, repo, invite, handler](boost::asio::yield_context yield)
            {
                handler(yield, std::make_shared<opendht::pipe_impl>(io, repo, std::get<0>(invite), std::get<1>(invite), std::get<2>(invite)));
            }, boost::asio::detached);
        }
        while (true);
    }, boost::asio::detached);
}

template<>
void spawn_invite(boost::asio::io_context& io, const opendht::context& ctx, const identity& host, const identity& peer, const coroutine& handler) noexcept(true)
{
    boost::asio::spawn(io, [&io, ctx, host, peer, handler](boost::asio::yield_context yield)
    {
        opendht::repository repo(ctx);
        handler(yield, std::make_shared<opendht::pipe_impl>(io, repo, std::time(nullptr), host, peer));
    }, boost::asio::detached);
}

template<>
void forward_advent(boost::asio::io_context& io, const opendht::context& ctx, const identity& host, const identity& peer, const observer& handler, const fallback& failure) noexcept(true)
{
    boost::asio::spawn(io, [&io, ctx, host, peer, handler, failure](boost::asio::yield_context yield)
    {
        try
        {
            opendht::repository repo(ctx);
            auto op = opendht::forward::start(io, repo, host, peer, std::time(nullptr), opendht::advent_token);
            op->wait(yield);

            _dbg_ << "advent: " << peer << " -> " << host << ":" << ctx.app;
            handler(host, peer);
        }
        catch(const std::exception& ex)
        {
            _err_ << "advent: " << peer << " -> " << host << ":" << ctx.app << " error: " << ex.what();
            failure(host, peer, ex.what());
        }
    }, boost::asio::detached);
}

template<>
void receive_advent(boost::asio::io_context& io, const opendht::context& ctx, const identity& host, const identity& peer, const observer& handler, const fallback& failure) noexcept(true)
{
    boost::asio::spawn(io, [&io, ctx, host, peer, handler, failure](boost::asio::yield_context yield)
    {
        opendht::repository repo(ctx);
        auto op = opendht::listen::start(io, repo, host, peer, opendht::advent_token);
        do
        {
            auto advent = op->wait(yield);
            boost::asio::spawn(io, [&io, repo, advent, handler, failure](boost::asio::yield_context yield)
            {
                auto id = std::get<0>(advent);
                auto host = std::get<1>(advent);
                auto peer = std::get<2>(advent);

                try
                {
                    auto op = opendht::acquire::start(io, repo, host, peer, id, opendht::advent_token);
                    op->wait(yield);

                    _dbg_ << "advent: " << host << " -> " << peer << ":" << repo.app;
                    handler(host, peer);
                }
                catch (const std::exception& ex) 
                {
                    _err_ << "advent: " << host << " -> " << peer << ":" << repo.app << " error: " << ex.what();
                    failure(host, peer, ex.what());
                }
            }, boost::asio::detached);
        }
        while (true);
    }, boost::asio::detached);
}

}
