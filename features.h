#pragma once

#include <string>

namespace plexus { namespace features {

struct pipe
{
    virtual ~pipe() {}
    virtual void push(const std::string& data) noexcept(false) = 0;
    virtual std::string pull() noexcept(false) = 0;
};

struct email_pipe_config
{
    std::string smtp;
    std::string imap;
    std::string login;
    std::string password;
    std::string certificate;
    std::string key;
    std::string frontend;
    std::string backend;
    int64_t timeout;
};

pipe* create_email_pipe(const email_pipe_config& config);

struct firewall
{
    enum binding
    {
        unknown = 0,
        independent = 1,
        address_dependend = 2,
        address_port_dependend = 3
    };

    unsigned int nat : 1,
                 hairpin : 1,
                 retainable_port : 1,
                 immutable_address : 1,
                 outbound_binding : 2,
                 inbound_binding : 2;
};

typedef std::pair<std::string, uint16_t> endpoint;

struct network_traverse
{
    virtual ~network_traverse() {}
    virtual firewall explore_firewall() noexcept(false) = 0;
    virtual endpoint punch_udp_hole() noexcept(false) = 0;
};

network_traverse* create_network_traverse(const std::string& stun_server, const std::string& local_address, uint16_t local_port);

}}
