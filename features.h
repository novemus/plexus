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
    long timeout;
};

pipe* create_email_pipe(const email_pipe_config& config);

struct network_traverse
{
    struct firewall
    {
        enum binding
        {
            independent = 0,
            address_dependend = 1,
            address_port_dependend = 2
        };

        int nat : 1,
            hairpin : 1,
            retainable_port : 1,
            immutable_address : 1,
            outbound_binding : 2,
            inbound_binding : 2;
    };

    struct mapping
    {
        std::string private_address;
        unsigned short private_port;
        std::string public_address;
        unsigned short public_port;
    };

    virtual ~network_traverse() {}
    virtual firewall explore_firewall() noexcept(false) = 0;
    virtual mapping punch_udp_hole() noexcept(false) = 0;
};

network_traverse* create_stun_network_traverse(const std::string& stun, const std::string& interface);

}}
