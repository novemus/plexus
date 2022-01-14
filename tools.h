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

enum nat_quality
{
    error = 0,
    address_filter = 0x00000001,
    port_filter = 0x00000002,
    port_keep = 0x00000004,
    port_reuse = 0x00000008,
    hairpin = 0x00000010,
    not_nat = 0x80000000
};

struct stun_info
{
    int nat_qualities;
    std::string private_address;
    unsigned short private_port;
    std::string public_address;
    unsigned short public_port;
};

stun_info explore_nat_by_stun(const std::string& server);

}}
