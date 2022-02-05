#pragma once

#include <string>

namespace plexus {
    
void exec(const std::string& prog, const std::string& args, const std::string& dir = "", const std::string& log = "");

namespace network {

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

enum binding
{
    unknown = 0,
    independent = 1,
    address_dependent = 2,
    address_and_port_dependent = 3
};

struct traverse
{
    unsigned int nat : 1,
                 hairpin : 1,
                 random_port : 1,
                 variable_address : 1,
                 mapping : 2, // enum binding
                 filtering : 2; // enum binding
};

typedef std::pair<std::string, uint16_t> endpoint;

struct stun_client
{
    virtual ~stun_client() {}
    virtual traverse explore_network() noexcept(false) = 0;
    virtual endpoint punch_udp_hole() noexcept(false) = 0;
    virtual void keep_udp_hole() noexcept(false) {}
    virtual void touch_remote_host(endpoint host) noexcept(false) {}
};

stun_client* create_stun_client(const std::string& stun_server, const std::string& local_address, uint16_t local_port);

}}
