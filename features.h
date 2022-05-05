#pragma once

#include <string>
#include "network.h"

namespace plexus {
    
void exec(const std::string& prog, const std::string& args, const std::string& dir = "", const std::string& log = "");

struct postman
{
    virtual ~postman() {}
    virtual void send_message(const std::string& data) noexcept(false) = 0;
    virtual std::string receive_message() noexcept(false) = 0;
};

std::shared_ptr<postman> create_email_postman(const std::string& smtp,
                                              const std::string& imap,
                                              const std::string& login,
                                              const std::string& passwd,
                                              const std::string& from,
                                              const std::string& to,
                                              const std::string& subj_from,
                                              const std::string& subj_to,
                                              const std::string& cert = "",
                                              const std::string& key = "",
                                              const std::string& ca = "",
                                              const std::string& smime_peer = "",
                                              const std::string& smime_cert = "",
                                              const std::string& smime_key = "",
                                              const std::string& smime_ca = "",
                                              int64_t timeout_sec = 10);

namespace network {

struct timeout_error : public std::runtime_error { timeout_error() : std::runtime_error("timeout") {} };

const uint16_t DEFAULT_STUN_PORT = 3478u;

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

struct puncher
{
    virtual ~puncher() {}
    virtual traverse explore_network() noexcept(false) = 0;
    virtual endpoint punch_udp_hole() noexcept(false) = 0;
    /*
        disposes udp connection on success
    */
    virtual void punch_hole_to_peer(const endpoint& peer, int64_t timeout_ms = 4000, int64_t deadline_ms = 120000) noexcept(false) = 0;
};

std::shared_ptr<puncher> create_stun_puncher(const endpoint& stun, const endpoint& local);

}}
