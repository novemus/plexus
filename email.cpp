#include <string>
#include <list>
#include <iostream>
#include <sstream>
#include <cstring>
#include <memory>
#include <regex>
#include <functional>
#include "features.h"
#include "network.h"
#include "utils.h"
#include "log.h"

namespace plexus { namespace email {

struct config
{
    network::endpoint smtp;
    network::endpoint imap;
    std::string login;
    std::string passwd;
    std::string from;
    std::string to;
    std::string subj_from;
    std::string subj_to;
    std::string cert;
    std::string key;
    std::string ca;

    struct
    {
        std::string peer;
        std::string cert;
        std::string key;
        std::string ca;
    } smime;
};

class channel
{
    static const size_t BUFFER_SIZE = 8192;

public:

    channel(const network::endpoint& address, const std::string& cert, const std::string& key, const std::string& ca)
        : m_ssl(network::create_ssl_client(address, cert, key, ca))
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

    void request(const std::string& request, const response_parser_t& parse)
    {
        _trc_ << "<<<<<\n" << request << "\n*****";

		size_t written = 0;
        do {
            written += m_ssl->write((const uint8_t*)request.c_str() + written, request.size() - written);
        } while (written < request.size());

        std::string response;
        do {
			size_t read = m_ssl->read(m_buffer, BUFFER_SIZE);
            response.append((char*)m_buffer, read);
        } while (!parse(response));

        _trc_ << ">>>>>\n" << response << "\n*****";
    }

private:

    uint8_t m_buffer[BUFFER_SIZE];
    std::shared_ptr<network::ssl> m_ssl;
};

std::string get_address(const std::string& email)
{
    std::smatch match;
    if (std::regex_search(email, match, std::regex("[\\w\\s]*\\<([^\\<]+@[^\\>]+)\\>\\s*")))
    {
        return match[1].str();
    }
    return email;
}

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

    std::string build_data(const std::string& data)
    {
        if (m_config.smime.peer.empty())
        {
            static const char* SIMPLE_EMAIL =
                "From: %s\r\n"
                "To: %s\r\n"
                "Subject: %s\r\n"
                "\r\n"
                "%s\r\n"
                ".\r\n";

            return utils::format(
                SIMPLE_EMAIL,
                m_config.from.c_str(),
                m_config.to.c_str(),
                m_config.subj_to.c_str(),
                data.c_str()
                );
        }

        static const char* MULTIPART_EMAIL =
            "From: %s\r\n"
            "To: %s\r\n"
            "Subject: %s\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: multipart/mixed; boundary=----%s\r\n"
            "\r\n"
            "------%s\r\n"
            "%s\r\n"
            "------%s--\r\n"
            ".\r\n";

        std::string bound = plexus::utils::to_hexadecimal((uint8_t*)m_config.to.data(), m_config.to.size());
        std::string content = plexus::utils::smime_encrypt(
            plexus::utils::smime_sign(data, m_config.smime.cert, m_config.smime.key),
            m_config.smime.peer
            );

        return utils::format(
            MULTIPART_EMAIL,
            m_config.from.c_str(),
            m_config.to.c_str(),
            m_config.subj_to.c_str(),
            bound.c_str(),
            bound.c_str(),
            content.c_str(),
            bound.c_str()
            );
    }

public:
    
    smtp(const config& conf)
        : m_config(conf)
    {
    }

    void push(const std::string& data) noexcept(false)
    {
        std::unique_ptr<channel> session = std::make_unique<channel>(
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
        session->request(utils::format("MAIL FROM: %s\r\n", get_address(m_config.from).c_str()), code_checker(250));
        session->request(utils::format("RCPT TO: %s\r\n", get_address(m_config.to).c_str()), code_checker(250));
        session->request("DATA\r\n", code_checker(354));
        session->request(build_data(data), code_checker(250));
    }

private:

    config m_config;
};

class imap
{
    typedef channel::response_parser_t response_parser_t;

    const response_parser_t connect_checker = [](const std::string& response) -> bool {
            std::smatch match;
            bool done = std::regex_search(response, match, std::regex("^\\*\\s+(OK|NO)\\s+.*\\r\\n$"));
            if (done && match[1] != "OK")
                throw std::runtime_error(response);
            return done;
        };

    const response_parser_t success_checker = [](const std::string& response) -> bool {
        std::smatch match;
        bool done = std::regex_search(response, match, std::regex("(.*\\r\\n)?x\\s+(OK|NO)\\s+.*\\r\\n$"));
        if (done && match[2] != "OK")
            throw std::runtime_error(response);
        return done;
    };

    const response_parser_t select_parser = [this](const std::string& response) -> bool {
        if (success_checker(response))
        {
            std::smatch match;
            if (std::regex_search(response, match, std::regex(".*\\n\\*\\s+OK\\s+\\[UIDVALIDITY\\s+(\\d+)\\]$.*")))
            {
                std::stringstream ss;
                ss << match[1].str();

                uint64_t validity;
                ss >> validity;

                if (validity != m_validity)
                {
                    m_last_seen = 0;
                    m_unseen.clear();
                }

                m_validity = validity;
            }
            return true;
        }
        return false;
    };

    const response_parser_t search_parser = [this](const std::string& response) -> bool {
        if (success_checker(response))
        {
            std::smatch match;
            if (std::regex_search(response, match, std::regex("^\\*\\s+SEARCH\\s+([\\d\\f\\t\\v ]+).*")))
            {
                std::stringstream stream;
                stream << match[1].str();

                uint64_t uid = 0;
                while (stream >> uid)
                {
                    if (uid > m_last_seen)
                        m_unseen.push_back(uid);
                }
            }
            return true;
        }
        return false;
    };

    const response_parser_t fetch_parser = [this](const std::string& response) -> bool {
        if (success_checker(response))
        {
            std::smatch match;
            if (std::regex_search(response, match, std::regex("^[^\\r\\n]+\\r\\n([\\s\\S]+)\\r\\n\\)\\r\\n.*")))
            {
                std::string raw = match[1].str();
                if (m_config.smime.peer.empty())
                {
                    m_data = match[1].str();
                }
                else
                {
                    try
                    {
                        m_data = plexus::utils::smime_verify(
                            plexus::utils::smime_decrypt(match[1].str(), m_config.smime.cert, m_config.smime.key),
                            m_config.smime.peer,
                            m_config.smime.ca
                            );
                    }
                    catch(const std::exception& ex)
                    {
                        _err_ << ex.what();
                    }
                }
            }
            return true;
        }
        return false;
    };

    inline std::string pull_data()
    {
        std::string data;
        std::swap(data, m_data);
        return data;
    }

public:

    imap(const config& conf)
        : m_config(conf)
    {
    }

    std::string pull() noexcept(false)
    {
        std::unique_ptr<channel> session = std::make_unique<channel>(
            m_config.imap,
            m_config.cert,
            m_config.key,
            m_config.ca
        );

        session->connect(connect_checker);
        session->request(utils::format("x LOGIN %s %s\r\n", m_config.login.c_str(), m_config.passwd.c_str()), success_checker);
        session->request("x SELECT INBOX\r\n", select_parser);

        if (m_unseen.empty())
        {
            session->request(utils::format("x UID SEARCH (SINCE %s) (From %s) (To %s) (Subject \"%s\")\r\n",
                utils::format("%d-%b-%Y", std::chrono::system_clock::now()).c_str(),
                get_address(m_config.from).c_str(),
                get_address(m_config.to).c_str(),
                m_config.subj_from.c_str()
             ), search_parser);
        }

        std::string data;
        do
        {
            if (m_unseen.empty())
                break;

            auto uid = m_unseen.front();
            session->request(
                utils::format("x UID FETCH %d (BODY.PEEK[TEXT])\r\n", uid), fetch_parser
            );
            
            m_unseen.pop_front();
            m_last_seen = uid;

            data = pull_data();
        } while (data.empty());

        return data;
    }

private:

    config m_config;
    std::list<uint64_t> m_unseen;
    std::string m_data;
    uint64_t m_last_seen = 0;
    uint64_t m_validity = 0;
};

}

using namespace email;

class email_mediator : public mediator
{
    smtp m_smtp;
    imap m_imap;
    plexus::network::endpoint m_host;
    plexus::network::endpoint m_peer;
    uint64_t m_host_secret = 0;
    uint64_t m_peer_secret = 0;

public:

    email_mediator(const config& conf)
        : m_smtp(conf)
        , m_imap(conf)
    {
    }

    void invite(const plexus::network::endpoint& host, uint64_t host_secret) noexcept(false) override
    {
        _dbg_ << "sending invite message...";

        if (m_host != host || m_host_secret != host_secret)
        {
            m_smtp.push(plexus::utils::format("PLEXUS 1.0 %s %u %llu", host.first.c_str(), host.second, host_secret));
            m_host = host;
            m_host_secret = host_secret;
        }
    }

    void accept(plexus::network::endpoint& peer, uint64_t& peer_secret) noexcept(false) override
    {
        _dbg_ << "receiving accept message...";

        do
        {
            std::string message;
            do
            {
                message = m_imap.pull();
                
                std::smatch match;
                if (std::regex_search(message, match, std::regex("^PLEXUS\\s+1\\.0\\s+(\\S+)\\s+(\\d+)\\s+(\\d+)$")))
                {
                    m_peer = std::make_pair(match[1].str(), boost::lexical_cast<uint16_t>(match[2].str()));
                    m_peer_secret = boost::lexical_cast<uint64_t>(match[3].str());
                }
            }
            while (!message.empty());

            if (m_peer.first.empty())
                std::this_thread::sleep_for(std::chrono::seconds(30));
        } 
        while (m_peer.first.empty());

        peer = m_peer;
        peer_secret = m_peer_secret;
    }

    void refresh() override
    {
        m_host = plexus::network::endpoint();
        m_peer = plexus::network::endpoint();
        m_host_secret = 0;
        m_peer_secret = 0;
    }
};

std::shared_ptr<mediator> create_email_mediator(const std::string& smtp,
                                                const std::string& imap,
                                                const std::string& login,
                                                const std::string& passwd,
                                                const std::string& from,
                                                const std::string& to,
                                                const std::string& subj_from,
                                                const std::string& subj_to,
                                                const std::string& cert,
                                                const std::string& key,
                                                const std::string& ca,
                                                const std::string& smime_peer,
                                                const std::string& smime_cert,
                                                const std::string& smime_key,
                                                const std::string& smime_ca)
{
    network::endpoint smtp_ep(smtp, 25);

    std::smatch match;
    if (std::regex_search(smtp, match, std::regex("(\\w+://)?(.+):(.*)")))
    {
        smtp_ep.first = match[2].str();
        smtp_ep.second = boost::lexical_cast<uint16_t>(match[3].str());
    }

    network::endpoint imap_ep(imap, 143);

    if (std::regex_search(imap, match, std::regex("(\\w+://)?(.+):(.*)")))
    {
        imap_ep.first = match[2].str();
        imap_ep.second = boost::lexical_cast<uint16_t>(match[3].str());
    }

    return std::make_shared<email_mediator>(config{
        smtp_ep, imap_ep, login, passwd,
        from, to, subj_from, subj_to,
        cert, key, ca,
        { smime_peer, smime_cert, smime_key, smime_ca }});
}

}
