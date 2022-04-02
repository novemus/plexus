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

#define PLEXUS_VERSION "1.0"

namespace plexus { namespace email {

struct config
{
    std::string smtp;
    std::string imap;
    std::string sender;
    std::string recipient;
    std::string login;
    std::string password;
    std::string certificate;
    std::string key;
    int64_t timeout;
};

class mediator
{
    static const int BUFFER_SIZE = 8192;

public:

    mediator(const std::string& server, const std::string& cert, const std::string& key, int64_t timeout)
        : m_ssl(network::create_ssl_client(server.c_str(), cert.c_str(), key.c_str(), timeout))
    {
    }

    typedef std::function<bool(const std::string&)> response_parser_t;

    void connect(const response_parser_t& parse)
    {
        m_ssl->connect();

        std::string response;
        do {
            int read = m_ssl->read(m_buffer, BUFFER_SIZE);
            response.append((char*)m_buffer, read);
        } while (!parse(response));

        _trc_ << ">>>>>\n" << response << "\n*****";
    }

    void request(const std::string& request, const response_parser_t& parse)
    {
        _trc_ << "<<<<<\n" << request << "\n*****";

        int written = 0;
        do {
            written += m_ssl->write((const uint8_t*)request.c_str() + written, request.size() - written);
        } while (written < (int)request.size());

        std::string response;
        do {
            int read = m_ssl->read(m_buffer, BUFFER_SIZE);
            response.append((char*)m_buffer, read);
        } while (!parse(response));

        _trc_ << ">>>>>\n" << response << "\n*****";
    }

private:

    uint8_t m_buffer[BUFFER_SIZE];
    std::shared_ptr<network::ssl> m_ssl;
};

std::string address(const std::string& email)
{
    std::smatch match;
    if (std::regex_search(email, match, std::regex("[\\w\\s]*\\<?([^\\<]+@[^\\>]+)\\>?\\s*")))
    {
        return match[1].str();
    }
    throw std::runtime_error("bad email address");
}

class smtp
{
    typedef mediator::response_parser_t response_parser_t;
    
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

public:
    
    smtp(const config& conf)
        : m_config(conf)
    {
    }

    void push(const std::string& data) noexcept(false)
    {
        static const char* EMAIL =
            "To: %s\r\n"
            "From: %s\r\n"
            "X-Plexus-Version: " PLEXUS_VERSION "\r\n"
            "X-Plexus-Data: %s\r\n"
            "Subject: Plexus\r\n"
            "\r\n"
            "Hello, Plexus!\r\n"
            ".\r\n";

        std::unique_ptr<mediator> mdr = std::make_unique<mediator>(
            m_config.smtp,
            m_config.certificate,
            m_config.key,
            m_config.timeout
        );

        mdr->connect(code_checker(220));
        mdr->request("HELO smtp\r\n", code_checker(250));
        mdr->request("AUTH LOGIN\r\n", code_checker(334));
        mdr->request(utils::format("%s\r\n", utils::to_base64_no_nl(m_config.login.c_str(), m_config.login.size()).c_str()), code_checker(334));
        mdr->request(utils::format("%s\r\n", utils::to_base64_no_nl(m_config.password.c_str(), m_config.password.size()).c_str()), code_checker(235));
        mdr->request(utils::format("MAIL FROM: %s\r\n", address(m_config.sender).c_str()), code_checker(250));
        mdr->request(utils::format("RCPT TO: %s\r\n", address(m_config.recipient).c_str()), code_checker(250));
        mdr->request("DATA\r\n", code_checker(354));
        mdr->request(utils::format(EMAIL, m_config.recipient.c_str(), m_config.sender.c_str(), utils::to_base64_no_nl(data.c_str(), data.size()).c_str()), code_checker(250));
    }

private:

    config m_config;
};

class imap
{
    typedef mediator::response_parser_t response_parser_t;

    const response_parser_t connect_checker = [](const std::string& response) -> bool {
            std::smatch match;
            bool done = std::regex_search(response, match, std::regex("^\\*\\s+(OK|NO)\\s+.*\\r\\n$"));
            if (done && match[1] != "OK")
                throw std::runtime_error(response);
            return done;
        };

    const response_parser_t success_checker = [](const std::string& response) -> bool {
        std::smatch match;
        bool done = std::regex_search(response, match, std::regex(".*\\ntag\\s+(OK|NO)\\s+.*\\r\\n$"));
        if (done && match[1] != "OK")
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
            m_data.clear();
            auto what = utils::format(
                ".*\\sTo:\\s+%s\\s+From:\\s+%s\\s+X-Plexus-Version:\\s+(\\d+\\.\\d+)\\s+X-Plexus-Data:\\s+(\\S+)\\s.*",
                m_config.sender.c_str(), 
                m_config.recipient.c_str());
            std::smatch match;
            if (std::regex_search(response, match, std::regex(what)))
            {
                std::string raw = match[2].str();
                m_data = utils::from_base64(raw.c_str(), raw.size());
            }
            else
            {
                m_data = "";
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
        std::unique_ptr<mediator> mdr = std::make_unique<mediator>(
            m_config.imap,
            m_config.certificate,
            m_config.key,
            m_config.timeout
        );

        mdr->connect(connect_checker);
        mdr->request(utils::format("tag LOGIN %s %s\r\n", m_config.login.c_str(), m_config.password.c_str()), success_checker);
        mdr->request("tag SELECT INBOX\r\n", select_parser);

        if (m_unseen.empty())
        {
            mdr->request(utils::format("tag UID SEARCH SINCE %d-%b-%Y\r\n", std::chrono::system_clock::now()), search_parser);
        }

        std::string data;
        do
        {
            if (m_unseen.empty())
                break;

            unsigned int uid = m_unseen.front();
            mdr->request(
                utils::format("tag UID FETCH %d (BODY.PEEK[HEADER.FIELDS (From To X-Plexus-Version X-Plexus-Data)])\r\n", uid), fetch_parser
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

class email_postman : public postman
{
    smtp m_smtp;
    imap m_imap;

public:

    email_postman(const config& conf)
        : m_smtp(conf)
        , m_imap(conf)
    {
    }

    void send_message(const std::string& data) noexcept(false) override
    {
        _dbg_ << "sending plexus message...";
        m_smtp.push(data);
    }

    std::string receive_message() noexcept(false) override
    {
        _dbg_ << "receiving plexus message...";
        return m_imap.pull();
    }
};

std::shared_ptr<postman> create_email_postman(const std::string& smtp,
                                              const std::string& imap,
                                              const std::string& sender,
                                              const std::string& recipient,
                                              const std::string& login,
                                              const std::string& password,
                                              const std::string& certificate,
                                              const std::string& key,
                                              int64_t timeout)
{
    return std::make_shared<email_postman>(config{
        smtp,
        imap,
        sender,
        recipient,
        login,
        password,
        certificate,
        key,
        timeout});
}

}
