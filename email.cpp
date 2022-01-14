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

#define PLEXUS_VERSION "1.0"

namespace plexus { namespace features {

class ssl_channel_mediator
{
    static const int BUFFER_SIZE = 8192;

public:

    ssl_channel_mediator(const std::string& server, const std::string& cert, const std::string& key, long timeout)
        : m_channel(network::create_ssl_channel(server.c_str(), cert.c_str(), key.c_str(), timeout))
    {
    }

    typedef std::function<bool(const std::string&)> response_parser_t;

    void connect(const response_parser_t& parse)
    {
        m_channel->open();

        std::string response;
        do {
            int read = m_channel->read(m_buffer, BUFFER_SIZE);
            response.append(m_buffer, read);
        } while (!parse(response));

        if (m_trace)
            std::cout << ">>>>>\n" << response << "\n*****" << std::endl;
    }

    void request(const std::string& request, const response_parser_t& parse)
    {
        if (m_trace)
            std::cout << "<<<<<\n" << request << "\n*****" << std::endl;

        int written = 0;
        do {
            written += m_channel->write(request.c_str() + written, request.size() - written);
        } while (written < (int)request.size());

        std::string response;
        do {
            int read = m_channel->read(m_buffer, BUFFER_SIZE);
            response.append(m_buffer, read);
        } while (!parse(response));

        if (m_trace)
            std::cout << ">>>>>\n" << response << "\n*****" << std::endl;
    }

private:

    char m_buffer[BUFFER_SIZE];
    std::unique_ptr<network::channel> m_channel;
    bool m_trace = false;
};

class smtp_strategy
{
    typedef ssl_channel_mediator::response_parser_t response_parser_t;
    
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
    
    smtp_strategy(const email_pipe_config& conf)
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

        std::unique_ptr<ssl_channel_mediator> mediator = std::make_unique<ssl_channel_mediator>(
            m_config.smtp,
            m_config.certificate,
            m_config.key,
            m_config.timeout
        );

        mediator->connect(code_checker(220));
        mediator->request("HELO smtp\r\n", code_checker(250));
        mediator->request("AUTH LOGIN\r\n", code_checker(334));
        mediator->request(utils::format("%s\r\n", utils::to_base64_no_nl(m_config.login.c_str(), m_config.login.size()).c_str()), code_checker(334));
        mediator->request(utils::format("%s\r\n", utils::to_base64_no_nl(m_config.password.c_str(), m_config.password.size()).c_str()), code_checker(235));
        mediator->request(utils::format("MAIL FROM: %s\r\n", m_config.frontend.c_str()), code_checker(250));
        mediator->request(utils::format("RCPT TO: %s\r\n", m_config.backend.c_str()), code_checker(250));
        mediator->request("DATA\r\n", code_checker(354));
        mediator->request(utils::format(EMAIL, m_config.frontend.c_str(), m_config.backend.c_str(), utils::to_base64_no_nl(data.c_str(), data.size()).c_str()), code_checker(250));
    }

private:

    const email_pipe_config m_config;
};

class imap_strategy
{
    typedef ssl_channel_mediator::response_parser_t response_parser_t;

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

                unsigned long validity;
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

                unsigned long uid = 0;
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
                m_config.frontend.c_str(), 
                m_config.backend.c_str());
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

    imap_strategy(const email_pipe_config& conf)
        : m_config(conf)
    {
    }

    std::string pull() noexcept(false)
    {
        std::unique_ptr<ssl_channel_mediator> mediator = std::make_unique<ssl_channel_mediator>(
            m_config.imap,
            m_config.certificate,
            m_config.key,
            m_config.timeout
        );

        mediator->connect(connect_checker);
        mediator->request(utils::format("tag LOGIN %s %s\r\n", m_config.login.c_str(), m_config.password.c_str()), success_checker);
        mediator->request("tag SELECT INBOX\r\n", select_parser);

        if (m_unseen.empty())
        {
            mediator->request(utils::format("tag UID SEARCH SINCE %d-%b-%Y\r\n", std::chrono::system_clock::now()), search_parser);
        }

        std::string data;
        do
        {
            if (m_unseen.empty())
                break;

            unsigned int uid = m_unseen.front();
            mediator->request(
                utils::format("tag UID FETCH %d (BODY.PEEK[HEADER.FIELDS (From To X-Plexus-Version X-Plexus-Data)])\r\n", uid), fetch_parser
            );
            
            m_unseen.pop_front();
            m_last_seen = uid;

            data = pull_data();
        } while (data.empty());

        return data;
    }

private:

    const email_pipe_config m_config;
    std::list<unsigned long> m_unseen;
    std::string m_data;
    unsigned long m_last_seen = 0;
    unsigned long m_validity = 0;
};

class email_pipe : public pipe
{
    smtp_strategy m_smtp;
    imap_strategy m_imap;

public:

    email_pipe(const email_pipe_config& config)
        : m_smtp(config)
        , m_imap(config)
    {
    }

    void push(const std::string& data) noexcept(false) override
    {
        m_smtp.push(data);
    }

    std::string pull() noexcept(false) override
    {
        return m_imap.pull();
    }
};

pipe* create_email_pipe(const email_pipe_config& config)
{
    return new email_pipe(config);
}

}}
