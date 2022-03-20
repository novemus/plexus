#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>
#include <openssl/md5.h>
#include <vector>
#include <sstream>
#include "utils.h"

namespace plexus { namespace utils {

template <bool no_nl, bool url_cvt>
std::string to_base64_impl(const void* data, size_t length)
{
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* out = BIO_new(BIO_s_mem());

    if(no_nl)
    {
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    }
    out = BIO_push(b64, out);
    BIO_write(out, data, (int) length);
    (void) BIO_flush(out);

    char* data_ptr(0);
    size_t data_size = BIO_get_mem_data(out, &data_ptr);
    if(url_cvt)
    {
        for(char* p=data_ptr, *end=(data_ptr+data_size); p!=end; ++p)
        {
            switch(*p)
            {
                case '/': *p = '_';
                            break;
                case '+': *p = '-';
                            break;
            }
        }
    }

    std::string res(data_ptr, data_size);

    BIO_free_all(out);

    return res;
}

std::string to_base64(const void* data, size_t length)
{
    return to_base64_impl<false,false>(data, length);
}

std::string to_base64_no_nl(const void* data, size_t length)
{
    return to_base64_impl<true,false>(data, length);
}

std::string to_base64_url(const void* data, size_t length)
{
    return to_base64_impl<true,true>(data,length);
}

template <bool no_nl, bool url_cvt>
std::string from_base64_impl(const char* data, size_t length)
{
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* out = BIO_new(BIO_s_mem());
    BIO* in  = BIO_new_mem_buf((void*) data, (int) length);

    if(url_cvt)
    {
        char* data_ptr(0);
        size_t data_size = BIO_get_mem_data(in, &data_ptr);
        for(char* p=data_ptr, *end=(data_ptr+data_size); p!=end; ++p)
        {
            switch(*p)
            {
                case '_': *p = '/';
                            break;
                case '-': *p = '+';
                            break;
            }
        }
    }

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    if(!no_nl)
    {
        for (const char* ptr = data; ptr < data + length; ++ptr)
            if (*ptr == '\r' || *ptr == '\n')
            {
                BIO_clear_flags(b64, BIO_FLAGS_BASE64_NO_NL);
                break;
            }
    }

    b64 = BIO_push(b64, in);

    char inbuf[512];
    int ret = 0;
    while(true)
    {
        ret = BIO_read(b64, inbuf, 512);
        if (ret <= 0)
            break;

        BIO_write(out, inbuf, ret);
    }

    char* data_ptr(0);
    size_t data_size = BIO_get_mem_data(out, &data_ptr);
    std::string res(data_ptr, data_size);

    BIO_free(in);
    BIO_free(out);
    BIO_free(b64);

    return res;
}
std::string from_base64(const char* data, size_t length)
{
    return from_base64_impl<false,false>(data,length);
}
std::string from_base64_url(const char* data, size_t length)
{
    return from_base64_impl<true,true>(data,length);
}

std::string format(const std::string& format, ...)
{
    va_list args1;
    va_start(args1, format);
    va_list args2;
    va_copy(args2, args1);
    std::vector<char> buf(1 + std::vsnprintf(nullptr, 0, format.c_str(), args1));
    va_end(args1);
    std::vsnprintf(buf.data(), buf.size(), format.c_str(), args2);
    va_end(args2);
    return buf.data();
}

std::string format(const std::string& format, const boost::posix_time::ptime& time)
{
    std::stringstream out;
    out.imbue(std::locale(std::cout.getloc(), new boost::posix_time::time_facet(format.c_str())));
    out << time;
    return out.str();
}

std::string format(const std::string& format, const std::chrono::system_clock::time_point& time)
{
    std::time_t tt = std::chrono::system_clock::to_time_t(time);
    std::tm tm = *std::gmtime(&tt);
    std::stringstream ss;
    ss << std::put_time(&tm, format.c_str());
    return ss.str();
}

std::string to_hexadecimal(const uint8_t* data, size_t len)
{
    std::stringstream out;
    for (size_t i = 0; i < len; ++i)
    {
        out << std::setw(2) << std::setfill('0') << std::hex << (int)data[i];
    }
    return out.str();
}

}}
