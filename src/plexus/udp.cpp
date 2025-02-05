/*
 * Copyright (c) 2022 Novemus Band. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 */

#include <plexus/network.h>

namespace plexus { namespace network {

std::shared_ptr<udp_socket> create_udp_transport(boost::asio::io_service& io, const boost::asio::ip::udp::endpoint& bind)
{
    auto socket = std::make_shared<udp_socket>(bind.protocol(), io);
    socket->bind(bind);

    return socket;
}

}}
