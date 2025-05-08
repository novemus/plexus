# README

The [plexus](https://github.com/novemus/plexus) tool is designed to make the possibility of establishing a direct network connection between applications running on machines located behind *NAT*s. To do this `plexus` implements the well-known *UDP hole punching* technique using the *STUN*. You can use a `DHT` network or `email` service as a rendezvous to exchange public addresses between local and remote app instances. For success, it is necessary that *NAT*s on both sides implement independent mapping policy of internal addresses to public ones. That is, the public address and port assigned by the *NAT* should not be changed when the destination address/port of the outgoing packet is changed, while the source address/port of the outgoing packet remains unchanged. In addition, you will need an accessible *STUN* server and email accounts for each side if you want to use `email` as the rendezvous. It is possible to use one email account for both sides.

For those who prefer GUI, there is a [webpier](https://github.com/novemus/webpier) application based on the `plexus` library.

## Build

You can download [prebuild packages](https://github.com/novemus/plexus/releases) for Debian and Windows platforms.

The project depends on [boost](https://github.com/boostorg/boost), [openssl](https://github.com/openssl/openssl), [opendht](https://github.com/savoirfairelinux/opendht), [wormhole](https://github.com/novemus/wormhole) and [tubus](https://github.com/novemus/tubus) libraries. Clone the repository, then configure and build project.

```console
$ cd ~
$ git clone https://github.com/novemus/plexus.git
$ cd ~/plexus
$ [PKG_CONFIG_PATH=...] [CMAKE_PREFIX_PATH=...] cmake -B ./build -DCMAKE_BUILD_TYPE=Release [-DBUILD_SHARED_LIBS=ON] [-DBOOST_ROOT=...] [-DOPENSSL_ROOT_DIR=...]
$ cmake --build ./build --target all
$ cmake --build ./build --target install
```

## Using

Create an application repository and specify the path to the host directory according to the scheme `apprepo/owner@mailer.com/pin`. You must place there the X509 *cert.crt* certificate and the *private.key* key of the host. Likewise, make the directory for the peer and place there its *cert.crt* certificate. Make the same on the peer machine. The intermediate directory `owner@mailer.com` can be named as you want if you use the `DHT` rendezvous, but for the `email` case it must have the name of the appropriate email address. So for compatibility, it is recommended to always use the email address.

To run the example below you need to install the *openvpn*. The *exec.sh* script will try to establish point-to-point *VPN* connection.

Command for the accepting side:
```console
$ plexus --app-id=appname --app-repo=/path/to/apprepo --accept --dht-bootstrap=bootstrap.jami.net:4222 --host-info=host@mailer.com/hostid --peer-info=peer@mailer.com/peerid --stun-server=stun.someserver.com[:xxxx] --exec-command=~/plexus/tests/exec.sh
```

Command for the inviting side:
```console
$ plexus --app-id=appname --app-repo=/path/to/apprepo --dht-bootstrap=bootstrap.jami.net:4222 --host-info=host@mailer.com/hostid --peer-info=peer@mailer.com/peerid --stun-server=stun.someserver.com[:xxxx] --exec-command=~/plexus/tests/exec.sh
```

The `--app-id` key determines the target application. The `--host-info` argument points to the local application identity and the `--peer-info` points to the remote one. The `--app-repo` key is used to specify the application repository. The `--accept` key tells the app to cyclically accept invitations from the remotes. It must only be set for one side. If you want to accept many peers you should just omit the `--peer-info` argument. In this case, every peer is contained in the repository will be accepted.

Some *NAT*s may drop mapping when receiving an incoming packet that does not meet the filtering policy. This package may be a punching package sent by `plexus` towards the peer. In this case, it is impossible to punch the *passage* between the machines. To avoid such situations, `plexus` sets a small *ttl* to the punching packet, by default 7. In general, this is enough for the packet to go beyond the host *NAT* to punch it, but not to reach the peer *NAT* and not to drop its peer mapping. If necessary, you can set a more appropriate *ttl* using the `--punch-hops` argument, determining the suitable value by some routing utility. This only makes sense for the *accepting* side.

As soon as both `plexus` instanses make the *passage* to each other the command specified by `--exec-command` will be started. You can pass your arguments to the executable by `--exec-args` argument with the following wildcards:

`%innerip%` - local address specified by `--stun-client` argument

`%innerport%` - local port specified by the `--stun-client` argument

`%outerip%` - public address issued by the NAT

`%outerport%` - port issued by the NAT

`%peerip%` - public address of the peer received by the rendezvous

`%peerport%` - port of the peer received by the rendezvous

`%hostmail%` - owner of the host, first part of the `--host-info` argument

`%peermail%` - owner of the peer, first part of the `--peer-info` argument

`%hostpin%` - id of the host, second part of the `--host-info` argument

`%peerpin%` - id of the peer, second part of the `--peer-info` argument

`%secret%` - shared 64-bit key used for the handshake procedure

To learn about additional parameters run the tool with the `--help` key.

## Extensions and Library

If you need to link *TCP* applications and cannot use *VPN* for some reason, then consider the [wormhole](https://github.com/novemus/wormhole) tunneling extension as execution payload. For example, you can forward the remote *ssh* service with the following payload arguments.

Remote machine:
```console
--exec-command=wormhole --exec-args="--purpose=export --service=127.0.0.1:22 --gateway=%innerip%:%innerport% --faraway=%peerip%:%peerport%" --exec-log=export.ssh.log
```

Local machine:
```console
--exec-command=wormhole --exec-args="--purpose=import --service=127.0.0.1:2222 --gateway=%innerip%:%innerport% --faraway=%peerip%:%peerport%" --exec-log=import.ssh.log
```

Then connect to the remote *ssh* via the local mapping:
```console
$ ssh -p 2222 127.0.0.1
```

The `plexus` library API is described in the [plexus.h](https://github.com/novemus/plexus/blob/master/plexus.h) header and provides the same functionality with the additional UDP streaming capability, so you will need the [tubus](https://github.com/novemus/tubus) UDP library.

## Bugs and improvements

Feel free to [report](https://github.com/novemus/plexus/issues) bugs and [suggest](https://github.com/novemus/plexus/issues) improvements. 

## License

Plexus is licensed under the Apache License 2.0, which means that you are free to get and use it for commercial and non-commercial purposes as long as you fulfill its conditions. See the LICENSE.txt file for more details.

## Copyright

Copyright © 2022 Novemus Band. All Rights Reserved.
