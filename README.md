# README

The [plexus](https://github.com/novemus/plexus) tool is designed to make the possibility of establishing a direct network connection between applications running on machines located behind NATs. To do this `plexus` implements the well-known *UDP/TCP hole punching* technique using STUN. You can use a `DHT` network or `Email` service as a rendezvous to exchange public addresses between local and remote app instances. For success, at least it is necessary that NATs on both sides implement independent mapping policy of internal addresses to public ones. That is, the public address and port assigned by the NAT should not be changed when the destination address/port of the outgoing packet is changed, while the source address/port of the outgoing packet remains unchanged. In addition, you will need an accessible STUN server and email accounts for each side if you want to use `Email` as the rendezvous. You can use one email account for both sides.

For those who prefer GUI, there is the [webpier](https://github.com/novemus/webpier) application based on the `plexus` library.

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

Create an application repository and specify the path to the host directory according to the scheme *apprepo/owner@mailer.com/pin*. You must place there the X509 *cert.crt* certificate and the *private.key* key of the host. Likewise, make the directory for the peer and place there its *cert.crt* certificate. Make the same on the peer machine. The intermediate directory *.../owner@mailer.com/...* can be named as you want if you use the `DHT` rendezvous, but for the `Email` case it must have the name of the appropriate email address. So for compatibility, it is recommended to always use the email address.

To run the example below you need to install the *openvpn*. The *exec.sh* script will try to establish point-to-point VPN connection.

Command for the accepting side:
```console
$ plexus --app-name=appname --app-repo=/path/to/apprepo --accept --dht-bootstrap=bootstrap.jami.net --host-id=host@mailer.com/hostid --peer-id=peer@mailer.com/peerid --udp-stun=stun.someserver.com[:xxxx] --exec-cmd=~/plexus/tests/exec.sh [--app-qos=udp:either]
```

Command for the inviting side:
```console
$ plexus --app-name=appname --app-repo=/path/to/apprepo --dht-bootstrap=bootstrap.jami.net --host-id=host@mailer.com/hostid --peer-id=peer@mailer.com/peerid --udp-stun=stun.someserver.com[:xxxx] --exec-cmd=~/plexus/tests/exec.sh [--app-qos=udp:either]
```

The `--app-name` key determines the target application. The `--host-id` argument points to the local application identity and the `--peer-id` points to the remote one. The `--app-repo` key is used to specify the application repository. The `--accept` key tells the app to cyclically accept invitations from the remotes. It must only be set for one side. If you want to accept many peers you should just omit the `--peer-id` argument. In this case, every peer is contained in the repository will be accepted. To set a special application criteria you can use the `--app-qos` key with any of the following values: *udp:client|udp:server|udp:mutual|tcp:client|tcp:server|tcp:mutual|ssl:client|ssl:server|ssl:mutual|any:either*. The special value *any:either* allows to negotiate the most suitable transport protocol and connection schema, so it only makes sense for special applications or scenarios. Negotiation can lead to the *mutual* connection schema for both sides, which is the same as the *client* schema, which means that the ssl applications must be able to not only connect towards each other, but also choose a proper role for the ssl handshake.

Some *NAT*s may drop mapping when receiving an incoming packet that does not meet the filtering policy. This packet may be a punching one sent by `plexus` towards the peer. To avoid such situations, `plexus` sets a small *ttl* to the punching packet, by default 7. In general, this is enough for the packet to go beyond the host NAT to punch it, but not to reach the peer NAT and not to drop its peer mapping. If necessary, you can set a more appropriate *ttl* using the `--nat-hops` argument, determining the suitable value by some routing utility.

As soon as both `plexus` instances make the *passage* to each other, the command specified by `--exec-cmd` will be started. You can pass your arguments to the executable by `--exec-args` argument with the following wildcards:

`%inner%` - local endpoint specified by the `--udp-bind` or `--tcp-bind` arguments

`%outer%` - public endpoint issued by the NAT

`%alien%` - public endpoint of the peer received by the rendezvous

`%qos%` - application criteria agreed upon by the rendezvous

`%hostid%` - the host identifier specified by the `--host-id` argument

`%peerid%` - the peer identifier specified by the `--peer-id` argument

Also you can set the `--exec-env` argument to pass the list of extra environment to the command with the following wildcards:

`%secret%` - shared 64-bit key agreed upon by the rendezvous

`%hostcert%` - path to the host certificate

`%hostkey%` - path to the host private key

`%peercert%` - path to the peer certificate

To learn about additional parameters run the tool with the `--help` key.

## Extensions and Library

TCP applications are known to connect unstable via NAT, but the `plexus` can punch TCP holes whenever possible. Specify TCP STUN server with `--tcp-stun` key and appropriate `--app-qos` argument on both sides. It is strongly recommended to specify the `--udp-stun` argument too, since the `plexus` synchronizes the sides using UDP handshake before handing over control to your application. If you need more NAT-tolerance mean to connect TCP applications, then consider the [wormhole](https://github.com/novemus/wormhole) tunneling tool as execution payload. For example, you can forward the remote *ssh* service with the following payload arguments.

Remote machine:
```console
--exec-cmd=wormhole --exec-args="--purpose=export --service=127.0.0.1:22 --gateway=%inner% --faraway=%alien%" --exec-log=export.ssh.log --exec-env="WORMHOLE_SECRET=%secret%"
```

Local machine:
```console
--exec-cmd=wormhole --exec-args="--purpose=import --service=127.0.0.1:2222 --gateway=%inner% --faraway=%alien%" --exec-log=import.ssh.log --exec-env="WORMHOLE_SECRET=%secret%"
```

Then connect to the remote *ssh* via the local mapping:
```console
$ ssh -p 2222 127.0.0.1
```

The `plexus` library API is described in the [plexus.h](https://github.com/novemus/plexus/blob/master/plexus.h) header.

## Bugs and improvements

Feel free to [report](https://github.com/novemus/plexus/issues) bugs and [suggest](https://github.com/novemus/plexus/issues) improvements.

## License

Plexus is licensed under the Apache License 2.0, which means that you are free to get and use it for commercial and non-commercial purposes as long as you fulfill its conditions. See the LICENSE.txt file for more details.

## Copyright

Copyright © 2022 Novemus Band. All Rights Reserved.
