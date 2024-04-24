# README

The [plexus](https://github.com/novemus/plexus) tool is designed to make the possibility of establishing a direct network connection between applications running on machines located behind *NAT*s. To do this `plexus` implements the well-known *UDP hole punching* technique using the *STUN*. An email service is used to exchange public addresses between app instances on the local and remote machines. For success, it is necessary that *NAT*s of the both sides implement policy of independent mapping internal addresses to public ones. That is, the public address and port assigned by the *NAT* should not be changed when the destination address/port of the outgoing packet is changed, while the local address/port of the outgoing packet remains unchanged. In addition, you will need an accessible *STUN* server and email accounts for each side. It is possible to use one email account for both sides. For that, you need to specify a unique subjects (`--host-id` and `--peer-id` arguments) for incoming and outgoing plexus messages.

## Build

You can download [prebuild packages](https://github.com/novemus/plexus/releases) for Debian and Windows platforms.

The project depends on `boost` and `openssl` libraries. Clone repository and run make command.

```console
cd ~
git clone --recurse-submodules https://github.com/novemus/plexus.git
cd ~/plexus
cmake -B ./build [-DBOOST_ROOT=...] [-DOPENSSL_ROOT_DIR=...]
cmake --build ./build --target plexus [plexus_shared] [plexus_static] [plexus_ut]
cmake --build ./build --target install
```

To build libraries, specify the *plexus_static* and *plexus_shared* targets.

## Using

To run the example below you need to install *openvpn*. Launch following commands with your arguments on each machines. Script *exec.sh* will try to establish point-to-point *VPN* connection.

Command for remote machine:
```console
plexus --accept --app-id=appname --email-smtps=smtp.mailer.com[:xxxx] --email-imaps=imap.mailer.com[:xxxx] --email-login=login --email-password=password --host-info=host@mailer.com/hostname --peer-info=peer@mailer.com/peername --stun-server=stun.someserver.com[:xxxx] --stun-client=xxx.xxx.xxx.xxx[:xxxx] --exec-command=~/plexus/tests/exec.sh
```

`--accept` key tells the app to cyclically accept initiations from other side. It must only be set for one side. If you want to accept several peers, create application repository and specify the path for each peer as *apprepo/peer@mailer.com/peername*. To use email encryption, you must place the X509 *cert.crt* peer certificates and, optionally, their CA *ca.crt* certificates in the appropriate folders. You must also make the same for the local host and additionally place its *private.key* key. The same must be done on every peer machine. Specify application repository with `--app-repo` argument.

Some *NAT*s may drop mappings when receiving an incoming packet that does not meet the filtering policy. This package may be a punching package sent by `plexus` towards the peer. In this case, it is impossible to punch the *passage* between the machines. To avoid such situations, `plexus` sets a small *ttl* to the punching packet, by default 7. In general, this is enough for the packet to go beyond the host *NAT* to punch it, but not reach the peer *NAT* to not drop peer mapping. If necessary, you can set a more appropriate *ttl* using the `--punch-hops` argument, defining a suitable value by some routing utility. This only makes sense for the *accepting* side.

Command for local machine:
```console
plexus --app-id=appname --email-smtps=smtp.mailer.com[:xxxx] --email-imaps=imap.mailer.com[:xxxx] --email-login=login --email-password=password --host-info=host@mailer.com/hostname --peer-info=peer@mailer.com/peername --stun-server=stun.someserver.com[:xxxx] --stun-client=xxx.xxx.xxx.xxx[:xxxx] --exec-command=~/plexus/tests/exec.sh
```

As soon as both `plexus` instanses make the *passage* to each other the command specified by `--exec-command` will be started. You can pass your arguments to the executable by `--exec-args` argument with the following wildcards:

`%innerip%` - local address specified by `--stun-client` argument

`%innerport%` - local port specified by the `--stun-client` argument

`%outerip%` - public address issued by the NAT

`%outerport%` - port issued by the NAT

`%peerip%` - public address of the peer received by email

`%peerport%` - port of the peer received by email

`%hostpin%` - name of the host

`%peerpin%` - name of the peer

`%hostmail%` - email of the host

`%peermail%` - email of the peer

To learn about additional parameters run tool with `--help` argument.

## Library and Extensions

If you need to link *TCP* applications and cannot use *VPN* for some reason, then consider the [wormhole](https://github.com/novemus/wormhole) tunneling extension as execution payload. The `plexus` library API is described in the [plexus.h](https://github.com/novemus/plexus/blob/master/plexus.h) header and provides the same functionality with additional UDP streaming capability, so you will need [tubus](https://github.com/novemus/tubus) UDP library.

## Bugs and improvements

Feel free to [report](https://github.com/novemus/plexus/issues) bugs and [suggest](https://github.com/novemus/plexus/issues) improvements. 

## License

Plexus is licensed under the Apache License 2.0, which means that you are free to get and use it for commercial and non-commercial purposes as long as you fulfill its conditions. See the LICENSE.txt file for more details.

## Copyright

Copyright © 2022 Novemus Band. All Rights Reserved.
