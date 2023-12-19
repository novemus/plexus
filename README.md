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
cmake --build ./build --target plexus [wormhole]
cmake --build ./build --target install
```

## Using

To run the example below you need to install *openvpn*. Launch following commands with your arguments from the project directory on each machines. Script *exec.sh* will try to establish point-to-point *VPN* connection.

Command for remote machine:
```console
plexus --accept --email-smtps=smtp.peermailer.com[:xxxx] --email-imaps=imap.peermailer.com[:xxxx] --email-login=peerlogin --email-passwd=peerpassword --email-from=peerhost@peermailer.com --email-to=yourhost@yourmailer.com --host-id=remote --peer-id=local --stun-server=stun.someserver.com[:xxxx] --stun-client=xxx.xxx.xxx.xxx[:xxxx] --exec-command=~/plexus/exec.sh
```

`--accept` key tells the app to accept punching initiations from other side. It must only be set for one side.

Some *NAT*s may drop mappings when receiving an incoming packet that does not meet the filtering policy. This package may be a punching package sent by `plexus` towards the peer. In this case, it is impossible to punch the *passage* between the machines. To avoid such situations, `plexus` sets a small *ttl* to the punching packet, by default 7. In general, this is enough for the packet to go beyond the host *NAT* to punch it, but not reach the peer *NAT* to not drop peer mapping. If necessary, you can set a more appropriate *ttl* using the `--punch-hops` argument, defining a suitable value by some routing utility. This only makes sense for the *accepting* side.

Command for local machine:
```console
plexus --email-smtps=smtp.yourmailer.com[:xxxx] --email-imaps=imap.yourmailer.com[:xxxx] --email-login=yourlogin --email-passwd=yourpassword --email-from=yourhost@yourmailer.com --email-to=peerhost@peermailer.com --host-id=local --peer-id=remote --stun-server=stun.someserver.com[:xxxx] --stun-client=xxx.xxx.xxx.xxx[:xxxx] --exec-command=~/plexus/exec.sh
```

As soon as both `plexus` instanses make the *passage* to each other the command specified by `--exec-command` will be started. By default, the executable gets the following parameters:

```console
/path/to/exec/command innerip innerport outerip outerport peerip peerport
```

Alternatively you can pass your own arguments to executable by `--exec-args` and use `%innerip%`, `%innerport%`, `%outerip%`, `%outerport%`, `%peerip%`, `%peerport%`, `%secret%` wildcards.

`innerip` - local address specified by `--stun-client` argument

`innerport` - local port specified by the `--stun-client` argument

`outerip` - public address issued by the NAT

`outerport` - port issued by the NAT

`peerip` - public address of the peer received by email

`peerport` - port of the peer received by email

To learn about additional parameters run tool with `--help` argument.

## Extension

If you need to link *TCP* applications and for some reason cannot use *VPN*, then consider the [wormhole](https://github.com/novemus/wormhole) tunneling extension as execution payload.

## Bugs and improvements

Feel free to [report](https://github.com/novemus/plexus/issues) bugs and [suggest](https://github.com/novemus/plexus/issues) improvements. 

## License

Plexus is licensed under the Apache License 2.0, which means that you are free to get and use it for commercial and non-commercial purposes as long as you fulfill its conditions. See the LICENSE.txt file for more details.

## Copyright

Copyright © 2022 Novemus Band. All Rights Reserved.
