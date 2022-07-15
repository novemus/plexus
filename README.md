# README

The `plexus` tool is designed to make the possibility of establishing a direct network connection between applications running on machines located behind NATs. To do this `plexus` implements the well-known UDP hole punching technique using the STUN. An email service is used to exchange public addresses between app instances on the local and remote machines. For success, it is necessary that NATs of the both sides implement policy of independent mapping internal addresses to public ones. That is, the public address and port assigned by the NAT should not be changed when the destination address/port of the outgoing packet is changed, while the local address/port of the outgoing packet remains unchanged. In addition, you will need an accessible STUN server and email accounts for each side. It is possible to use one email account for both sides. For that, you need to specify a unique subjects for incoming and outgoing plexus messages.

## Build

Project depends on `boost` and `openssl` libraries. Clone repository and run make command.

```console
cd ~
git clone git@github.com:novemus/plexus.git
cd ~/plexus
cmake -B ./build [-DBOOST_ROOT=...] [-DOPENSSL_ROOT_DIR=...]
cmake --build ./build --target plexus
cmake --build ./build --target install
```

## Using

To run the example below you need to install `openvpn`. Launch following commands with your arguments from the project directory on each machines. Script `exec.sh` will try to establish point-to-point vpn connection.

Command for remote machine:
```console
plexus --accept --email-smtps=smtp.peermailer.com:xxx --email-imaps=imap.peermailer.com:xxx --email-login=peerlogin --email-passwd=peerpassword --email-from=peerhost@peermailer.com --email-to=yourhost@yourmailer.com --email-subj-from=remote --email-subj-to=local --stun-ip=stun.someserver.com --bind-port=xxxx --bind-ip=xxx.xxx.xxx.xxx --exec-command=~/plexus/exec.sh
```

`--accept` key tells the app to accept punching initiations from other side infinitely. It can only be set for one side.

Command for local machine:
```console
plexus --email-smtps=smtp.yourmailer.com:xxx --email-imaps=imap.yourmailer.com:xxx --email-login=yourlogin --email-passwd=yourpassword --email-from=yourhost@yourmailer.com --email-to=peerhost@peermailer.com --email-subj-from=local --email-subj-to=remote --stun-ip=stun.someserver.com --bind-port=xxxx --bind-ip=xxx.xxx.xxx.xxx --exec-command=~/plexus/exec.sh
```

As soon as both app instanses receive the messages with connection data, they will start punching the UDP holes to each other. After that, the command specified by `--exec-command` will be started. It gets the following parameters:

```console
/path/to/exec/command innerip innerport outerip outerport peerip peerport
```

`innerip` - inner address specified by the `--bind-ip` parameter

`innerport` - inner port specified by the `--bind-port` parameter

`outerip` - outer address issued by the NAT

`outerport` - outer port issued by the NAT

`peerip` - address of the peer recieved by email

`peerport` - port of the peer recieved by email

To learn about additional parameters run tool with `--help` argument.

## Bugs and improvements

Feel free to [report](https://github.com/novemus/plexus/issues) bugs and [suggest](https://github.com/novemus/plexus/issues) improvements. 

## License

Plexus is licensed under the Apache License 2.0, which means that you are free to get and use it for commercial and non-commercial purposes as long as you fulfill its conditions. See the LICENSE.txt file for more details.

## Copyright

Copyright © 2022 Novemus Band. All Rights Reserved.
