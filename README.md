# README

The `plexus` tool is designed to make the possibility of a direct network connection between applications running on machines located behind NATs. To do this `plexus` implements the well-known UDP hole punching technique using the STUN. An email service is used to exchange public addresses between app instances on the local and remote machines. For success, it is necessary that NATs of the both sides implement policy of independent mapping internal addresses to public ones. That is, the public address and port assigned by the NAT should not be changed when the destination address of the outgoing packet is changed, while the local address of the outgoing packet remains unchanged. In addition, you will need an accessible STUN server and email accounts for each side. It is possible to use one email account for both sides. For that, you need to specify a unique subjects for incoming and outgoing plexus messages.

## Build

Project depends on `boost` and `openssl` libraries. Clone repository and run make command.

```console
cd ~
git clone git@github.com:novemus/plexus.git
cd ~/plexus
make
```

## Using

To run the example below you need to install `openvpn`. Launch following commands with your arguments from the project directory on each machines. Script `exec.sh` will try to establish point-to-point vpn connection.

Command for local machine:
```console
cd ~/plexus
./plexus --email-smtps=smtp.yourmailer.com:xxx --email-imaps=imap.yourmailer.com:xxx --email-login=yourlogin --email-passwd=yourpassword --email-from=yourhost@yourmailer.com --email-to=peerhost@peermailer.com --email-subj-from=local --email-subj-to=remote --stun-ip=stun.someserver.com --bind-port=xxxx --bind-ip=xxx.xxx.xxx.xxx --exec-command=./exec.sh
```

Command for remote machine:
```console
cd ~/plexus
./plexus --email-smtps=smtp.peermailer.com:xxx --email-imaps=imap.peermailer.com:xxx --email-login=peerlogin --email-passwd=peerpassword --email-from=peerhost@peermailer.com --email-to=yourhost@yourmailer.com --email-subj-from=remote --email-subj-to=local --stun-ip=stun.someserver.com --bind-port=xxxx --bind-ip=xxx.xxx.xxx.xxx --exec-command=./exec.sh
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

Copyright © 2022 Novemus Band
