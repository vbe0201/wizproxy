# wizproxy

A packet proxy for exfiltrating and manipulating encrypted Wizard101
network traffic.

## How it works

wizproxy sits between a client and a server, receiving and forwarding
all traffic from both parties to each other.

Initially, client and server establish a session by confirming they
use the same RSA key pair and making the client generate a symmetric
encryption key and send it back encrypted to the server.

wizproxy compromises this session handshake to exfiltrate said AES keys.

Subsequently, wizproxy can decrypt all data passing through and implement
desirable features on top of that.

## Setup

> Follow these steps closely, no support will be provided when steps were
> skipped. I do not take responsibility in case you get your account banned.

### Requirements

Make sure [Python 3.11](https://www.python.org) is installed on your system,
and install with `pip install -U wizproxy`.

Run Wizard101's patch client, login, and let it update the game. It is
important to always be up-to-date when trying to use the proxy.

### Patching the game

**You will not be able to connect to KingsIsle's servers anymore after this step until you run the patch client again.**

Download the [latest release of ki-keyring](https://github.com/cedws/ki-keyring/releases)
for your operating system and run the following commands:

```
ki-keyring-windows-amd64 eject > ki_keys.json
ki-keyring-windows-amd64 inject > injected_keys.json
```

If your installation of Wizard101 is not in the default install directory,
you may need to provide the `--bin /path/to/WizardGraphicalClient.exe`
argument to both commands.

You should then be left with two non-empty files `ki_keys.json` and
`injected_keys.json` in your working directory.

### Connecting to wizproxy

First, you need to run wizproxy using `python -m wizproxy /path/to/keys`
where `/path/to/keys` is the directory with the two JSONs from the previous step.

After successful launch, you will see a log message along the lines of
`[0.0.0.0:40881] Spawning shard to SocketAddress(ip='...', port=...)...` in your
console. Note the port at the start, `40881` in this case.

Then navigate to the `Bin/` directory of your Wizard101 installation (on Windows,
it's usually `C:\ProgramData\KingsIsle Entertainment\Wizard101\Bin`).

Open a command line and run `.\WizardGraphicalClient.exe -L 127.0.0.1 40881` to
connect to wizproxy.

### Using with EU servers

**Skip this if you're a US player.**

wizproxy does support the EU servers of the game just as well as the US ones.

Simply follow all the above steps and then launch the proxy using the command
`python -m wizproxy /path/to/keys -l <login server ip>`.

You can find the login server IP in `PatchClient/BankA/PatchConfig.xml` inside
the game's installation directory, XML key `LoginHostname`.

For the German servers for example, you would use
`python -m wizproxy /path/to/keys -l login-de.eu.wizard101.com`.

### Dumping captures

The wizproxy CLI supports several configuration options for customization,
which can be found using the `--help` flag.

Notably, `-c /path/to/capture.pcapng` dumps all packets passing through the
proxy to a pcapng file. Each packet will be annotated with a comment saying
what shard produced it and what client ID it was.

A Wireshark plugin that enables filtering expression for KingsIsle frames
is provided in [`extra/`](./extra/).

[Moonlight](https://github.com/kronos-project/moonlight) can be used for
post-processing these captures.

## FAQ

> Client X crashed: Invalid signature

This means your client is out of date. Open the patch client and let it run
to completion, then follow the above setup steps again to inject a custom
key ring into the updated binary.

> Is injection supported?

Yes and no.

Injection as in arbitrarily injecting any amount of packets at any given time
is not supported and, for many use cases where this would be considered, can
get your account banned.

Interception and manipulating the contents of specific packet types, however,
is supported and is the encouraged way of interacting with the packet stream.

> I'm getting `json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)`

This is because you are on Windows and the JSON files you dumped are UTF-16
encoded. Use any text editor of your preference to convert them to UTF-8.
