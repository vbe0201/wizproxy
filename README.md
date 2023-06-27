# catalyst

A proxy server for exfiltrating and manipulating encrypted Wizard101
network traffic.

## How it works

catalyst sits between a client and a server, receiving and forwarding
all traffic from both parties to each other.

Initially, client and server establish a session by confirming they
use the same RSA key pair and making the client generate a symmetric
encryption key and send it back encrypted to the server.

catalyst compromises this session handshake to exfiltrate said AES keys.

Subsequently, catalyst can decrypt all data passing through and implement
desirable features on top of that.

## Setup

> Follow these steps closely, no support will be provided when steps were
> skipped. I do not take responsibility in case you get your account banned.

### Requirements

Make sure [Python 3.11](https://www.python.org) and [Poetry](https://python-poetry.org)
are installed on your system, and clone the repository.

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

### Connecting to catalyst

First, you need to run catalyst using `poetry run catalyst -- --keys /path/to/keys`
where `/path/to/keys` is the directory with the two JSONs from the previous step.

Then navigate to the `Bin/` directory of your Wizard101 installation (on Windows,
it's usually `C:\ProgramData\KingsIsle Entertainment\Wizard101\Bin`).

Open a command line and run `.\WizardGraphicalClient.exe -L 127.0.0.1 12000` to
connect to catalyst.
