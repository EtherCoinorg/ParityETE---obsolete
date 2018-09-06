# [Parity For EthGold](https://ethgold.io/) - fast, light, and robust Ethereum Gold client

[![build status](https://gitlab.ethgold.io/parity/parity/badges/master/build.svg)](https://gitlab.ethgold.io/parity/parity/commits/master)
[![Snap Status](https://build.snapcraft.io/badge/paritytech/parity.svg)](https://build.snapcraft.io/user/paritytech/parity)
[![GPLv3](https://img.shields.io/badge/license-GPL%20v3-green.svg)](https://www.gnu.org/licenses/gpl-3.0.en.html)

- [Download the latest release here.](https://github.com/EthGold/ParityETG/releases)

### Join the chat!

Get in touch with us on Gitter:
[![Gitter: Parity](https://img.shields.io/badge/gitter-parity-4AB495.svg)](https://gitter.im/paritytech/parity)
[![Gitter: Parity.js](https://img.shields.io/badge/gitter-parity.js-4AB495.svg)](https://gitter.im/paritytech/parity.js)
[![Gitter: Parity/Miners](https://img.shields.io/badge/gitter-parity/miners-4AB495.svg)](https://gitter.im/paritytech/parity/miners)
[![Gitter: Parity-PoA](https://img.shields.io/badge/gitter-parity--poa-4AB495.svg)](https://gitter.im/paritytech/parity-poa)

Be sure to check out [our wiki](https://github.com/paritytech/parity/wiki) and the [internal documentation](https://paritytech.github.io/parity/ethcore/index.html) for more information.

----

## About Parity

Parity's goal is to be the fastest, lightest, and most secure Ethereum client. We are developing Parity using the sophisticated and cutting-edge Rust programming language. Parity is licensed under the GPLv3, and can be used for all your Ethereum needs.

Parity comes with a built-in wallet. To access [Parity Wallet](http://web3.site/) simply go to http://web3.site/ (if you don't have access to the internet, but still want to use the service, you can also use http://127.0.0.1:8180/). It includes various functionality allowing you to:

- create and manage your Ethereum accounts;
- manage your Ether and any Ethereum tokens;
- create and register your own tokens;
- and much more.

By default, Parity will also run a JSONRPC server on `127.0.0.1:8545`. This is fully configurable and supports a number of RPC APIs.

If you run into an issue while using parity, feel free to file one in this repository or hop on our [gitter chat room](https://gitter.im/paritytech/parity) to ask a question. We are glad to help!

**For security-critical issues**, please refer to the security policy outlined in `SECURITY.MD`.

Parity's current release is 1.7. You can download it at https://github.com/paritytech/parity/releases or follow the instructions below to build from source.

----

## Build dependencies

**Parity requires Rust version 1.19.0 to build**

We recommend installing Rust through [rustup](https://www.rustup.rs/). If you don't already have rustup, you can install it like this:

- Ubuntu:
	```bash
	apt install build-essential
	apt install pkg-config
	apt install libssl-dev
	apt install libudev-dev
 	source $HOME/.cargo/env
	rustup toolchain install 1.26.0
	rustup default 1.26.0
	rustup run 1.26.0 cargo build --release
	```
- Linux:
	```bash
	$ curl https://sh.rustup.rs -sSf | sh
	```

	Parity also requires `gcc`, `g++`, `libssl-dev`/`openssl`, `libudev-dev` and `pkg-config` packages to be installed.
- OSX:
	```bash
	$ curl https://sh.rustup.rs -sSf | sh
	```

	`clang` is required. It comes with Xcode command line tools or can be installed with homebrew.
- Windows

    Make sure you have Visual Studio 2015 with C++ support installed. Next, download and run the rustup installer from
	https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe, start "VS2015 x64 Native Tools Command Prompt", and use the following command to install and set up the msvc toolchain:
    ```
	$ rustup default stable-x86_64-pc-windows-msvc
    ```

Once you have rustup, install parity or download and build from source

----

## Install from the snap store

In any of the [supported Linux distros](https://snapcraft.io/docs/core/install):

```bash
sudo snap install parity --edge
```

(Note that this is an experimental and unstable release, at the moment)

----

## Build from source

```bash
# download Parity code
$ git clone https://github.com/paritytech/parity
$ cd parity

# build in release mode
$ cargo build --release
```

This will produce an executable in the `./target/release` subdirectory.
Note: if cargo fails to parse manifest try:

```bash
$ ~/.cargo/bin/cargo build --release
```
----

## Simple one-line installer for Mac and Ubuntu

```bash
bash <(curl https://get.ethgold.io -Lk)
```

## Start ParityETG
### Manually
To start Parity manually, just run
```bash
$ ./target/release/parity --chain etg --port 32800 \
--bootnodes="enode://9fce8413c4e77984cbaebc849e61392cf9fb753c6a532b5781dfc35340eb9b102fbcfdaa18dfb8bb98ff4b1e88a045c91bae29fe3cf8e4e1782b996a55c71a1b@206.189.75.108:32800"
```

Note that our default port is 32800 and you need to specify the bootnodes, otherwise the EtherCoin Cash won't be correctly synced.

and Parity will begin syncing the Ethereum blockchain.

### Using systemd service file
To start Parity as a regular user using systemd init:

1. Copy `parity/scripts/parity.service` to your
systemd user directory (usually `~/.config/systemd/user`).
2. To pass any argument to Parity, write a `~/.parity/parity.conf` file this way:
`ARGS="ARG1 ARG2 ARG3"`.

	Example: `ARGS="ui --identity MyMachine"`.
