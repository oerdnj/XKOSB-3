# Diffie-Hellman-Merkle key exchange

This is an implementation of Diffie-Hellman-Merkle key exchange in client-server
architecture.

## Build Instructions

Following libaries are needed:

* gmplib (https://gmplib.org) - modern, easy-to-use software library for encryption, decryption, signatures, password hashing, and more.
* libuv (https://libuv.org) - multi-platform support library with a focus on asynchronous I/O.
* libsodium (https://libsodium.org) - modern, easy-to-use software library for encryption, decryption, signatures, password hashing, and more.
* meson (https://mesonbuild.com) - open source build system meant to be both extremely fast, and, even more importantly, as user friendly as possible.
* ninja (https://ninja-build.org) - small build system with a focus on speed.

The build system is meson, so build is done by running:

    $ meson setup build
	$ cd build
	$ ninja

## Usage

First run a server, then run a client; client will first download the p, g and
then the server and client will exchange their public keys, calculate shared
secret.  The shared secret is then fed to hash function to generate 32-bytes key
used to as key to establish symmetric XChaCha2-Poly1305 encryption between the
two endpoints.

NOTE: Server can only talk to a single client at the time, but it will accept
multiple connections; server's private and public keys are different for every
connection.

### Server

    $ ./dhm --server <ip_address> <port>

Example:

    $ ./dhm --server ::1 12345

### Client

    # ./dhm --client <ip_address> <port>

Example:

    # ./dhm --client ::1 12345

### Advanced usage

You can also provide your own modulus (prime) and base (primitive root modulo).
Otherwise a safe prime is generated and thus base will be always 2.

## Implementation details

The DHM key exchange is implemented using gmplib that provides large int
arithmetics (including the exponentiation function modulo).  This is the DHM in
its simplest form - there's no authentication of the parties.

The symmetric key encryption is implemented using libsodium's XChaCha20-Poly1305
stream cipher. The code calls abort() on any crypto failure, which is not
exactly user friendly.  The library has support for 'additional data' that can
be included in the computation of the authentication tag.  I think this could be
used to establish trust between the parties (both client and server would have
to provide same value of 'additional data'), but I would have to verify this.

The networking part is implemented using libuv excellent asynchronous I/O, so
it's full of callbacks and very hard to read to whoever is not used to it :).
The code is full of hard assert() calls as it expects all TCP and TTY writes and
reads to succeed.  Pull requests to improve the error handling welcome.
