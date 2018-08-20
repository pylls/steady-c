# Steady device C implementation
Steady is a simple end-to-end secure logging system. This repository contains a C implementation of
the device that generate log events.
For the relay and collector, [see the Go repository](https://github.com/pylls/steady).
The go repository also contains further documentation.

### Brief instructions to compile and run
1. clone this repository
2. install [libsodium](https://libsodium.org)
3. run make
4. follow the steps in the [the Go repository](https://github.com/pylls/steady) to get a relay running and device config copied
5. echo "hello world" | ./demo 127.0.0.1 16 1 1

Above should log "hello world" to the relay at 127.0.0.1 with 16 MiB of max device memory using
encryption (1) and compression (1).

### Paper (TODO)
[https://eprint.iacr.org/2018/737](https://eprint.iacr.org/2018/737)

### License
Apache 2.0
