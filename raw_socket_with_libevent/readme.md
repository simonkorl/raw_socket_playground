# raw socket with libevent

## install libevent

### By apt on ubuntu

`sudo apt install libevent-dev`

### install dependencies

1. install libmbedtls
    sudo apt update
    sudo apt install libmbedtls-dev

### make

1. cmake
2. make install

### link

add library path in /etc/ld.so.conf or /etc/ld.so.conf.d path in ubuntu

`sudo ldconfig`

## Compile and run

```sh
make
sudo ./a.out > output.log
```

## Result

There might be a lot of reading events and a few of them will give special output with packet content.

This program listens to a raw socket and periodically send ipv4 packet into the same raw socket.

It turns out that the raw socket event loop will recongnise the writing operation into the raw socket as a new listen event at default, even if the writing operation is in the same program.