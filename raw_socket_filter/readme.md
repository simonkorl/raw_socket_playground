# raw socket with filter

## bpf blog

https://blog.csdn.net/as3522/article/details/102972458

## compile and run

```sh
make
sudo ./a.out > output.log
```

## result

The BPF filter can block the writing event from being recongised as a listen event.