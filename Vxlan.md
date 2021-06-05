# Layer 2 commands 

List helpful commands to run the Layer 2 topology

```
make start
make onos-log
make app-build
make app-reload
make netcfg
make mn-cli
make stop
```

MTU 1500

default iperf UDP encapsulated exceeds 1500, add -l flag to reduce default size

```
h1 iperf -c h6 -u -b1M -P5 -t60 -i1 -l 1310
```