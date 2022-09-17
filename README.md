![Linting](https://github.com/s41m0n/goshark/workflows/Linting/badge.svg)

# GoShark: Network Packet Analyzer and Monitoring

GoShark is a tool for capturing and analyzing network traffic. It offers the possibility to dump the traffic into pcap files and to apply custom monitoring logic on the network packet, by leveraging a plugin-architecture. Last but not least, it supports multi-core packet capture and monitoring using FANOUT groups, and it comes with a tool for sorting single pcaps into a unified capture.

## Usage

```bash
❯ go run -exec sudo . --help
[sudo] password for s41m0n: 
Root Command

Usage:
  root [flags]
  root [command]

Available Commands:
  capture      Capture packets
  completion   Generate the autocompletion script for the specified shell
  help         Help about any command
  list_devices Listen network devices
  sorter       Sort Pcaps

Flags:
  -h, --help   help for root

Use "root [command] --help" for more information about a command.
```

* **list_devices**: list all available network devices
* **completion**: generate autocompletion script for the specified shell
* **sorter**: sort pcaps file into a unique unified one (used when captured packets in multi-core mode)
* **capture**: main command to start capturing/monitoring network traffic

The main command can be used as follows:

```bash
❯ go run -exec sudo . capture --help
Capture packets

Usage:
  root capture [flags]

Flags:
  -b, --blocksize int       Block Size (MB) (default 524288)
  -c, --cpuprofile string   File to store CPU profile
  -d, --device string       Device to capture on
  -F, --filter string       BPF filter
  -f, --framesize int       Frame Size (default 4096)
  -h, --help                help for capture
  -M, --module string       Module to load
  -m, --multicore           Use Fanout (multicore)
  -n, --numblock int        Num Block (default 128)
  -p, --pcap string         Pcap file to store
  -P, --promiscuous         Promiscuous Mode
  -s, --statsec uint        Stats print interval (default 5)
  -V, --vlan                Use vlan
```

* **--device**: mandatory flag to specify the network interface
* **--pcap**: flag to specify to dump the captured network traffic to the apposite pcap file
* **--module**: flag to specify the module to load for monitoring network traffic. If replaced at runtime, GoShark reloads it and apply the new logic to network traffic

While all the other flags are not mandatory, the user must provide the **--device** and at least one among **--pcap** and **--module** to start the tool.

An example command is:

```bash
❯ go run -exec sudo . capture -d lo -M monitor.so -p capture.pcap -m
```

GoShark will analyze network traffic from the **lo** interface, dump it into multiple pcap files named **capture{i}.pcap** using multi-core (where **i** is the number of the core), and execute the processing logic specified in the monitoring module **monitor.so**.

An example to build a monitoring module as plugin is in the [example](./examples/) folder. The module must provide the **Parse** and **ParseConcurrent** methods, and can be compiled with the following command:

```bash
❯ go build -buildmode=plugin -linkshared -o monitor.so examples/monitor.go
```

## Acknowledgements

The [google-stenographer](https://github.com/google/stenographer) project is the core project I used as reference for using Go-pcap libraries and structure the project.

GoShark is not supposed to overcome the google-stenographer tool, while it offers an additional possibility to dinamically plug and unplug monitoring modules for further analsis on network packets.
