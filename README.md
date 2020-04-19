# Myra

[![Build Status](https://travis-ci.org/joemccann/dillinger.svg?branch=master)](https://travis-ci.org/joemccann/dillinger)
<img align="center" width="112" alt="Screen Shot 2020-04-19 at 17 38 55" src="https://user-images.githubusercontent.com/61026070/79687106-b6985b00-8264-11ea-976a-02d87a5ae2d1.png">
Myra is an python based modular automatic report generator of pcap files giving summaries of packets as ensemble as well according to each layer.

  - Pcap parser based upon Scapy
  - Summary Report generator
  - Modular

### Notice
This is the master branch which is stable. Please checkout the develop branch for new features.

### Installation
Myra requires Scapy as dependency to run.

```sh
$ cd myra
$ pip3 install scapy
```
 Recommended for Dev Environments

```sh
$ python3 -m venv .venv
$ source .venv/bin/activate
$ pip3 install scapy
```

### Plugins

Myra currently supports the following plugins. 

| Plugin | README |
| ------ | ------ |
| Summary Report | - |
| IP report | - |
| DNS report | - |
| Transport report | - |

### Development

Want to contribute? Great! Hop on.

### Todos
 - Add support for more layers such as ARP.
 - Generate Top 10 list for each layer depending upon count.
 - Generate Plots of statistics.
 - Support output in HTML and PDF.
 - Write Unit Tests
 - Multi-threading support for efficiency.

License
----
Apache Software License V2

