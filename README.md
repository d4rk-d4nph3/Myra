# Myra

[![N|Solid](https://cldup.com/dTxpPi9lDf.thumb.png)](https://nodesource.com/products/nsolid)

[![Build Status](https://travis-ci.org/joemccann/dillinger.svg?branch=master)](https://travis-ci.org/joemccann/dillinger)

Myra is an python based modular automatic report generator of pcap files giving summaries of packets as ensemble as well according to each layer.

  - Pcap parser based upon Scapy
  - Summary Report generator
  - Modular

# New Features!

  - Import a HTML file and watch it magically convert to Markdown
  - Drag and drop images (requires your Dropbox account be linked)

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

