# Myra

[![Made with](https://img.shields.io/static/v1?label=Made%20with&message=python&color=af4bce)](https://www.python.org)
[![experimental](https://img.shields.io/static/v1?label=stability&message=experimental&color=critical)](http://github.com/badges/stability-badges)
[![Build Status](https://travis-ci.org/joemccann/dillinger.svg?branch=master)](https://travis-ci.org/joemccann/dillinger)
[![License](https://img.shields.io/badge/License-Apache%202-blue.svg)](https://shields.io/)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://GitHub.com/Naereen/StrapDown.js/graphs/commit-activity)

Myra is an automatic report generator of pcap files written in Python. It generates summaries of packets as ensemble as well according to each layer.

  - Based on [Scapy](https://github.com/secdev/scapy)
  - Summary report generator
  - Support for threat intel feeds
  - Strives to be modular

## Logo
<img align="center" width="112" alt="Screen Shot 2020-04-19 at 17 38 55" src="https://user-images.githubusercontent.com/61026070/79687106-b6985b00-8264-11ea-976a-02d87a5ae2d1.png">

### Notice
This is the master branch which is made to be more stable. Thus, this branch lags behind the other branches. Please checkout the develop branch for bleeding edge code.

### Installation

```sh
$ cd myra
$ pip3 install -r requirements.txt
```
 Recommended for Dev Environments

```sh
$ python3 -m venv .venv
$ source .venv/bin/activate
$ pip3 install -r requirements.txt
```

### Plugins

Myra currently supports the following plugins. 

| Plugin | README |
| ------ | ------ |
| Summary Report | - |
| IP report | - |
| DNS report | - |
| Transport report | - |
| Threat Intel report | - |

### Development

Want to contribute? Great! Hop on.

### Todos
 - [x] Add support for more layers such as ARP.
 - [x] Integrate Threat Intelligence 
 - [ ] Generate Top 10 list for each layer depending upon count.
 - [ ] Generate Plots of statistics.
 - [ ] Support output in HTML and PDF.
 - [ ] Write unit tests
 - [ ] Multiprocessing support for efficiency.
 