# Myra

[![Build Status](https://travis-ci.org/joemccann/dillinger.svg?branch=master)](https://travis-ci.org/joemccann/dillinger)

Myra is an python based modular automatic report generator of pcap files giving summaries of packets as ensemble as well according to each layer.

  - Pcap parser based upon Scapy
  - Summary Report generator
  - Modular

### Notice
This is the develop branch which is unstable and is being actively worked on. 

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

### Currently
<img width="980" alt="Screen Shot 2020-04-18 at 13 30 42" src="https://user-images.githubusercontent.com/61026070/79631394-de11f980-8178-11ea-903b-0462c54630f7.png">
<img width="1022" alt="Screen Shot 2020-04-18 at 13 20 36" src="https://user-images.githubusercontent.com/61026070/79631319-55935900-8178-11ea-9d01-7c33d73bcb36.png">
<img width="913" alt="Screen Shot 2020-04-18 at 13 20 59" src="https://user-images.githubusercontent.com/61026070/79631322-56c48600-8178-11ea-9dde-c4fadfa81150.png">
<img width="1052" alt="Screen Shot 2020-04-18 at 13 21 11" src="https://user-images.githubusercontent.com/61026070/79631324-5926e000-8178-11ea-9194-9487f3664fcb.png">
<img width="1032" alt="Screen Shot 2020-04-18 at 13 21 23" src="https://user-images.githubusercontent.com/61026070/79631326-5af0a380-8178-11ea-90e4-a4c1c27d831e.png">

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

