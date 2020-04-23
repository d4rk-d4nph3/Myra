# Myra
[![Made with](https://img.shields.io/static/v1?label=Made%20with&message=python&color=af4bce)](https://www.python.org)
[![experimental](https://img.shields.io/static/v1?label=stability&message=experimental&color=critical)](http://github.com/badges/stability-badges)
[![Build Status](https://travis-ci.org/joemccann/dillinger.svg?branch=master)](https://travis-ci.org/joemccann/dillinger)
[![License](https://img.shields.io/badge/License-Apache%202-blue.svg)](https://shields.io/)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://GitHub.com/Naereen/StrapDown.js/graphs/commit-activity)

Myra is an python based modular automatic report generator of pcap files giving summaries of packets as ensemble as well according to each layer.

  - Pcap parser based upon Scapy
  - Summary Report generator
  - Modular

## Logo
<img align="center" width="112" alt="Screen Shot 2020-04-19 at 17 38 55" src="https://user-images.githubusercontent.com/61026070/80141004-89cba700-85c8-11ea-885e-bedf8100218d.png">
This is the develop branch which is very unstable and is being actively worked on. If only the features are stable enough then, they are merged to master.

### NOTICE TO CONTRIBUTERS
There is another branch named zero which is created for integration of PyZMQ. I will work on that branch for now and will only review pull requests for develop branch.

### Dependencies
Myra requires the following dependencies:
- animation
- descartes
- fpdf
- geopandas
- matplotlib
- pandas
- scapy


### Plugins

Myra currently supports the following plugins. 

| Plugin | README |
| ------ | ------ |
| Summary Report | - |
| IP report | - |
| DNS report | - |
| Transport report | - |
| Threat Intelligence report | - |

### Currently
#### Torrent Activity Captured in this short capture file (Just the first pic)
<img width="1088" alt="Screen Shot 2020-04-18 at 18 11 31" src="https://user-images.githubusercontent.com/61026070/79637606-a159f880-81a0-11ea-9ab7-9073d0c57102.png">
<img width="980" alt="Screen Shot 2020-04-18 at 13 30 42" src="https://user-images.githubusercontent.com/61026070/79631394-de11f980-8178-11ea-903b-0462c54630f7.png">
<img width="1022" alt="Screen Shot 2020-04-18 at 13 20 36" src="https://user-images.githubusercontent.com/61026070/79631319-55935900-8178-11ea-9d01-7c33d73bcb36.png">
<img width="913" alt="Screen Shot 2020-04-18 at 13 20 59" src="https://user-images.githubusercontent.com/61026070/79631322-56c48600-8178-11ea-9dde-c4fadfa81150.png">
<img width="1052" alt="Screen Shot 2020-04-18 at 13 21 11" src="https://user-images.githubusercontent.com/61026070/79631324-5926e000-8178-11ea-9194-9487f3664fcb.png">
<img width="1032" alt="Screen Shot 2020-04-18 at 13 21 23" src="https://user-images.githubusercontent.com/61026070/79631326-5af0a380-8178-11ea-90e4-a4c1c27d831e.png">

### Development

Want to contribute? Great! Hop on.

### Todos
 - [x] Add support for more layers such as ARP.
 - [ ] Replace that ugly coordinate map plot with a beautiful Choropleth.
 - [ ] Generate Top 10 list for each layer depending upon count.
 - [ ] Generate varieties of plots for statistics such as sankey, doughnut, tree, etc.
 - [ ] Support output in HTML and PDF.
 - [ ] Write Unit Tests
 - [ ] Implement Micro-services architecture for concurrency.

License
----
Apache Software License V2 (Maybe). Subject to change in future.

