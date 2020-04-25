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
<img align="center" width="150" alt="Screen Shot 2020-04-19 at 17 38 55" src="https://user-images.githubusercontent.com/61026070/80220425-89ccb500-8663-11ea-8f77-da4a0bdba1ad.png">
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
### Choropleth Map of Source Countries
<img width="1315" alt="Screen Shot 2020-04-25 at 21 04 42" src="https://user-images.githubusercontent.com/61026070/80283604-83f4d380-8738-11ea-9bc2-73fd8cdf0016.png">

### Heat Map of Source Countries
<img width="1030" alt="Screen Shot 2020-04-25 at 23 00 15" src="https://user-images.githubusercontent.com/61026070/80286011-a1ca3480-8748-11ea-9c6a-240bc2144837.png">

<img width="823" alt="Screen Shot 2020-04-26 at 00 23 17" src="https://user-images.githubusercontent.com/61026070/80288114-77cb3f00-8755-11ea-9adc-5a79e192e0c8.png">
<img width="833" alt="Screen Shot 2020-04-26 at 00 23 53" src="https://user-images.githubusercontent.com/61026070/80288116-7d288980-8755-11ea-8983-b818af5e70e5.png">
<img width="830" alt="Screen Shot 2020-04-26 at 00 24 16" src="https://user-images.githubusercontent.com/61026070/80288122-80bc1080-8755-11ea-961e-3aaeaab561db.png">
<img width="826" alt="Screen Shot 2020-04-26 at 00 28 09" src="https://user-images.githubusercontent.com/61026070/80288127-8ade0f00-8755-11ea-92e3-d41f858e6a04.png">

### Development

Want to contribute? Great! Hop on.

### Todos
 - [x] Add support for more layers such as ARP.
 - [x] Replace that ugly coordinate map plot with a beautiful Choropleth.
 - [ ] Generate Top 10 list for each layer depending upon count.
 - [ ] Generate varieties of plots for statistics such as sankey, doughnut, tree, etc.
 - [ ] Support output in HTML and PDF.
 - [ ] Write Unit Tests
 - [ ] Implement Micro-services architecture for concurrency.

License
----
Apache Software License V2 (Maybe). Subject to change in future.

