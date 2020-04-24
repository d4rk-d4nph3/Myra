# GeoIP Repo

### Source
The data in this folder is obtained from **MaxMind**.

### Usage
The GeoLite2-City file is used by the *MaxMind GeoIP2 Python API* used in Myra.
Previously, the web was queried to obtain geo-information of IPs and was slow.
The usage of this local database file will now make this query order of magnitude faster.

### GeoIP API Source
> https://github.com/maxmind/GeoIP2-python