


## Install

### Docker
Install docker and clone the repo

Build the container
```bash
$ docker build . -t Pcredz
```

Then use the command below to map the current working directory inside the Pcredz container. This is useful for moving .pcap files to parse or for retrieving log files from a live capture.
```bash
$ docker run --net=host -v $(pwd):/opt/Pcredz -it pcredz
```

### Linux

On a debian based OS bash:

```bash
apt install python3-pip && sudo apt-get install libpcap-dev && pip3 install Cython && pip3 install python-libpcap
```

## Usage
 
 ```
python3 ./Pcredz -i eth0 -v
```

### Options

```
  -h, --help          show this help message and exit
  -f capture.pcap     Pcap file to parse
  -d /home/pnt/pcap/  Pcap directory to parse recursivly
  -i eth0             interface for live capture
  -v                  More verbose.
  -o output_dir       Store log files in output_dir instead of the directory containing Pcredz.
```

