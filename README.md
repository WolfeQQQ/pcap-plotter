# PCAP Analyzer in C

program for Linux that reads a `.pcap` file, analyzes traffic, creates two PNG charts, and generates a PDF report .

## Dependencies

You need `gcc`, `make`, and three libraries:
* `libpcap` – reads packets from `.pcap` 
* `libgd` – draws PNG charts
* `libharu` (`libhpdf`) – creates the report

### Install on Ubuntu / Debian

```bash
sudo apt update
sudo apt install build-essential libpcap-dev libgd-dev libhpdf-dev
```

### Install on Fedora

```bash
sudo dnf install gcc make libpcap-devel gd-devel libharu-devel
```

## Build

Run this in the project folder:

```bash
make
```

To clean build files and output files:

```bash
make clean
```

## Usage

Run the program and pass a `.pcap` file:

```bash
./pcap_analyzer traffic.pcap
```

Output files created in the current folder:
* `tcp_udp.png` 
* `top_ports.png` 
* `raport.pdf` 