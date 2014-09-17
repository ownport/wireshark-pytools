wireshark-pytools
=================

Scripts collection for working with wireshark

## m3ua-unbundle.py

Short presentation about m3ua-unbundle https://docs.google.com/presentation/d/1vjIivmb8TwIR0W1gO28hlLEycMzq0wdKes9ryDh9rMk/view

### Installation (Ubuntu)

To run m3ua-unbunde.py you need to have python and wireshark installed on your PC. Python included by default, to install wireshark please type
```
# sudo apt-get install wireshark
```
That's all.
```
# ./m3ua-unbundle.py <source.pcap> <unbundled.pcap>
```

### Installation (Windows)

As for Ubuntu, you need to have installed python http://www.python.org and wireshark http://www.wireshark.org. During wireshark installation be sure that tshak and text2pcap tools are marked for installation. When python and wireshark are installed, in command line (console) you need to check that path to wireshark directory where are located tshark.exe and text2pcap.exe files is specified in system environment variable %PATH%. 


## Contributors

- [Vasil Velichkov](https://github.com/velichkov)
