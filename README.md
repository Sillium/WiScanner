WiScanner
=========

Python script to notify you when known devices enter or leave your network.

Prerequisites
=============

Python3, nmap, Twython, Pushover

Installation on a Raspberry Pi
==============================

Setup WiFi:
http://www.maketecheasier.com/setup-wifi-on-raspberry-pi/

Install NMAP:

    sudo apt-get install nmap

Install Python NMAP:
http://linoxide.com/linux-how-to/python-nmap-library/

    wget https://pypi.python.org/packages/source/p/python-nmap/python-nmap-0.3.4.tar.gz
    tar xf python-nmap-0.3.4.tar.gz
    cd python-nmap-0.3.4
    python3 setup.py install

Install Twython:
http://twython.readthedocs.org/en/latest/usage/install.html#pip-or-easy-install

    git clone git://github.com/ryanmcgrath/twython.git
    python3 setup.py install

Install Requests Module for Twython:
http://askubuntu.com/questions/351976/how-to-install-requests-module-for-python-3-2-by-using-pip-install

    sudo apt-get install python3-pip
    sudo pip-3.2 install requests

Install missing requests_oauth:
    sudo pip-3.2 install requests_oauthlib

Install Pushover:

    git clone https://github.com/Wyattjoh/pushover
    cd pushover
    python3 setup.py install
    
Install dweet.io:
https://pypi.python.org/pypi/dweepy/0.0.1

    sudo su -
    pip-3.2 install dweepy

Running
=======

    sudo python3 wiscanner.py

