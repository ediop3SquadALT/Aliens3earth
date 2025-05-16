#!/bin/bash
sudo apt update
sudo apt install -y python3 python3-pip python3-dev libffi-dev libssl-dev build-essential
pip3 install paramiko netifaces requests scapy
sudo apt install -y tcpdump graphviz
echo your setup is done. lol
