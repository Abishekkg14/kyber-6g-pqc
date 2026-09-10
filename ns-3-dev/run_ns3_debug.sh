#!/bin/bash
cd "/home/force123/roshyy/Kyber-6G project/Kyber-6G project/ns-3-dev"
export PYTHONPATH=./bindings/python:$PYTHONPATH
python3 ./ns3 --version > /tmp/ns3_out.txt 2>&1
cat /tmp/ns3_out.txt
