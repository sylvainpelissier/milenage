# Milenage
[![Build Status](https://travis-ci.org/sylvainpelissier/milenage.svg?branch=master)](https://travis-ci.org/sylvainpelissier/milenage)

This program can be used to generate GSM authentication triplets
using milenage algorithm specified in 3GPP TS 55.205 v9.0.0. These
authentication triplets can be used to test EAP-SIM with real UE
and freeradius server.

## Installing
The program is supported by Python 3 only. You need to have pycrytodome installed to run the program. You can install it as follows:
```bash
pip install pycryptodome --user
```

## Usage:
The program expects an input file with Ki, Op and rand values.
Please refer to sample input file for the format
```bash
./milenage [input]
```

## Author
Adapted from Manish Mehra [code](https://github.com/mmehra/milenage) to Python 3.
