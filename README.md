# Secure Drop 
##### A secure version of airdrop
###### By: Jacob Glik, and Peyton Somerville

<br>

## Prerequisites

### Python Packages
* `cryptography`
  * `pip install cryptography`
  * `python3 -m pip install cryptography`
* `stdiomask`
  * `pip install stdiomask`
  * `python3 -m pip install stdiomask`
* `tinyec`
  * `pip install tinyec`
  * `python3 -m pip install tinyec`
* `cffi`
  * `pip install cffi`
  * `python3 -m pip install cffi`


<br>

<br>

## Instructions
### Type `python3 secureDrop.py` to run Secure Drop.
### Type `python3 reset.py` to reset Secure Drop and erase all data.


<br>

<br>


## Usage Note:
###### Secure Drop will work best on `Windows`. The functionality may be limited when running on other operating systems.
###### The size of files is limited to `2 GB` when transferring between instances of Secure Drop.

<br>

<br>

## Implements
###### Complete "end-to-end encryption" 

1. `Credit Authority` validates clients and their asymmetric encryption keys
2. An `ECDH Key Handshake` is performed between the two parties before every message to ensure `Perfect Forward Secrecy`
3. All communication is symmetrically encrypted using the symmetric key generated from the `ECDH Key Handshake` step above
4. The file system is tamper-proof due to the `FileCredibility` system



