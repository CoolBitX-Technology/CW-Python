# CW-Python
To implement HWI interface so user can interact with CoolWallet using scripts.

# Prerequisites

## OS
Ubuntu 16.04.6 LTS

## Install Bitcoin Hardware Wallet Interface
[HWI 1.0.0](https://github.com/bitcoin-core/HWI/tree/1.0.0) released this on 16 Mar

# Install

## python-bitcoinlib
```
$ sudo apt-get install libssl-dev
$ git clone https://github.com/petertodd/python-bitcoinlib.git
$ cp -r python-bitcoinlib/bitcoin ~/.local/lib/python3.5/site-packages/
```

## pycrypto
```
pip3 install pycrypto
```

## CW-HWI
```
$ git clone https://github.com/CoolBitX-Technology/CW-Python
$ cd CW-Python/
$ cp coolwallet.py ~/Desktop/HWI/hwilib/devices/
$ cp -r CoolwalletLib/ ~/Desktop/HWI/hwilib/devices/
```

# Setup Coolwallet in HWI

## Add the Coolwallet device at the HWI
```
$ vi HWI/hwilib/devices/__init__.py
```
Add ``'coolwallet'`` in `__all__`

![](https://i.imgur.com/hotAIV9.png)

## IP Config

Get Local IP from App Server :
```
Local IP:192.168.66.146:9527
```
Modify "ip" according above IP
```
$ vi HWI/hwilib/devices/CoolwalletLib/tools/ip.config
```

![](https://i.imgur.com/KzVHszc.png)

## Test Coolwallet server connection

```
$ curl http://192.168.66.146:9527/?cmd=80100000
<!DOCTYPE html><html><body>Time: ... <br>Command:80100000<br>Data:null<br>Response:07 00 90 00 <br><br></body></html>
```

## First Binding

- HWI
Auto binding first host on HWI, 
then creat HD Wallet using seed at CW-Python/CoolwalletLib/tools/seed.
```
$ cd HWI/
$ sudo ./hwi.py enumerate
otp:******
Remote end closed connection without response
[{"type": "coolwallet", "path": "192.168.66.146", "fingerprint": "9ab01a72"}]
```

# Support Usage
Current implemented commands are:
- `enumerate`
- `getmasterxpub`
- `signtx`
- `getxpub`
- `getkeypool`
- `setup`


## signtx
Sign a PSBT
```
$ sudo ./hwi.py -d "path" -t "type" signtx [PSBT]
```
[PSBT] can generate from Bitcoin Core, follow below link
[Using Bitcoin Core with Hardware Wallets](https://github.com/bitcoin-core/HWI/blob/master/docs/bitcoin-core-usage.md)

## setup
Setup a device
```
$ sudo./hwi.py -d "path" -t "type" -i setup
```
