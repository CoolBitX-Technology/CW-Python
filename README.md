# CW-Python
To implement HWI interface so user can interact with CoolWallet using scripts.

# Prerequisites

## OS
Ubuntu 16.04.6 LTS

## CoolWallet
Binding host device first

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

# Setup

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
```
$ cd HWI/
$ sudo ./hwi.py enumerate
otp:******
Remote end closed connection without response
[{"type": "coolwallet", "error": "Could not open client or get fingerprint information: Done register but not confirmed, plz approve the host at first host", "path": "192.168.66.146"}]
```

- App Server

Approve the HWI host at APP Server

- HWI
```
$ sudo ./hwi.py enumerate
[{"type": "coolwallet", "path": "192.168.66.146", "fingerprint": "921eabb2"}]
```

# Usage

## enumerate
List all available devices
```
$ sudo ./hwi.py enumerate
[{"type": "coolwallet", "path": "192.168.66.146", "fingerprint": "921eabb2"}]
```

## getmasterxpub
Get the extended public key at m/44'/0'/0'
```
$ sudo ./hwi.py -d 192.168.66.146 -t coolwallet getmasterxpub
{"xpub": "xpub6C5xd9tA6t9QXzWBArHT2cLDtBuhogMwNZyBkgmXEJr6jJqB6JCtkaq4jhuqATb5VxKvrU3dKS89dKRFdY31bAAq6e5xLbULVcMWEX8ZQwu"}
```

## signtx
Sign a PSBT
```
$ sudo ./hwi.py -d 192.168.66.146 -t coolwallet signtx [PSBT]
```
[PSBT] can generate from Bitcoin Core, follow below link
[Using Bitcoin Core with Hardware Wallets](https://github.com/bitcoin-core/HWI/blob/master/docs/bitcoin-core-usage.md)
