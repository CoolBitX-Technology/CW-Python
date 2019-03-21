#Coolwallet Client

from ..hwwclient import HardwareWalletClient
from ..base58 import get_xpub_fingerprint, decode, encode, to_address, xpub_main_2_test, get_xpub_fingerprint_hex
from trezorlib import protobuf, tools, btc
#from CoolwalletLib.CwAPI import cwse_apdu_command
from CoolwalletLib.CwClient import CoolwalletClient as Coolwallet
from CoolwalletLib import CwClient

import os
import sys
import json
import hashlib
import hmac
from Crypto.Cipher import AES

class CoolwalletClient(HardwareWalletClient):

    def __init__(self, path, password=''):
        #print(os.getcwd())
        super(CoolwalletClient, self).__init__(path, password)
        self.client = Coolwallet()

        # if it wasn't able to find a client, throw an error
        if not self.client:
            raise IOError("no Device")


    # Must return a dict with the xpub
    # Retrieves the public key at the specified BIP 32 derivation path
    def get_pubkey_at_path(self, path):
        #print('get_pubkey_at_path')
        # convert BIP32 path string to list of uint32 int
        expanded_path = tools.parse_path(path)
        output = Coolwallet.get_pubkey_at_path(self.client, expanded_path) 
        if self.is_testnet:
            return {'xpub':xpub_main_2_test(output)}
        else:
            #print(output)
            return {'xpub':output}
        pass

    def sign_tx(self, tx):
        pass

    def sign_message(self, message, keypath):
        raise NotImplementedError('The HardwareWalletClient base class does not '
            'implement this method')

    def display_address(self, keypath, p2sh_p2wpkh, bech32):
        pass

    def setup_device(self, hwdName):
        Coolwallet.setup_device(self.client, hwdName)

    def wipe_device(self):
        #back to nohost
        pass

    def close(self):
        self.client.close()
        print('close HTTP connet')

def enumerate(password=None):
    results = []
    #for dev in enumerate_devices():
    with open('ip.config') as config:
            ipdata = json.load(config)
    path = ipdata['ip']
    d_data = {}

    d_data['type'] = 'coolwallet'
    d_data['path'] = path
    hstCred = bytes(range(32))

    try:
        client = CoolwalletClient(d_data['path'], password)
        client.setup_device('abcdefghijklmnopqrstuvwxyz012345')
        master_xpub = client.get_pubkey_at_path('m/0h')['xpub']
        print('master_xpub:', master_xpub)
        d_data['fingerprint'] = get_xpub_fingerprint_hex(master_xpub)
        client.close()
    except Exception as e:
        d_data['error'] = "Could not open client or get fingerprint information: " + str(e)

    results.append(d_data)
    return results
