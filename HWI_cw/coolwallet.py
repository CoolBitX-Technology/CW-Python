#Coolwallet Client

from ..hwwclient import HardwareWalletClient
from ..base58 import get_xpub_fingerprint, decode, encode, to_address, xpub_main_2_test, get_xpub_fingerprint_hex
from ..serializations import ser_uint256

from trezorlib import protobuf, tools, btc
from trezorlib import messages as proto

#from CoolwalletLib.CwAPI import cwse_apdu_command
from CoolwalletLib.CwClient import CoolwalletClient as Coolwallet
from CoolwalletLib import CwClient

from bitcoin import SelectParams, params
from bitcoin.core import b2x, lx, COIN, COutPoint, CMutableTxOut, CMutableTxIn, CMutableTransaction, Hash160, x
from bitcoin.core.script import CScript, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG, SignatureHash, SIGHASH_ALL
from bitcoin.core.scripteval import VerifyScript, SCRIPT_VERIFY_P2SH
from bitcoin.core.serialize import Hash
from bitcoin.wallet import CBitcoinAddress, CBitcoinSecret, P2PKHBitcoinAddress, P2SHBitcoinAddress


import os
import sys
import json
import hashlib
import hmac
from Crypto.Cipher import AES

class CoolwalletClient(HardwareWalletClient):

    def __init__(self, path, password=''):
        print("--------------------------------- CoolwalletClient init ---------------------------------")
        super(CoolwalletClient, self).__init__(path, password)
        self.simulator = False
        self.client = Coolwallet()

        # if it wasn't able to find a client, throw an error
        if not self.client:
            raise IOError("no Device")
        self.password = password
        self.type = 'Coolwallet'
        print("--------------------------------- CoolwalletClient init Done ---------------------------------")


    # Must return a dict with the xpub
    # Retrieves the public key at the specified BIP 32 derivation path
    def get_pubkey_at_path(self, path):
        # convert BIP32 path string to list of uint32 int
        expanded_path = tools.parse_path(path)
        output = Coolwallet.get_pubkey_at_path(self.client, expanded_path) 
        if self.is_testnet:
            return {'xpub':xpub_main_2_test(output)}
        else:
            return {'xpub':output}
        pass

    def sign_tx(self, tx):
        print('--------------------------------- CoolwalletClient sign_tx ---------------------------------')
        # Get this devices master key fingerprint
        master_key = Coolwallet.get_pubkey_at_path(self.client, [2147483648, 2147483648, 2147483662])
        master_fp = get_xpub_fingerprint(master_key)

        # Prepare inputs
        inputs = []
        for psbt_in, txin in zip(tx.inputs, tx.tx.vin):
            txinputtype = proto.TxInputType()

            # Set the input stuff
            txinputtype.prev_hash = ser_uint256(txin.prevout.hash)[::-1]
            txinputtype.prev_index = txin.prevout.n
            txinputtype.sequence = txin.nSequence

            # Detrermine spend type
            if psbt_in.non_witness_utxo:
                txinputtype.script_type = proto.InputScriptType.SPENDADDRESS
            elif psbt_in.witness_utxo:
                # Check if the output is p2sh
                if psbt_in.witness_utxo.is_p2sh():
                    txinputtype.script_type = proto.InputScriptType.SPENDP2SHWITNESS
                else:
                    txinputtype.script_type = proto.InputScriptType.SPENDWITNESS

            # Check for 1 key
            if len(psbt_in.hd_keypaths) == 1:
                # Is this key ours
                pubkey = list(psbt_in.hd_keypaths.keys())[0]
                fp = psbt_in.hd_keypaths[pubkey][0]
                keypath = list(psbt_in.hd_keypaths[pubkey][1:])
                print('pubkey: ', pubkey.hex())
                print('psbt_in: ', psbt_in)
                print('psbt_in.hd_keypaths: ', psbt_in.hd_keypaths)

                print('fp: ', fp)
                print('master_fp: ', master_fp)

                if fp == master_fp:
                    # Set the keypath
                    print("# Set the keypath")
                    txinputtype.address_n = keypath

            # Check for multisig (more than 1 key)
            elif len(psbt_in.hd_keypaths) > 1:
                raise TypeError("Cannot sign multisig yet")
            else:
                raise TypeError("All inputs must have a key for this device")

            # Set the amount
            if psbt_in.non_witness_utxo:
                txinputtype.amount = psbt_in.non_witness_utxo.vout[txin.prevout.n].nValue
            elif psbt_in.witness_utxo:
                txinputtype.amount = psbt_in.witness_utxo.nValue

            # append to inputs
            inputs.append(txinputtype)

        # address version byte
        if self.is_testnet:
            p2pkh_version = b'\x6f'
            p2sh_version = b'\xc4'
            bech32_hrp = 'tb'
        else:
            p2pkh_version = b'\x00'
            p2sh_version = b'\x05'
            bech32_hrp = 'bc'

        # prepare outputs
        outputs = []
        for out in tx.tx.vout:
            txoutput = proto.TxOutputType()
            txoutput.amount = out.nValue
            txoutput.script_type = proto.OutputScriptType.PAYTOADDRESS
            if out.is_p2pkh():
                txoutput.address = to_address(out.scriptPubKey[3:23], p2pkh_version)
            elif out.is_p2sh():
                txoutput.address = to_address(out.scriptPubKey[2:22], p2sh_version)
            else:
                wit, ver, prog = out.is_witness()
                if wit:
                    txoutput.address = bech32.encode(bech32_hrp, ver, prog)
                else:
                    raise TypeError("Output is not an address")

            # append to outputs
            outputs.append(txoutput)

        # Prepare prev txs
        prevtxs = {}
        for psbt_in in tx.inputs:
            if psbt_in.non_witness_utxo:
                prev = psbt_in.non_witness_utxo

                t = proto.TransactionType()
                t.version = prev.nVersion
                t.lock_time = prev.nLockTime

                for vin in prev.vin:
                    i = proto.TxInputType()
                    i.prev_hash = ser_uint256(vin.prevout.hash)[::-1]
                    i.prev_index = vin.prevout.n
                    i.script_sig = vin.scriptSig
                    i.sequence = vin.nSequence
                    t.inputs.append(i)

                for vout in prev.vout:
                    o = proto.TxOutputBinType()
                    o.amount = vout.nValue
                    o.script_pubkey = vout.scriptPubKey
                    t.bin_outputs.append(o)
                #logging.debug(psbt_in.non_witness_utxo.hash)
                prevtxs[ser_uint256(psbt_in.non_witness_utxo.sha256)[::-1]] = t

        # Sign the transaction
        tx_details = proto.SignTx()
        tx_details.version = tx.tx.nVersion
        tx_details.lock_time = tx.tx.nLockTime

        print('\r\n[========== deserialize PSBT Trx ==========]')
        print(inputs)
        print(outputs)
        print(tx_details)
        #print(prevtxs)

        print('[========== deserialize PSBT Trx ==========]')

        SelectParams('testnet')
        print('[testnet]')
        print('[input]')
        print('prev_hash:\t', list(inputs)[0].prev_hash.hex())
        print('prev_index:\t', list(inputs)[0].prev_index)
        print('amount:\t\t', list(inputs)[0].amount)

        txid = lx(list(inputs)[0].prev_hash.hex())
        vout = list(inputs)[0].prev_index
        txin = CMutableTxIn(COutPoint(txid, vout))

        print('[output]')
        print('address:\t', list(outputs)[0].address)
        print('amount:\t\t', list(outputs)[0].amount)

        #--------------------------------- Generate Hash ---------------------------------
        '''
        pub_main_addr_0 = list(outputs)[0].address
        print(b2x(decode(pub_main_addr)))
        print(b2x(decode(pub_main_addr))[2:-8])
        print('6F'+b2x(decode(pub_main_addr))[2:-8])
        print(Hash(bytes.fromhex('6F'+b2x(decode(pub_main_addr))[2:-8])).hex())
        print(Hash(bytes.fromhex('6F'+b2x(decode(pub_main_addr))[2:-8])).hex()[:8])
        print('6F'+b2x(decode(pub_main_addr))[2:-8] + Hash(bytes.fromhex('6F'+b2x(decode(pub_main_addr))[2:-8])).hex()[:8])
        pub_testnet_addr_0 = encode(bytes.fromhex('6F'+b2x(decode(pub_main_addr_0))[2:-8] + Hash(bytes.fromhex('6F'+b2x(decode(pub_main_addr_0))[2:-8])).hex()[:8]))
        print(pub_testnet_addr_0)
        '''
        txout1 = CMutableTxOut(list(outputs)[0].amount, CBitcoinAddress(list(outputs)[0].address).to_scriptPubKey())

        print('address:\t', list(outputs)[1].address)
        print('amount:\t\t', list(outputs)[1].amount)
        '''
        pub_main_addr_1 = list(outputs)[1].address
        pub_testnet_addr_1 = encode(bytes.fromhex('6F'+b2x(decode(pub_main_addr_1))[2:-8] + Hash(bytes.fromhex('6F'+b2x(decode(pub_main_addr_1))[2:-8])).hex()[:8]))
        print(pub_testnet_addr_1)
        '''
        txout2 = CMutableTxOut(list(outputs)[1].amount, CBitcoinAddress(list(outputs)[1].address).to_scriptPubKey())
        tmp_tx = CMutableTransaction([txin], [txout1] + [txout2])
        txin_scriptPubKey = CScript([OP_DUP, OP_HASH160, Hash160(decode(master_key)), OP_EQUALVERIFY, OP_CHECKSIG])
        sighash = SignatureHash(txin_scriptPubKey, tmp_tx, 0, SIGHASH_ALL)
        print('Hash:\t\t', b2x(sighash))
        #--------------------------------- Generate Hash Done ---------------------------------

        '''
        if self.is_testnet:
            signed_tx = btc.sign_tx(self.client, "Testnet", inputs, outputs, tx_details, prevtxs)
        else:
            signed_tx = btc.sign_tx(self.client, "Bitcoin", inputs, outputs, tx_details, prevtxs)
        '''
        signatures = Coolwallet.sign_tx_hash(self.client, b2x(sighash), list(inputs)[0].amount, list(outputs)[0].amount, list(outputs)[0].address)

        print('--------------------------------- CoolwalletClient sign_tx done ---------------------------------')
        
        for psbt_in in tx.inputs:
            for pubkey, sig in zip(psbt_in.hd_keypaths.keys(), signatures):
                fp = psbt_in.hd_keypaths[pubkey][0]
                keypath = psbt_in.hd_keypaths[pubkey][1:]
                if fp == master_fp:
                    psbt_in.partial_sigs[pubkey] = sig + b'\x01'
                break
            #signatures.remove(sig)
        
        return {'psbt':tx.serialize()}

    def sign_message(self, message, keypath):
        raise NotImplementedError('The HardwareWalletClient base class does not implement this method')

    def display_address(self, keypath, p2sh_p2wpkh, bech32):
        raise NotImplementedError('The HardwareWalletClient base class does not implement this method')

    def setup_device(self, hwdName, acc_id):
        Coolwallet.setup_device(self.client, hwdName, acc_id)

    def wipe_device(self):
        #back to nohost
        pass

    def close(self):
        self.client.close()
        print('close HTTP connet')

def enumerate(password=None):
    results = []
    #for dev in enumerate_devices():
    path = CwClient.get_ip()[0]

    d_data = {}

    d_data['type'] = 'coolwallet'
    d_data['path'] = path

    hstCred = bytes(range(32))
    hdw_name = 'ikv' + ' ' * (32 - len('ikv'))
    account_id = '00000000'

    try:
        client = CoolwalletClient(d_data['path'], password)
        client.setup_device(hdw_name, account_id)
        master_xpub = client.get_pubkey_at_path('m/0h')['xpub']
        print('master_xpub:', master_xpub)
        d_data['fingerprint'] = get_xpub_fingerprint_hex(master_xpub)
        client.close()
    except Exception as e:
        d_data['error'] = "Could not open client or get fingerprint information: " + str(e)

    results.append(d_data)
    return results
