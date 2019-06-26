#Coolwallet Client

from ..hwwclient import HardwareWalletClient
from ..base58 import get_xpub_fingerprint, decode, encode, to_address, xpub_main_2_test, get_xpub_fingerprint_hex
from ..serializations import ser_uint256
from .. import bech32

from trezorlib import protobuf, tools, btc
from trezorlib import messages as proto

from CoolwalletLib.CwClient import CoolwalletClient as Coolwallet
from CoolwalletLib.CwClient import get_ip

from bitcoin import SelectParams
from bitcoin.core import b2x, lx, COIN, COutPoint, CMutableTxOut, CMutableTxIn, CMutableTransaction, Hash160, x
from bitcoin.core.script import CScript, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG, SignatureHash, SIGHASH_ALL
from bitcoin.wallet import CBitcoinAddress

import os
import sys
import json
import hashlib
import hmac
from Crypto.Cipher import AES

def generate_p2pkh(Params, pubkey, inputs, inIndex, outputs, details):
    # 1. SelectParams
    SelectParams(Params)
    # 2. make trx input scriptPubKey
    txin_scriptPubKey = CScript([OP_DUP, OP_HASH160, Hash160(pubkey), OP_EQUALVERIFY, OP_CHECKSIG])
    
    current_input = 0
    current_output = 0
    txout = [None] * len(outputs)
    txin_all = []
    txout_all = []

    # 3. make inputs data 
    while current_input < len(inputs):
        txid = lx(list(inputs)[current_input].prev_hash.hex())
        vout = list(inputs)[current_input].prev_index
        txin = CMutableTxIn(COutPoint(txid, vout), nSequence = list(inputs)[current_input].sequence)
        txin_all.append(txin)
        current_input += 1

    # 4. make outputs data
    while current_output < len(outputs):
        out_address = list(outputs)[current_output].address
        out_amount = list(outputs)[current_output].amount
        txout[current_output] = CMutableTxOut(out_amount, CBitcoinAddress(out_address).to_scriptPubKey())
        txout_all.append(txout[current_output])
        current_output += 1

    # 5. make Trx data
    tmp_trx = CMutableTransaction(txin_all, txout_all, nLockTime = details.lock_time, nVersion = details.version)
    # 6. generate Trx Hash
    sighash = SignatureHash(txin_scriptPubKey, tmp_trx, inIndex, SIGHASH_ALL)
    return sighash

class CoolwalletClient(HardwareWalletClient):

    def __init__(self, path, password=''):
        super(CoolwalletClient, self).__init__(path, password)
        self.simulator = False
        self.client = Coolwallet()

        # if it wasn't able to find a client, throw an error
        if not self.client:
            raise IOError("no Device")
        self.password = password
        self.type = 'Coolwallet'

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
        # Get this devices master key fingerprint        
        master_key = Coolwallet.get_pubkey_at_path(self.client, [2147483648])
        master_fp = get_xpub_fingerprint(master_key)

        # 1. Parser PSBT Trx
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
                #print('SPEND_ADDRESS')
            elif psbt_in.witness_utxo:
                # Check if the output is p2sh
                if psbt_in.witness_utxo.is_p2sh():
                    txinputtype.script_type = proto.InputScriptType.SPENDP2SHWITNESS
                    print('SPEND_P2SH_WITNESS')
                else:
                    txinputtype.script_type = proto.InputScriptType.SPENDWITNESS
                    print('SPEND_WITNESS')

            # Check for 1 key
            if len(psbt_in.hd_keypaths) == 1:
                # Is this key ours
                pubkey = list(psbt_in.hd_keypaths.keys())[0]
                fp = psbt_in.hd_keypaths[pubkey][0]
                keypath = list(psbt_in.hd_keypaths[pubkey][1:])
                if fp == master_fp:
                    # Set the keypath
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

        # 2. Generate Trx Hash
        input_amount = [] 
        input_txhash = []
        signatures = []
        keypath = []

        current_input = 0
        while current_input < len(inputs):
            keypath.append(list(inputs)[current_input].address_n)
            utrx_pubkey = Coolwallet.get_pubkey_at_path(self.client, keypath[current_input])
            pubkey = decode(utrx_pubkey)[-37:-4] # public key data

            if self.is_testnet:
                sighash_params = 'testnet'
                raise ValueError('CW not supported TestNet')
            else:
                sighash_params = 'mainnet'
                
            # SPENDADDRESS unspent input
            if psbt_in.non_witness_utxo:              
                sighash = generate_p2pkh(sighash_params, pubkey, inputs, current_input, outputs, tx_details)
                input_amount.append(list(inputs)[current_input].amount)
                input_txhash.append(b2x(sighash))                     

            elif psbt_in.witness_utxo:
                if psbt_in.witness_utxo.is_p2sh():
                    # SPENDP2SHWITNESS unspent input
                    print("SPENDP2SHWITNESS not implement....")
                    raise NotImplementedError
                    
                else:
                    # SPENDWITNESS unspent input
                    print("SPENDWITNESS not implement....")
                    raise NotImplementedError
                    
            current_input += 1
        #End while

        # 3. Sign Trx
        signatures = Coolwallet.sign_tx(self.client, len(inputs), input_txhash, input_amount, keypath, list(outputs)[0].amount, list(outputs)[0].address)

        # 4. Serialize PSBT Trx
        sig_n = 0
        for psbt_in in tx.inputs:
            for pubkey, sig in zip(psbt_in.hd_keypaths.keys(), signatures):
                fp = psbt_in.hd_keypaths[pubkey][0]
                keypath = psbt_in.hd_keypaths[pubkey][1:]
                if fp == master_fp:
                    psbt_in.partial_sigs[pubkey] = signatures[sig_n] + b'\x01'
                
                sig_n += 1
                signatures.remove(sig)
                break
        
        return {'psbt':tx.serialize()}

    def sign_message(self, message, keypath):
        raise NotImplementedError('The HardwareWalletClient base class does not implement this method')

    def display_address(self, keypath, p2sh_p2wpkh, bech32):
        raise NotImplementedError('The HardwareWalletClient base class does not implement this method')

    def setup_device(self):
        Coolwallet.setup_device(self.client)

    def setup_device_dev(self, HDW_name, Acc_id, Acc_name):
        Coolwallet.setup_device_develop(self.client, HDW_name, Acc_id, Acc_name)
                
    def wipe_device(self):
        #back to nohost
        pass

    def close(self):
        self.client.close()

def enumerate(password=None):
    results = []
    #for dev in enumerate_devices():
    path = get_ip()[0]

    d_data = {}
    d_data['type'] = 'coolwallet'
    d_data['path'] = path

    name = 'ikv-wallet-mainnet'
    wallet_name = name + ' ' * (32 - len(name))
    
    acc_id = 0
    acc_id_format = '{:0>8d}'.format(acc_id)
    acc_name = 'ikv-account-0'

    try:
        client = CoolwalletClient(d_data['path'], password)
        #client.setup_device_dev(wallet_name, acc_id_format, acc_name)
        client.setup_device()
        master_xpub = client.get_pubkey_at_path('m/0h')['xpub']
        d_data['fingerprint'] = get_xpub_fingerprint_hex(master_xpub)
        client.close()
    except Exception as e:
        d_data['error'] = "Could not open client or get fingerprint information: " + str(e)

    results.append(d_data)
    return results
