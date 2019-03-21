# This file is part of the Coolwallet project.
# Coolwallet Client

from .CwAPI import cwse_apdu_command
from .tools.base58 import encode

import sys
import os
import json
import hashlib
import hmac
from Crypto.Cipher import AES

key_path = os.path.join(os.path.dirname(__file__), "tools/key.bin")
ip_path = os.path.join(os.path.dirname(__file__), "tools/ip.config")

def Readkey():
    try:
        fr = open(key_path, "rb")
    except Exception as e:
        print(e)
        sys.exit()
    else:
        fr.seek(0, 0)
        data = fr.readline(1 + 6 + 16)
        #print(data.hex()[:2])           # id
        #print(data.hex()[2:2+12])       # otp
        #print(data.hex()[2+12:2+12+32]) #login chlng
        fr.close()
        return data

def analysisReData(data):
    if not data:
        print('Transport Failed')
        #return False
        sys.exit()
    if data[:2] == '66':
        print('error:', data)
        sys.exit()
    elif data[-6:-4] == '90':
        tmp = data[:-7].split(' ')
        result = ''
        for i in range(len(tmp)):
            result += tmp[i]
        return result
    else:
        print('IDK', data)
        sys.exit()

def se_info(conn):
    ret = analysisReData(conn.se_get_mode_state())
    mode = ret[:2]
    if mode == '00':
        print('[INIT]')
        return mode
    elif mode == '01':
        print('[PERSO]')
        return mode
    elif mode == '02':
        print('[NORMAL]')
        return mode
    elif mode == '03':
        print('[AUTH]')
        return mode
    elif mode == '04':
        print('[LOCK]')
        return mode
    elif mode == '05':
        print('[ERROR]')
        return mode
    elif mode == '06':
        print('[NOHOST]')
        return mode
    elif mode == '07':
        print('[DISCONN]')
        return mode
    #conn.se_get_fw_version()
    #conn.se_get_unique_id()
    #conn.se_get_mod_err()
    #conn.se_get_basic_info()

def BindReg(conn, hstCred, hstDesc):
    print('========BindReg========')
    # if mode not NOHOST(06), exit
    if not se_info(conn) == '06':
        print('MODE should be [NOHOST]')
        return None 

    print('[se_bind_reg_init]')
    firstHost = '01'
    # hstHash = sha256(hstCred||hstDesc)
    sha256 = hashlib.sha256()
    sha256.update(hstCred)
    sha256.update(hstDesc)
    hstHash = sha256.digest()
    ret = conn.se_bind_reg_init(firstHost, hstCred.hex(), hstDesc.hex(), hstHash.hex())
    ret = analysisReData(ret)
    brHandle = ret[:8]
    otp = input('otp:')
    otpbyte = ''.join([r'%x' % ord(c) for c in otp]) # str to ascii hex str

    print('[se_bind_reg_chlng]')
    ret = conn.se_bind_reg_chlng(brHandle)
    # will failed try do while:
    if not ret:
        ret = conn.se_bind_reg_chlng(brHandle)
    #'''
    chlng = analysisReData(ret)

    print('[se_bind_reg_finish]')
    # otpKey = SHA256(hstCred||OTP)
    sha256 = hashlib.sha256()
    sha256.update(hstCred)
    sha256.update(bytes.fromhex(otpbyte)) # 6 byte
    otpKey = sha256.digest()

    # regResp = AES256(otpKey, chlng)
    cryptor = AES.new(otpKey, AES.MODE_ECB)
    regResp = cryptor.encrypt(bytes.fromhex(chlng))
    ret = conn.se_bind_reg_finish(brHandle, regResp.hex())
    ret = analysisReData(ret)
    hstID = ret[:2]
    print('HostID:', hstID)
    if ret[2:] == '00':
        print('Confirmed')
    elif ret[2:] == '01':
        print('Not Confirmed')
        return None

    # save otp key for login
    try:
        fw = open(key_path, "wb")
    except Exception as e:
        print(e)
        sys.exit()
    else:
        fw.write(bytes.fromhex(hstID))   # firstHost 1 byte
        fw.write(bytes.fromhex(otpbyte)) # otp 6 bytes
        print('write key')
        fw.close()
    print('========BindReg Done========')

def BindLogin(conn, hstCred):
    print('\n========BindLogin========')
    # if mode not DISCONN(07), exit
    if not se_info(conn) == '07':
        print('MODE should be [DISCONN]')
        return None

    data = Readkey()
    hstID = data[:1]
    otp = data[1:6+1]

    print('[se_bind_login_chlng]')
    ret = conn.se_bind_login_chlng(hstID.hex())
    login_chlng = analysisReData(ret)

    # save login_chlng
    try:
        fw = open(key_path, "wb")
    except Exception as e:
        print(e)
        sys.exit()
    else:
        fw.write(hstID)                      # firstHost 1 byte
        fw.write(otp)                        # otp 6 bytes
        fw.write(bytes.fromhex(login_chlng)) # login_chlng 16 bytes
        fw.close()
        print('write login chlng')

    print('[se_bind_login]')
    # otpKey = sha256(hstCred||otp)
    sha256 = hashlib.sha256()
    sha256.update(hstCred)
    sha256.update(otp)
    otpKey = sha256.digest()
    # resp = aes-ebc(chlng, otpKey)
    cryptor = AES.new(otpKey, AES.MODE_ECB)
    login_resp = cryptor.encrypt(bytes.fromhex(login_chlng))
    ret = conn.se_bind_login(hstID.hex(), login_resp.hex())
    result = analysisReData(ret)
    print('========BindLogin Done========')

    # if the mode is PERSO, set the perso data then enter normal mode
    data = bytes(4) # \x00\x00\x00\x00
    if se_info(conn) == '01':
        PersoSet(conn, data, hstCred, otp, bytes.fromhex(login_chlng), 'MAC')
    else:
        #print('========BindLogin Done========')
        pass

def Bind_session_key(hostCred, Regotp, loginChlng, mtrl):
    ## otpKey = sha256(hstCred||otp)
    sha256 = hashlib.sha256()
    sha256.update(hostCred)
    sha256.update(Regotp)
    otpKey = sha256.digest()
    ## sessKey = sha256(loginChlng||otpKey||mtrl)
    sha256 = hashlib.sha256()
    sha256.update(loginChlng)
    sha256.update(otpKey)
    sha256.update(mtrl.encode('utf-8')) # srt'' -> b''
    return sha256.digest() # sessKey

def Bind_session_mac(data, hostCred, Regotp, loginChlng):
    ## bind_smack = bind_session_key()
    bind_smack = Bind_session_key(hostCred, Regotp, loginChlng, 'MAC')
    ## mac = hmac_sha256(bind_smack, data)
    hmac_sha256 = hmac.new(bind_smack, data, hashlib.sha256)
    return hmac_sha256.digest() #mac

def PersoSet(conn, data, hostCred, Regotp, loginChlng, mtrl):
    print('\n========PersoSet========')

    print('[se_perso_set_data]')
    #bind_session_key(hostCred, Regotp, loginChlng, mtrl, OUT sessKey)
    sessKey = Bind_session_key(hostCred, Regotp, loginChlng, mtrl)
    #bind_session_mac(data, hostCred, Regotp, loginChlng, OUT mac)
    mac = Bind_session_mac(data, hostCred, Regotp, loginChlng)
    ret = conn.se_perso_set_data('00', data.hex(), mac.hex())
    result = analysisReData(ret)

    print('[se_perso_confirm]')
    ret = conn.se_perso_confirm()
    result = analysisReData(ret)
    se_info(conn)
    print('========PersoSet Done========')

def BindLogout(conn):
    print('\n========BindLogout========')
    # if mode is 01 or 02 or 04
    mode = se_info(conn)
    if mode == '01' or mode == '02' or mode == '04':
        analysisReData(conn.se_bind_logout())
    se_info(conn)
    print('========BindLogout Done========')

def InitWallet(conn, hwdName, hostCred):
    print('\n========InitWallet========')
    mode = se_info(conn)
    # check mode
    if mode == '02' or mode == '03':
        pass
    else:
        print('MODE should be [NORMAL] or [AUTH]')
        return False
    # check HDW status
    status = hdw_query_wallet_info(conn)
    if status != '00': 
        print('HDW status should be [INACTIVE]')
        return False 
    if len(hwdName) != 32:
        print('hwdName len should be 32, hwdName:', len(hwdName))
        return False

    mkseed = bytes([1, 27, 124, 79, 142, 112, 183, 181,
                    239, 250, 203, 131, 208, 233, 130, 229, 
                    84, 96, 88, 50, 185, 0, 69, 100,
                    28, 230, 79, 15, 69, 226, 233, 1,
                    180, 185, 15, 190, 149, 167, 15, 38, 
                    161, 70, 247, 221, 47, 205, 137, 80, 
                    115, 224, 4, 79, 97, 126, 241, 64, 
                    138, 37, 191, 172, 228, 60, 25, 108])

    data = Readkey()
    Regotp = data[1:1+6]
    loginChlng = data[1+6:1+6+16]

    # bind_session_key(hostCred, Regotp, loginChlng, mtrl, OUT sessKey)
    bind_senck = Bind_session_key(hostCred, Regotp, loginChlng, 'ENC')

    # emkseed = AES-ECB(bind_senck, mkseed)
    cryptor = AES.new(bind_senck, AES.MODE_ECB)
    emkseed = cryptor.encrypt(mkseed)

    # bind_session_mac(data, hostCred, Regotp, loginChlng, OUT mac)
    mac = Bind_session_mac(emkseed, hostCred, Regotp, loginChlng)

    nameAscii = ''.join([r'%x' % ord(c) for c in hwdName]) # str to ascii hex str
    ret = conn.se_hdw_init_wallet(nameAscii, emkseed.hex(), mac.hex())
    result = analysisReData(ret)
    #print('->bind_senck:', bind_senck.hex())
    #print('->emkseed:', emkseed.hex())
    #print('->mac:', mac.hex())
    print('========InitWallet Done========')
    return True

def hdw_query_wallet_info(conn):
    infoID = '00' # HDW status
    ret = conn.se_hdw_qry_wa_info(infoID)
    return analysisReData(ret)
'''
    infoID = '01' # HDW name
    ret = conn.se_hdw_qry_wa_info(infoID)
    infoID = '02' # HDW account pointer
    ret = conn.se_hdw_qry_wa_info(infoID)
    infoID = '03' # all HDW
    ret = conn.se_hdw_qry_wa_info(infoID)
'''

def hdw_create_account_test(conn):
    print('\n========Create account========')
    acc_id = '00000000'
    tmp = 'ikv_test'
    tmpAscii = ''.join([r'%x' % ord(c) for c in tmp])
    comp = 64 - len(tmpAscii)
    acc_name = tmpAscii + '0' * comp
    ret = conn.se_hdw_create_account(acc_id, acc_name)
    result = analysisReData(ret)
    print('========Create account Done========')

#path: BIP32 Derivation Path

def _hdw_query_xpub(conn, hostCred):
    acc_purpose = '2c000080' # 44
    acc_cointype = '01000080' # Bitcoin Testnet
    acc_val = '00000080'
    '''
    acc_purpose = path[0].to_bytes(4, 'little').hex()
    acc_cointype = path[0].to_bytes(4, 'little').hex() # Bitcoin Testnet
    acc_val = path[0].to_bytes(4, 'little').hex()
    print(acc_purpose, acc_cointype, acc_val) 
    '''
    #change = '00000000'
    #index = '00000000' # = acc_id
    ret = conn.se_hdw_qry_xpub(acc_purpose, acc_cointype, acc_val)

    rdata = bytes.fromhex(analysisReData(ret))
    pubk = rdata[:64] # 64 bytes
    chacode = rdata[64:64+32] # 32 bytes
    fingerprint = rdata[64+32:64+32+4] # 4 bytes
    rmac = rdata[64+32+4:64+32+4+32] # 32 bytes
    #print(pubk.hex(), '\n', chacode.hex(), '\n', fingerprint.hex(), '\n', rmac.hex())

    data = Readkey()
    Regotp = data[1:1+6]
    loginChlng = data[1+6:1+6+32]
    mac = Bind_session_mac(rdata[:64+32+4], hostCred, Regotp, loginChlng)
    #print('my MAC:', mac.hex())
    if rmac != mac:
        print('mac failed')
        print('return MAC:', rmac.hex())
        print('my MAC:', mac.hex())
        sys.exit()
    print('mac pass')

    version = '043587CF' #testnet public
    depth = '04' # 1 byte ?
    childnumber = '00' * 4  # 4 bytes
    pubkey = pubk[:32] # 32 bytes
    if int(pubk[32:].hex(), 16) % 2 == 0: # even
        pubkey_y = '02' # 1 byte
    else: # odd
        pubkey_y = '03' # 1 byte

    tmp = version + depth + fingerprint.hex() + childnumber + chacode.hex() + pubkey_y + pubkey.hex() # hex str
    sha256 = hashlib.sha256()
    sha256.update(bytes.fromhex(tmp))
    checksum_tmp = sha256.digest()

    sha256 = hashlib.sha256()
    sha256.update(checksum_tmp)
    checksum = sha256.digest()

    ex_pubkey = version + depth + fingerprint.hex() + childnumber + chacode.hex() + pubkey_y + pubkey.hex() + checksum[:4].hex() # hex str
    #print(ex_pubkey)
    print(encode(bytes.fromhex(ex_pubkey)))
    return {'xpub':encode(bytes.fromhex(ex_pubkey))}


def hdw_query_xpub(conn, path): # IN path : [2147483692, 2147483648, 2147483648]

    hstCred = bytes(range(32))
    acc_purpose = path[0].to_bytes(4, 'little').hex() #'2c000080'
    acc_cointype = '00000080'
    acc_val = '00000000'
    if len(path) > 1:
        acc_purpose = path[0].to_bytes(4, 'little').hex()
        acc_cointype = path[1].to_bytes(4, 'little').hex() # Bitcoin Testnet
        acc_val = path[2].to_bytes(4, 'little').hex()

    print(acc_purpose, acc_cointype, acc_val)
    ret = conn.se_hdw_qry_xpub(acc_purpose, acc_cointype, acc_val)

    rdata = bytes.fromhex(analysisReData(ret))
    pubk = rdata[:64] # 64 bytes
    chacode = rdata[64:64+32] # 32 bytes
    fingerprint = rdata[64+32:64+32+4] # 4 bytes
    rmac = rdata[64+32+4:64+32+4+32] # 32 bytes
    #print(pubk.hex(), '\n', chacode.hex(), '\n', fingerprint.hex(), '\n', rmac.hex())

    data = Readkey()
    Regotp = data[1:1+6]
    loginChlng = data[1+6:1+6+32]
    mac = Bind_session_mac(rdata[:64+32+4], hstCred, Regotp, loginChlng)
    #print('my MAC:', mac.hex())
    if rmac != mac:
        print('mac failed')
        print('return MAC:', rmac.hex())
        print('my MAC:', mac.hex())
        sys.exit()
    print('mac pass')

    version = '043587CF' #testnet public
    depth = '03' # 1 byte ?
    childnumber = '00' * 4  # 4 bytes
    pubkey = pubk[:32] # 32 bytes
    if int(pubk[32:].hex(), 16) % 2 == 0: # even
        pubkey_y = '02' # 1 byte
    else: # odd
        pubkey_y = '03' # 1 byte

    tmp = version + depth + fingerprint.hex() + childnumber + chacode.hex() + pubkey_y + pubkey.hex() # hex str
    sha256 = hashlib.sha256()
    sha256.update(bytes.fromhex(tmp))
    checksum_tmp = sha256.digest()
    
    sha256 = hashlib.sha256()
    sha256.update(checksum_tmp)
    checksum = sha256.digest()

    ex_pubkey = version + depth + fingerprint.hex() + childnumber + chacode.hex() + pubkey_y + pubkey.hex() + checksum[:4].hex() # hex str
    #print(ex_pubkey)
    #print(encode(bytes.fromhex(ex_pubkey)))
    return encode(bytes.fromhex(ex_pubkey))

#TxCopyHashGen(client, coin_name, index, inputs, outputs, details=None, prev_txes=None):
def TxCopyHashGen(client, coin_name, inputs, outputs, details=None, prev_txes=None):
    ADDR_TO_PUBKEY_HASH_BASE = 0 
    ADDR_TO_PUBKEY_HASH_ADDR = (ADDR_TO_PUBKEY_HASH_BASE + 0x01)
    
    ADDRESS_VERIFY_BASE = 0
    ADDRESS_VERIFY_DECODE = (ADDRESS_VERIFY_BASE + 0x01)
    ADDRESS_VERIFY_CHECKSUM = (ADDRESS_VERIFY_BASE + 0x02)

    BASE58_DECODE_BASE = 0
    NETWORK = 0x00

    def doubleSha256(data): # in bytes, out bytes
        sha256_1 = hashlib.sha256()
        sha256_2 = hashlib.sha256()
        sha256_1.update(data)
        sha256_2.update(sha256_1.digest())
        return sha256_2.digest()

    def base58Decode(strdata): # in string, out bytes
        byte_ret = decode(strdata)
        #TODO: check inputdata is str, or convers
        return BASE58_DECODE_BASE, byte_ret

    def addrVerify(addr):
        decode_ret = base58Decode(addr)
        if decode_ret[0] != BASE58_DECODE_BASE or decode_ret[1][:1] != NETWORK:
            return ADDRESS_VERIFY_DECODE

        ret_hash = doubleSha256(decode_ret[1][:21]) # sz = 21
        if decode_ret[1][21:] == ret_hash[:4]: # Compares 4 bytes
            return ADDRESS_VERIFY_CHECKSUM
        else:
            return ADDRESS_VERIFY_BASE

    def addrToPubKeyHash(addr):
        buf = bytes(25)
        if addrVerify(addr) != ADDRESS_VERIFY_BASE:
            return ADDR_TO_PUBKEY_HASH_ADDR, buf

        pubKeyHash = base58Decode(addr)[1][1:21] # sz = 20 bytes
        return ADDR_TO_PUBKEY_HASH_BASE, pubKeyHash

    def scriptPubPayToHash(addr):
        #[25] {0x76,0xa9,0x14,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x88,0xac}
        scriptPub = bytes([118,169,20,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,136,172])
        ret = addrToPubKeyHash(addr)
        if ret[0] == ADDR_TO_PUBKEY_HASH_BASE:
            ret_scriptPub = scriptPub[:3] + ret[1] + scriptPub[23:]
            return  ret_scriptPub # sz = 25 bytes
        return scriptPub


    # version no, 4 byte
    hashdata += bytes.fromhex("%08d" % details.version)
    print(hashdata)
    # In-counter, 1 or 3 or 5 byte
    hashdata += bytes.fromhex("%02d" % len(inputs))
    print(hashdata)

    # List of inputs
    for vin in len(inputs):
        # prehash, 32 byte
        hashdata += inputs[vin].prev_hash
        print(hashdata)
        # index, 4 byte
        hashdata += bytes.fromhex("%02d" % inputs[vin].prev_index)
        print(hashdata)

        if (vin == index):
            # script len, 1 or 3 or 5 byte
            hashdata += bytes.fromhex("%02d" % len(inputs[vin].script_sig))
            print(hashdata)
            # script, (script len) byte
            hashdata += inputs[vin].script_sig
            print(hashdata)
        else:
            # script len, 1 or 3 or 5 byte
            hashdata += bytes.fromhex("00")
            print(hashdata)

        # sequence_no, 4 byte
        hashdata += bytes.fromhex("ffffffff")
        print(hashdata)
    
    # Out-counter, 1 or 3 or 5 byte
    hashdata += bytes.fromhex("%02d" % len(outputs))
    print(hashdata)

    # List of outputs
    for vout in len(outputs):
        # value, 8 byte
        hashdata += outputs[vout].amount
        print(hashdata)
        # script len, 1 or 3 or 5 byte
        #hashdata += len(outputs[vout].address) 
        hashdata += bytes.fromhex("25") # 25 in hex 
        print(hashdata)
        # script, (script len) byte
        hashdata += scriptPubPayToHash(outputs[vout].address)
        print(hashdata)

    # sequence_no, 4 byte
    hashdata += bytes.fromhex("%08d" % details.lock_time)
    print(hashdata)
    
    # signature type: All, 4 byte
    hashdata += bytes.fromhex("00000001")
    print(hashdata)

    #TODO: doublesha256
    ret = doubleSha256(hashdata)
    print(ret)

def hdw_prep_trx_sign(conn, hostCred):
    print('\n========se_hdw_prep_trx_sign========')
    inputID = '00'
    KeyChain = '00'
    acc_id = '00000000'
    key_id = '00000000'
    balance = '0000000000000000'
    trxHash = TxCopyHashGen()

    data = Readkey()
    Regotp = data[1:1+6]
    loginChlng = data[1+6:1+6+16]

    mac = Bind_session_mac(acc_id, hostCred, Regotp, loginChlng)

    ret = conn.se_hdw_prep_trx_sign(inputID, KeyChain, acc_id, key_id, balance, trxHash, mac)
    result = analysisReData(ret)
    print('========se_hdw_prep_trx_sign Done========')

def trx_begin(conn, hostCred):
    print('\n========hdw_transaction_sign_begin========')
    trxAmount = 'FF' * 8
    outAddr = '035cc8348e75f8baa139a6863b9aae0f8973c98190a4ec010a800b9bd4b14b9d0e00'

    data = Readkey()
    Regotp = data[1:1+6]
    loginChlng = data[1+6:1+6+16]
    # bind_session_key(hostCred, Regotp, loginChlng, mtrl, OUT sessKey)
    bind_senck = Bind_session_key(hostCred, Regotp, loginChlng, 'ENC')

    # emkseed = AES-ECB(bind_senck, mkseed)
    cryptor = AES.new(bind_senck, AES.MODE_ECB)
    enc_outAddr = cryptor.encrypt(outAddr)

    ret = conn.se_trx_begin(trxAmount, enc_outAddr)
    result = analysisReData(ret)
    print('========se_trx_begin Done========')

def trx_sign(conn):
    print('\n========se_trx_sign========')
    inputID = '00'
    ret = conn.se_trx_sign(inputID)
    result = analysisReData(ret)
    print('========se_trx_sign Done========')

def trx_finish(conn):
    print('\n========se_trx_finish========')
    ret = conn.se_trx_finish()
    result = analysisReData(ret)
    print('========se_trx_finish Done========')


class CoolwalletClient:
    """Coolwallet Client, a connection to a Trezor device.
    """
    def __init__(self):
        with open(ip_path) as f:
            data = json.load(f)
            f.close()
        self.ip = data['ip']
        self.port = data['port']
        self.hstCred = bytes(range(32))
        self.hstDesc = bytes(range(32, 96))

        self.conn = cwse_apdu_command(self.ip, self.port)
        self.init_device(self.conn, self.hstCred, self.hstDesc)
        #return conn

    def init_device(self, conn, hstCred, hstDesc):
        BindReg(conn, hstCred, hstDesc)
        BindLogout(conn)
        BindLogin(conn, hstCred)

    def setup_device(self, hwdName):
        #init wallet
        if InitWallet(self.conn, hwdName, self.hstCred):
        #create account
            hdw_create_account_test(self.conn)
        else: 
            print('pass setup_device')

    def get_pubkey_at_path(self, path):
        return hdw_query_xpub(self.conn, path)

    def sign_tx(self, tx):
        TxCopyHashGen()
        pass

    def sign_message(self, message, keypath):
        raise NotImplementedError('The HardwareWalletClient base class does not '
            'implement this method')

    def display_address(self, keypath, p2sh_p2wpkh, bech32):
        pass

    def setup_device(self, hwdName):
        #init wallet
        if InitWallet(self.conn, hwdName, self.hstCred):
        #create account
            hdw_create_account_test(self.conn)
        else: 
            print('pass setup_device')

    def wipe_device(self):
        #back to nohost
        pass

    def close(self):
        self.conn.close()


class _cw_client:

    def __init__(self):
        #connet
        with open(ip_path) as f:
            data = json.load(f)
        print(data['ip'])
        print(data['port'])
        self.conn = cwse_apdu_command(data['ip'], data['port'])
        #self.conn = cwse_apdu_command('192.168.0.100', 9527)
        f.close()
        #self.conn = conn
        #se_info(conn)
        self.hstCred = bytes(range(32))
        hstDesc = bytes(range(32, 96))
        BindReg(self.conn, self.hstCred, hstDesc)
        BindLogout(self.conn)
        BindLogin(self.conn, self.hstCred)
        #BindLogout(self.conn)

    def get_pubkey_at_path(self, path=''):
        _hdw_query_xpub(self.conn, self.hstCred)
        pass

    def sign_tx(self, tx):
        pass

    def sign_message(self, message, keypath):
        raise NotImplementedError('The HardwareWalletClient base class does not '
            'implement this method')

    def display_address(self, keypath, p2sh_p2wpkh, bech32):
        pass

    def setup_device(self, hwdName):
        #init wallet
        if InitWallet(self.conn, hwdName, self.hstCred):
        #create account
            hdw_create_account_test(self.conn)
        else: 
            print('pass setup_device')

    def wipe_device(self):
        #back to nohost
        pass

    def close(self):
        self.conn.close()
        print('close HTTP connet')

    def test(self):
        se_info(self.conn)

