# This file is part of the Coolwallet project.
# Coolwallet Client

from .CwAPI import cwse_apdu_command
from .tools.base58 import encode, decode

import sys
import os
import json
import hashlib
import hmac
from Crypto.Cipher import AES
import logging

key_path = os.path.join(os.path.dirname(__file__), "tools/key.bin")
ip_path = os.path.join(os.path.dirname(__file__), "tools/ip.config")

Client_log = logging.getLogger( __name__ )
Client_log.setLevel(logging.WARNING)

def Readkey():
    try:
        fr = open(key_path, "rb")
        fr.seek(0, 0)
        data = fr.readline(1 + 6 + 16)
        Client_log.debug('[key] id: %s', data.hex()[:2])
        Client_log.debug('[key] otp: %s', data.hex()[2:2+12])
        Client_log.debug('[key] login chlng: %s', data.hex()[2+12:2+12+32])
        fr.close()
        return data
    except Exception as e:
        raise ValueError(e)
        
def analysisReData(data):
    if not data:
        raise ValueError('Transport Failed')

    if data[:2] == '66':
        if data[-3:-1] == '24':
            Client_log.error('ERR_INTER_MODULE Failed')
            return 24
        raise ValueError('[Error code]'+ data)

    elif data[-6:-4] == '90':
        tmp = data[:-7].split(' ')
        result = ''
        for i in range(len(tmp)):
            result += tmp[i]
        return result

    else:
        raise ValueError('[IDK]'+ data)

def getModeState(conn):
    ret = analysisReData(conn.se_get_mode_state())
    mode = ret[:2]

    if mode == '00':
        mode_w = 'INIT'
    elif mode == '01':
        mode_w = 'PERSO'
    elif mode == '02':
        mode_w = 'NORMAL'
    elif mode == '03':
        mode_w = 'AUTH'
    elif mode == '04':
        mode_w = 'LOCK'
    elif mode == '05':
        mode_w = 'ERROR'
    elif mode == '06':
        mode_w = 'NOHOST'
    elif mode == '07':
        mode_w = 'DISCONN'

    Client_log.debug('[mode]: %s', mode_w)
    return mode

def BindInfo(conn, hostID='00'):
    Client_log.info('[BindInfo]')
    ret = analysisReData(conn.se_bind_reg_info(hostID))
    bind_state = ret[:2]
    bind_desc = ret[2:]

    Client_log.debug('[bind_state]: %s', bind_state)
    Client_log.debug('[bind_desc]: %s', bind_desc)

    return bind_state

def BindReg(conn, fisrt_reg, hstCred, hstDesc):
    Client_log.info('[BindReg]')
    # if mode is not NOHOST(06) or DISCONN(07), exit
    mode = getModeState(conn)
    if mode == '06' or mode == '07':
        pass
    else:
        Client_log.error('[BindReg] mode not supported')
        raise ValueError('[BindReg] mode not supported')

    Client_log.info('[1][se_bind_reg_init]')
     # if is first device set 01 else set 00
    if fisrt_reg:
        firstHost = '01'
        Client_log.warning('Can not be the fisrt_reg')
        #raise False
    else:
        firstHost = '00'

    # hstHash = sha256(hstCred||hstDesc)
    sha256 = hashlib.sha256()
    sha256.update(hstCred)
    sha256.update(hstDesc)
    hstHash = sha256.digest()
    ret = analysisReData(conn.se_bind_reg_init(firstHost, hstCred.hex(), hstDesc.hex(), hstHash.hex()))
    brHandle = ret[:8]

    otp = input('otp:')
    if len(otp) != 6:
        raise ValueError('wrong otp length')

    otpbyte = ''.join([r'%x' % ord(c) for c in otp]) # str to ascii hex str
    #[issue] will failed, retry
    conn.se_get_mode_state()

    Client_log.info('[2][se_bind_reg_chlng]')
    chlng = analysisReData(conn.se_bind_reg_chlng(brHandle))

    Client_log.info('[3][se_bind_reg_finish]')
    # otpKey = SHA256(hstCred||OTP)
    sha256 = hashlib.sha256()
    sha256.update(hstCred)
    sha256.update(bytes.fromhex(otpbyte)) # 6 byte
    otpKey = sha256.digest()

    # regResp = AES256(otpKey, chlng)
    cryptor = AES.new(otpKey, AES.MODE_ECB)
    regResp = cryptor.encrypt(bytes.fromhex(chlng))
     # PINRESP is only for register first device
    if fisrt_reg:
        pin = '00' * 16
        ret = conn.se_bind_reg_finish(brHandle, regResp.hex(), pin)
    else:
        ret = conn.se_bind_reg_finish(brHandle, regResp.hex(), '00' * 16)

    ret = analysisReData(ret)
    hstID = ret[:2]
    Client_log.debug('[hstID]: %s', hstID)

    # save otp key for login
    try:
        fw = open(key_path, "wb")
        fw.write(bytes.fromhex(hstID))   # firstHost 1 byte
        fw.write(bytes.fromhex(otpbyte)) # otp 6 bytes
        fw.close()
    except Exception as e:
        raise ValueError(e)

    if ret[2:] == '00':
        Client_log.info('Confirmed')
    elif ret[2:] == '01':
        raise ValueError('Done register but not confirmed, plz approve the host at first host')

    return None

def BindLogin(conn, hstCred):
    Client_log.info('[BindLogin]')
    # if mode not DISCONN(07), exit
    if not getModeState(conn) == '07':
        raise ValueError('[BindLogin] mode not supported')

    # get login info
    data = Readkey()
    hstID = data[:1]
    otp = data[1:6+1]

    Client_log.info('[1][se_bind_login_chlng]')
    login_chlng = analysisReData(conn.se_bind_login_chlng(hstID.hex()))

    # save login_chlng
    try:
        fw = open(key_path, "wb")
        fw.write(hstID)                      # firstHost 1 byte
        fw.write(otp)                        # otp 6 bytes
        fw.write(bytes.fromhex(login_chlng)) # login_chlng 16 bytes
        fw.close()
    except Exception as e:
        raise ValueError(e)

    Client_log.info('[2][se_bind_login]')
    # otpKey = sha256(hstCred||otp)
    sha256 = hashlib.sha256()
    sha256.update(hstCred)
    sha256.update(otp)
    otpKey = sha256.digest()
    # resp = AES-ECB(chlng, otpKey)
    cryptor = AES.new(otpKey, AES.MODE_ECB)
    login_resp = cryptor.encrypt(bytes.fromhex(login_chlng))
    analysisReData(conn.se_bind_login(hstID.hex(), login_resp.hex()))

    # if the mode is PERSO, set the perso data then enter normal mode
    if getModeState(conn) == '01':
        Client_log.info('[3][set perso data]')
        data = bytes(4) # \x00\x00\x00\x00
        PersoSet(conn, data, hstCred, otp, bytes.fromhex(login_chlng), 'MAC')

    return None

def BindLogout(conn):
    Client_log.info('[BindLogout]')
    # if mode is PERSO(01) or NORMAL(02) or LOCK(04)
    mode = getModeState(conn)
    if mode == '01' or mode == '02' or mode == '04':
        analysisReData(conn.se_bind_logout())

    return None

def bind_session_key(hostCred, Regotp, loginChlng, mtrl):
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

def bind_session_mac(data, hostCred, Regotp, loginChlng):
    ## bind_smack = bind_session_key()
    bind_smack = bind_session_key(hostCred, Regotp, loginChlng, 'MAC')
    ## mac = hmac_sha256(bind_smack, data)
    hmac_sha256 = hmac.new(bind_smack, data, hashlib.sha256)
    return hmac_sha256.digest() #mac

def PersoSet(conn, data, hostCred, Regotp, loginChlng, mtrl):
    Client_log.info('[PersoSet]')

    Client_log.info('[1][se_perso_set_data]')
    PDID = '00'
    sessKey = bind_session_key(hostCred, Regotp, loginChlng, mtrl)
    mac = bind_session_mac(data, hostCred, Regotp, loginChlng)
    analysisReData(conn.se_perso_set_data(PDID, data.hex(), mac.hex()))

    Client_log.info('[2][se_perso_confirm]')
    analysisReData(conn.se_perso_confirm())

def InitHDWallet(conn, HDWName, hostCred, seed=''):
    Client_log.info('[InitHDWallet]')

    # check mode
    mode = getModeState(conn)
    if mode == '02' or mode == '03':
        pass
    else:
        raise ValueError('[InitHDWallet] mode not supported')

    # check HDW status is [INACTIVE]
    Client_log.info('[1][se_hdw_qry_wa_info]')  
    wallet_status = analysisReData(conn.se_hdw_qry_wa_info('00'))
    Client_log.debug('[wallet_status]: %s', wallet_status) 

    if wallet_status != '00': 
        Client_log.wrong('[InitHDWallet] wallet have already created') 
        return False
        
    if len(HDWName) != 32:
        raise ValueError('[InitHDWallet] HDWName len should be 32, len(HDWName):' + len(HDWName))

    default_seed = "2b1d2cff928c21e40932d67113d746bb82b3d67c0ccd757d1aa1049f4523818f45b2620e1cb40ff2bcef30ff34df0e92d900c95701923a1260c778821e033f29"
    
    if seed == '':
        seed = default_seed

    seed = bytes.fromhex(seed)

    # get login info
    data = Readkey()
    Regotp = data[1:1+6]
    loginChlng = data[1+6:1+6+16]

    # init wallet with seed
    Client_log.info('[2][se_hdw_init_wallet]') 
    bind_senck = bind_session_key(hostCred, Regotp, loginChlng, 'ENC')
    cryptor = AES.new(bind_senck, AES.MODE_ECB)
    emkseed = cryptor.encrypt(seed)
    mac = bind_session_mac(emkseed, hostCred, Regotp, loginChlng)

    HDWNameAscii = ''.join([r'%x' % ord(c) for c in HDWName]) # str to ascii hex str
    analysisReData(conn.se_hdw_init_wallet(HDWNameAscii, emkseed.hex(), mac.hex()))

    # check HDW status is not [INACTIVE]
    Client_log.info('[3][se_hdw_qry_wa_info]')  
    wallet_status = analysisReData(conn.se_hdw_qry_wa_info('00'))
    Client_log.debug('[wallet_status]: %s', wallet_status) 

    if wallet_status != '00':
        return True
    else:
        raise ValueError('[InitHDWallet] init failed')

def HDWQryAccKeyinfo(conn, accountID, keyChainID, KeyID):
    Client_log.info('[HDWQryAccKeyinfo]')

    ret = analysisReData(conn.se_hdw_qry_acc_keyinfo('00', keyChainID, accountID, KeyID))
    Client_log.info('Address(25 Byte): %s', ret[:25*2])

    ret = analysisReData(conn.se_hdw_qry_acc_keyinfo('01', keyChainID, accountID, KeyID))
    Client_log.info('Public key(64 Byte): %s', ret[:64*2])

    ret = analysisReData(conn.se_hdw_qry_acc_keyinfo('02', keyChainID, accountID, KeyID))
    Client_log.info('KeyChain public key(64 Byte): %s', ret[:64*2])
    Client_log.info('KeyChain code(32 Byte): %s', ret[64*2:64*2+32*2])

def HDWCreatAccount(conn, acc_id, acc_name):
    Client_log.info('[HDWCreatAccount]')

    acc_name = ''.join([r'%x' % ord(c) for c in acc_name]) # str to ascii hex str
    padding = 64 - len(acc_name)
    acc_name = acc_name + '0' * padding                    # padding to 64 
    analysisReData(conn.se_hdw_create_account(acc_id, acc_name))

def HDWSetAccBalance(conn, info_id, acc_id, hostCred, balance):
    Client_log.info('[HDWSetAccBalance]')

    # padding
    set_balance = '0' * (16 - len(format(balance, '02X'))) + format(balance, '02X')

    # get login info
    data = Readkey()
    Regotp = data[1:1+6]
    loginChlng = data[1+6:1+6+16]

    mac = bind_session_mac(bytes.fromhex(set_balance), hostCred, Regotp, loginChlng)
    analysisReData(conn.se_hdw_set_acc_info(info_id, acc_id, set_balance, mac.hex()))

def HDWNextTrxAddress(conn, keyChain_id, acc_id):
    Client_log.info('[HDWNextTrxAddress]')

    result = analysisReData(conn.se_hdw_next_trx_addr(keyChain_id, acc_id))
    Client_log.debug('[Path]: account ID: %s', acc_id, \
                    'key chain ID: %s', keyChain_id, \
                    'key ID: %s', result[:8], \
                    '\nAddress: %s', result[8:8+50])

def HDWQryXpub(conn, path, hstCred): 
    # IN path like : [2147483692, 2147483648, 2147483648]
    Client_log.info('[HDWQryXpub]')
    Client_log.debug('[Path]: %s', path)

    Client_log.info('[1] parser path')
    #------------------------ parser path ------------------------
    # m / purpose' / coin_type' / account' / change / address_index
    purpose = '2c000080'    # purpose' set to 44 following the BIP43
    cointype = ''   
    account = ''
    change = ''
    address_i = ''

    if len(path) == 1:
        purpose =   path[0].to_bytes(4, 'little').hex()
        childnumber = path[0].to_bytes(4, 'big').hex()
    elif len(path) == 2:
        purpose =   path[0].to_bytes(4, 'little').hex()
        cointype =  path[1].to_bytes(4, 'little').hex() 
        childnumber = path[1].to_bytes(4, 'big').hex()        
    elif len(path) == 3:
        purpose =   path[0].to_bytes(4, 'little').hex()
        cointype =  path[1].to_bytes(4, 'little').hex() 
        account =   path[2].to_bytes(4, 'little').hex()
        childnumber = path[2].to_bytes(4, 'big').hex()        
    elif len(path) == 4:
        purpose =   path[0].to_bytes(4, 'little').hex()
        cointype =  path[1].to_bytes(4, 'little').hex() 
        account =   path[2].to_bytes(4, 'little').hex()
        change =    path[3].to_bytes(4, 'little').hex()
        childnumber = path[3].to_bytes(4, 'big').hex()        
    elif len(path) == 5:
        purpose =   path[0].to_bytes(4, 'little').hex()
        cointype =  path[1].to_bytes(4, 'little').hex() 
        account =   path[2].to_bytes(4, 'little').hex()
        change =    path[3].to_bytes(4, 'little').hex()
        address_i = path[4].to_bytes(4, 'little').hex()
        childnumber = path[4].to_bytes(4, 'big').hex()        
    else: 
        raise ValueError('[HDWQryXpub]: error at path')

    Client_log.debug('[Parser Path](m/purpose/coin_type/account/change/address): m/%s/%s/%s/%s/%s', purpose, cointype, account, change, address_i)

    Client_log.info('[2] get pubkey')
    #------------------------ get pubkey ------------------------
    ret = conn.se_hdw_qry_xpub(purpose, cointype, account, change, address_i)

    rdata       = bytes.fromhex(analysisReData(ret))
    pubk        = rdata[:64]                # 64 bytes: public key
    chacode     = rdata[64:64+32]           # 32 bytes: chain code
    fingerprint = rdata[64+32:64+32+4]      # 4 bytes: the fingerprint of the parent's key
    rmac        = rdata[64+32+4:64+32+4+32] # 32 bytes: retuen MAC

    # get login info
    data = Readkey()
    Regotp = data[1:1+6]
    loginChlng = data[1+6:1+6+32]

    Client_log.info('[3] check mac')
    #------------------------ check mac ------------------------
    mac = bind_session_mac(rdata[:64+32+4], hstCred, Regotp, loginChlng)
    if rmac != mac:
        raise ValueError('[HDWQryXpub]: MAC failed')

    Client_log.info('[4] make ex_pubkey')
    #------------------------ make ex_pubkey ------------------------
    version = '0488B21E'                # 4 bytes: version bytes (mainnet public)
    # CW not support testnet version
    ''' 
    if testnet:
        version = '043587CF'            # 4 bytes: version bytes (testnet public)
    ''' 
    depth = "{:0>2d}".format(len(path)) # 1 byte: depth

    #childnumber = '80000000'           # 4 bytes: child number (hardened addresses)
    
    pubkey_x = pubk[:32]                # 32 bytes: public key x coordinate
    if int(pubk[32:].hex(), 16) % 2 == 0:
        prefix = '02'                   # 1 byte: public key y coordinate is even
    else: 
        prefix = '03'                   # 1 byte: public key y coordinate is odd

    tmp = version \
        + depth \
        + fingerprint.hex() \
        + childnumber \
        + chacode.hex() \
        + prefix \
        + pubkey_x.hex() 

    # double sha256
    sha256 = hashlib.sha256()
    sha256.update(bytes.fromhex(tmp))
    checksum_tmp = sha256.digest()
    sha256 = hashlib.sha256()
    sha256.update(checksum_tmp)
    checksum = sha256.digest()

    ex_pubkey = version \
              + depth \
              + fingerprint.hex() \
              + childnumber \
              + chacode.hex() \
              + prefix \
              + pubkey_x.hex() \
              + checksum[:4].hex()

    return encode(bytes.fromhex(ex_pubkey))

def HDWPrepTrxSign(conn, hostCred, acc_id, keychain_id, key_id, inputID, balance, trxHash):
    Client_log.info('[HDWPrepTrxSign]')

    # check mode
    mode = getModeState(conn)
    if mode == '02' or mode == '03':
        pass
    else:
        raise ValueError('[HDWPrepTrxSign] mode not supported')

    # get login info
    data = Readkey()
    Regotp = data[1:1+6]
    loginChlng = data[1+6:1+6+16]

    mac_value = bytes.fromhex(acc_id) + bytes.fromhex(key_id) + bytes.fromhex(balance) + bytes.fromhex(trxHash)
    mac = bind_session_mac(mac_value, hostCred, Regotp, loginChlng)
    ret = analysisReData(conn.se_hdw_prep_trx_sign(inputID, keychain_id, acc_id, key_id, balance, trxHash, mac.hex()))

    if ret == 24 :
        Client_log.error('[HDWPrepTrxSign]Internal module error')
        err = conn.se_get_mod_err()
        raise ValueError('[Error code]'+ err)

def TrxBegin(conn, hostCred, trxAmount, outAddr):
    Client_log.info('[TrxBegin]')

    # get login info
    data = Readkey()
    Regotp = data[1:1+6]
    loginChlng = data[1+6:1+6+16]

    bind_senck = bind_session_key(hostCred, Regotp, loginChlng, 'ENC')
    cryptor = AES.new(bind_senck, AES.MODE_ECB)

    #padding
    outAddr_len = 48
    if len(outAddr) % outAddr_len != 0:
        padding_length = outAddr_len - (len(outAddr) % outAddr_len)
        outAddr += b'\x00' * padding_length

    enc_outAddr = cryptor.encrypt(outAddr)
    analysisReData(conn.se_trx_begin(trxAmount, enc_outAddr.hex()))

def TrxSign(conn, inputID, hostCred):
    Client_log.info('[TrxSign]')

    result = analysisReData(conn.se_trx_sign(inputID))
    if len(result) < (64+32) * 2:        
        raise ValueError('[TrxSign] CMD Failed, result:'+ result)
    tmp_sig = result[:64*2]
    tmp_sig_mac = result[64*2:]

    # get login info
    data = Readkey()
    Regotp = data[1:1+6]
    loginChlng = data[1+6:1+6+16]

    mac = bind_session_mac(bytes.fromhex(tmp_sig), hostCred, Regotp, loginChlng)
    if tmp_sig_mac != mac.hex():
        raise ValueError('[TrxSign]: MAC failed')

    r = tmp_sig[:64]
    s = tmp_sig[64:]

    # DER encoding
    if int(r[:2], 16) > 0x7f:
        r = '00' + r
    if int(s[:2], 16) > 0x7f:
        s = '00' + s

    sig = '30' \
            + hex(2 + len(bytes.fromhex(r)) \
            + 2 \
            + len(bytes.fromhex(s)))[2:] \
            + '02' \
            + hex(len(bytes.fromhex(r)))[2:] \
            + r \
            + '02' \
            + hex(len(bytes.fromhex(s)))[2:] \
            + s

    return sig

def TrxFinish(conn):
    Client_log.info('[TrxFinish]')
    conn.se_trx_finish()

def get_ip():
    try:
        with open(ip_path) as f:
            data = json.load(f)
            f.close()
        ip = data['ip']
        port = data['port']
        Client_log.info('IP: %s:%s', ip, port)
        return ip, port
    except Exception as e:
        raise ValueError(e)

class CoolwalletClient:
    """Coolwallet Client, a connection to a Trezor device.
    """
    def __init__(self):
        
        with open(ip_path) as f:
            data = json.load(f)
            f.close()
        self.ip = data['ip']
        self.port = data['port']

        cred = 'ikv_hstCred' + ' ' * (32 - len('ikv_hstCred'))
        desc = 'ikv_hstDesc' + ' ' * (64 - len('ikv_hstDesc'))
        self.hstCred = bytes.fromhex(''.join([r'%x' % ord(c) for c in cred]))
        self.hstDesc = bytes.fromhex(''.join([r'%x' % ord(c) for c in desc]))

        self.conn = cwse_apdu_command(self.ip, self.port)
        self.init_device(self.conn)
        #self.init_device_develop(self.conn)
        
    def init_device(self, conn):
        # 1. check CW not the first host
        host_id = '00'
        state = BindInfo(conn, host_id)
        if state != '02': # Confirmed state
            raise ValueError('[init_device] plz register and approve from the first host')

        # 2. register new host
        host_id = '01'
        state = BindInfo(conn, host_id)
        if state == '00':   # Empty state -> registered
            # fisrt_reg must be False
            BindReg(conn, False, self.hstCred, self.hstDesc)
            BindLogout(conn)
            BindLogin(conn, self.hstCred)

        elif state == '01': # Registered state -> approve
            raise ValueError('[init_device] not supported approve function, plz approve from the first host')

        else:               # Confirmed state -> skip
            BindLogout(conn)
            BindLogin(conn, self.hstCred)

    def init_device_develop(self, conn):
        print('--------------------------------- [CW] init_device_develop ---------------------------------')
        state = BindInfo(conn, '00')
        if state == '00':
            BindReg(conn, True, self.hstCred, self.hstDesc)
            BindLogout(conn)
            BindLogin(conn, self.hstCred)
        elif state == '01':
            raise False
        else:
            BindLogout(conn)
            BindLogin(conn, self.hstCred)
        print('--------------------------------- [CW] init_device_develop Done ---------------------------------')

    def get_pubkey_at_path(self, path):
        return HDWQryXpub(self.conn, path, self.hstCred)

    def sign_tx(self, input_count, input_txhash, input_amount, input_path, trx_amount, trx_addr):
        
        # padding to 8 bytes
        trx_amount_form = '0' * (16 - len(format(trx_amount, '02x'))) + format(trx_amount, '02x')
        signatures = [None] * input_count

        self.conn.change_apdu_CLA('81')
        # 1. Trx Finish
        TrxFinish(self.conn)

        # 2. Prep Trx Sign
        #------------------ prep_n times (input_amount, input_txhash)-----------------------
        prep_n = 0
        while prep_n < input_count:
            input_path_n = input_path[prep_n]
            acc_id      = input_path_n[2].to_bytes(4, 'little').hex()[:-2] + '00' # 4 bytes
            keychain_id = input_path_n[3].to_bytes(1, 'little').hex()             # 1 byte
            key_id      = input_path_n[4].to_bytes(4, 'little').hex()             # 4 byte: HEX 
            
            Client_log.debug('Prep data : %s ', prep_n)
            Client_log.debug('Prep data [key path](ACC/KCID/KID): %s/%s/%s', acc_id, keychain_id, key_id)
            Client_log.debug('Prep data [input_amount]: %s', input_amount[prep_n])
            Client_log.debug('Prep data [input_txhash]: %s', input_txhash[prep_n])

            #------------------ check key point ------------------
            if keychain_id == '00':     # external
                KCID = '02'
            elif keychain_id == '01':   # internal
                KCID = '03'

            key_point = analysisReData(self.conn.se_hdw_qry_acc_info(KCID, '00', acc_id))
            key_point = int(key_point[:2], 16)
            Client_log.debug('[keychain_id]:%s, [key_point]:%s', keychain_id, key_point)
            Client_log.debug('Trx input key path [keyid]:%s', input_path_n[4])
                 
            if key_point < (input_path_n[4]):
                # GetNextPath to path point 
                keydiff = input_path_n[4] - key_point              
                for x in range(0, keydiff+1):
                    HDWNextTrxAddress(self.conn, keychain_id, acc_id)
            #--------------------------------------------------------
                
            # padding to 8 bytes
            inputbalance =  '0' * (16 - len(format(input_amount[prep_n], '02x'))) + format(input_amount[prep_n], '02x')
            HDWPrepTrxSign(self.conn, self.hstCred, acc_id, keychain_id, key_id,"{:0>2d}".format(prep_n), inputbalance, input_txhash[prep_n])
            prep_n += 1
        #-----------------------------------------------------------------------------------

        # 3. Trx Begin
        Client_log.debug('Output data [trx_amount]: %s ', trx_amount_form)
        Client_log.debug('Output data [trx_addr]: %s ', trx_addr)
        TrxBegin(self.conn, self.hstCred, trx_amount_form, decode(trx_addr))

        input('\r\n[press the buttom on the card, then press enter to continue...]\r\n')
        self.conn.se_trx_status()
        self.conn.se_trx_status()

        # 4. Trx Sign
        sign_n = 0
        while sign_n < input_count:
            sig = TrxSign(self.conn, "{:0>2d}".format(sign_n), self.hstCred)
            signatures[sign_n] = bytes.fromhex(sig)
            Client_log.debug('sign_n %s', sign_n)
            Client_log.debug('[signatures]: %s', signatures[sign_n].hex())
            sign_n += 1

        # 5. Trx Finish
        TrxFinish(self.conn)

        return signatures

    def sign_message(self, message, keypath):
        raise NotImplementedError('The HardwareWalletClient base class does not '
            'implement this method')

    def display_address(self, keypath, p2sh_p2wpkh, bech32):
        raise NotImplementedError('The HardwareWalletClient base class does not '
            'implement this method')

    def setup_device(self):
        Client_log.info('[setup_device]')  
        # user should creat HDWallet first at the APP, check HDW status is not [INACTIVE]
        status = analysisReData(self.conn.se_hdw_qry_wa_info('00'))
        Client_log.debug('[status]: %s', status) 
        if status == '00': 
            raise ValueError('[setup_device] HDW status should be [ACTIVE]')

    def setup_device_develop(self, HDW_name, account_id, account_name):
        print("--------------------------------- [CW] CoolwalletClient setup_device_develop ---------------------------------") 
        
        # creat HDWallet and creat account
        if InitHDWallet(self.conn, HDW_name, self.hstCred):
            HDWCreatAccount(self.conn, account_id, account_name)
        
        # set wallet account blance, and query it
        account_balance = 2221600
        HDWSetAccBalance(self.conn, '01', account_id, self.hstCred, account_balance)
        
        Client_log.info('[se_hdw_qry_wa_info]')
        self.conn.se_hdw_qry_acc_info('00', '00', account_id)
        self.conn.se_hdw_qry_acc_info('01', '01', account_id)
        self.conn.se_hdw_qry_acc_info('02', '00', account_id)
        self.conn.se_hdw_qry_acc_info('03', '00', account_id)

        '''
        keyChainID = '01'
        KeyID = '14000000'
        HDWQryAccKeyinfo(self.conn, account_id, keyChainID, KeyID)
        '''
        print("--------------------------------- [CW] CoolwalletClient setup_device_develop done ---------------------------------")        

    def wipe_device(self):
        #back to nohost
        pass

    def close(self):
        self.conn.close()
