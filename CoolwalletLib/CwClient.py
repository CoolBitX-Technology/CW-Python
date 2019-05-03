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
        '''
        print(data.hex()[:2])           # id
        print(data.hex()[2:2+12])       # otp
        print(data.hex()[2+12:2+12+32]) #login chlng
        '''
        fr.close()
        return data

def analysisReData(data):
    if not data:
        print('Transport Failed')
        #return False
        sys.exit()

    if data[:2] == '66':
        if data[-3:-1] == '24':
            print('ERR_INTER_MODULE')
            return 24
        print('error:', data)
        sys.exit()
        #return None
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
    print('mode: ', end='')
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
    print('\n========BindReg========')

    # if mode is not NOHOST(06) or DISCONN(07), exit
    mode = se_info(conn)
    if mode == '06' or mode == '07':
        pass
    else:
        print('MODE should be [NOHOST] or [DISCONN]')
        print('====================================')
        return None 

    print('[se_bind_reg_init]')
    firstHost = '00' #if is first device set 01
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
        print('========================')
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

def BindLogout(conn):
    print('\n========BindLogout========')
    # if mode is 01 or 02 or 04
    mode = se_info(conn)
    if mode == '01' or mode == '02' or mode == '04':
        analysisReData(conn.se_bind_logout())
    se_info(conn)
    print('========BindLogout Done========')

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
    status = hdw_query_wallet_info(conn, '00')
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

    print('========InitWallet Done========')
    return True

def hdw_query_wallet_info(infoID):
    ret = conn.se_hdw_qry_wa_info(infoID)
    return analysisReData(ret)

def hdw_create_account_test(conn, acc_id):
    print('\n========Create account========')
    tmp = 'ikv_test'
    tmpAscii = ''.join([r'%x' % ord(c) for c in tmp])
    comp = 64 - len(tmpAscii)
    acc_name = tmpAscii + '0' * comp
    ret = conn.se_hdw_create_account(acc_id, acc_name)
    result = analysisReData(ret)
    print('========Create account Done========')

def hdw_query_account_info(conn, info_id, balance_format, acc_id):
    print('\n========query account========')
    ret = conn.se_hdw_qry_acc_info(info_id, balance_format, acc_id)
    result = analysisReData(ret)
    print('========query account Done========')

def hdw_set_account_balance(conn, info_id, acc_id, hostCred, balance):
    print('\n========Set account balance========')
    
    #balance = '00' * 3 + '00' + '0B' + 'EB' + 'C2' + '00' # 200,000,000 = 2BTC = 0xBEBC200
    set_balance = '0' * (16 - len(format(balance, '02X'))) + format(balance, '02X')
    

    data = Readkey()
    Regotp = data[1:1+6]
    loginChlng = data[1+6:1+6+16]

    mac = Bind_session_mac(bytes.fromhex(set_balance), hostCred, Regotp, loginChlng)

    print('set account balance: ', set_balance)
    print('MAC:', mac.hex())
    ret = conn.se_hdw_set_acc_info(info_id, acc_id, set_balance, mac.hex())
    result = analysisReData(ret)
    print('========Set account balance Done========')


def hdw_query_xpub(conn, path): # IN path : [2147483692, 2147483648, 2147483648]
    hstCred = bytes(range(32))

    #------------------------ parser path ------------------------
    acc_purpose = '2c000080' #BIP43
    acc_cointype = '01000080' # Bitcoin Testnet
    acc_val = '00000080'
    if len(path) > 1:
        acc_purpose = path[0].to_bytes(4, 'little').hex()
        acc_cointype = path[1].to_bytes(4, 'little').hex() 
        acc_val = path[2].to_bytes(4, 'little').hex()
    print(acc_purpose, acc_cointype, acc_val)

    #------------------------ get pubkey ------------------------
    ret = conn.se_hdw_qry_xpub(acc_purpose, acc_cointype, acc_val)

    #------------------------ check mac ------------------------
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

    if rmac != mac:
        print('hdw_query_xpub --> mac failed')
        print('hdw_query_xpub --> return MAC:', rmac.hex())
        print('hdw_query_xpub --> my MAC:', mac.hex())
        sys.exit()
    print('hdw_query_xpub --> mac pass')

    #------------------------ made ex_pubkey by hand ------------------------
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


def hdw_prep_trx_sign(conn, hostCred, acc_id, inputID, balance, trxHash):
    print('\n========[se_hdw_prep_trx_sign]========')
    se_info(conn)
    KeyChain = '00'
    key_id = '00000000'
    print('Transaction input amount: ', balance)
    print('Transaction Hash: ', trxHash)

    data = Readkey()
    Regotp = data[1:1+6]
    loginChlng = data[1+6:1+6+16]

    mac_value = bytes.fromhex(acc_id) + bytes.fromhex(key_id) + bytes.fromhex(balance) + bytes.fromhex(trxHash)
    mac = Bind_session_mac(mac_value, hostCred, Regotp, loginChlng)
    ret = conn.se_hdw_prep_trx_sign(inputID, KeyChain, acc_id, key_id, balance, trxHash, mac.hex())
    result = analysisReData(ret)
    if result == 24 :
        conn.se_get_mod_err()
    print('========[se_hdw_prep_trx_sign Done]========')


def trx_begin(conn, hostCred, trxAmount, outAddr):
    print('\n========[se_trx_begin Done]========')

    data = Readkey()
    Regotp = data[1:1+6]
    loginChlng = data[1+6:1+6+16]
    bind_senck = Bind_session_key(hostCred, Regotp, loginChlng, 'ENC')
    cryptor = AES.new(bind_senck, AES.MODE_ECB)

    outAddr_len = 48
    if len(outAddr) % outAddr_len != 0:
        padding_length = outAddr_len - (len(outAddr) % outAddr_len)
        outAddr += b'\x00' * padding_length

    enc_outAddr = cryptor.encrypt(outAddr)

    print('Transaction amoun: ', trxAmount)
    print('Encrypted output address: ', enc_outAddr.hex())
    ret = conn.se_trx_begin(trxAmount, enc_outAddr.hex())
    result = analysisReData(ret)
    print('========[se_trx_begin Done]========')

def trx_sign(conn, hostCred):
    print('\n========[se_trx_sign]========')
    inputID = '00'
    ret = conn.se_trx_sign(inputID)
    result = analysisReData(ret)

    if len(result) < (64+32) * 2:
        print("trx_sign Failed")
        sys.exit()

    sig = result[:64*2]
    print('sig: ', sig)
    sig_mac = result[64*2:]

    data = Readkey()
    Regotp = data[1:1+6]
    loginChlng = data[1+6:1+6+16]

    mac = Bind_session_mac(bytes.fromhex(sig), hostCred, Regotp, loginChlng)

    if sig_mac != mac.hex():
        print('hdw_query_xpub --> mac failed')
        print('hdw_query_xpub --> sig MAC:', sig_mac)
        print('hdw_query_xpub --> my MAC:', mac.hex())
        sys.exit()
    print('hdw_query_xpub --> mac pass')
    print('========[se_trx_sign Done]========')
    return sig

def trx_finish(conn):
    print('\n========[se_trx_finish]========')
    ret = conn.se_trx_finish()
    result = analysisReData(ret)
    print('========[se_trx_finish Done]========')

def get_ip():
    with open(ip_path) as f:
        data = json.load(f)
        f.close()
    ip = data['ip']
    port = data['port']
    print(ip, port)
    return ip, port

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
        #BindReg(conn, hstCred, hstDesc)
        BindLogout(conn)
        BindLogin(conn, hstCred)

    def get_pubkey_at_path(self, path):
        return hdw_query_xpub(self.conn, path)

    def sign_tx(client, coin_name, inputs, outputs, details=None, prev_txes=None):
        print("-------CoolwalletClient.sign_tx-------")
        #TxCopyHashGen(client, coin_name, inputs, outputs, details, prev_txes)

    def sign_tx_hash(self, txhash, input_amount, trx_amount, trx_addr):
        print("-------CoolwalletClient.sign_tx_hash-------")
        
        acc_id = '00000000'
        inputID = '00'

        
        
        self.conn.change_apdu_CLA(81)
        '''
        se_info(self.conn)
        self.conn.se_trx_status()
        '''

        trx_finish(self.conn)

        inputbalance =  '0' * (16 - len(format(input_amount, '02x'))) + format(input_amount, '02x')
        hdw_prep_trx_sign(self.conn, self.hstCred, acc_id, inputID, inputbalance, txhash)

        trx_amount_form = '0' * (16 - len(format(trx_amount, '02x'))) + format(trx_amount, '02x')
        print('trx_amount: ', trx_amount_form)
        print('trx_addr: ', trx_addr)

        trx_begin(self.conn, self.hstCred, trx_amount_form, decode(trx_addr))
        #self.conn.se_trx_get_ctxinfo(inputID)

        enter = input('\r\n[press the buttom on the card, then input enter]\r\n')
        self.conn.se_trx_status()
        self.conn.se_trx_status()
        se_info(self.conn)
        
        sig = trx_sign(self.conn, self.hstCred)

        trx_finish(self.conn)

        print("-------CoolwalletClient.sign_tx_hash Done-------")
        return sig

    def sign_message(self, message, keypath):
        raise NotImplementedError('The HardwareWalletClient base class does not '
            'implement this method')

    def display_address(self, keypath, p2sh_p2wpkh, bech32):
        pass

    def setup_device(self, hwdName, account_id):

        #init wallet
        if InitWallet(self.conn, hwdName, self.hstCred):
        #create account
            hdw_create_account_test(self.conn, account_id)
        else: 
            print('pass setup_device')

        #--- set wallet account blance, and query it
        hdw_set_account_balance(self.conn, '01', acc_id, self.hstCred, 400000000)
        self.conn.se_hdw_qry_wa_info('03')
        hdw_query_account_info(self.conn, '01', '01', acc_id)
        
        self.conn.se_hdw_next_trx_addr('00', acc_id)
        hdw_query_account_info(self.conn, '02', '00', acc_id)

    def wipe_device(self):
        #back to nohost
        pass

    def close(self):
        self.conn.close()








#back up 
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