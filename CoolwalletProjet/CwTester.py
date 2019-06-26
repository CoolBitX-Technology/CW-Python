#! /usr/bin/env python3

from CoolwalletLib.CwHttpTransport import CoolwalletClient
from CoolwalletLib.CwAPI import cwse_apdu_command
#from CoolwalletLib.CwClient import cw_client
from CoolwalletLib.CwClient import CoolwalletClient as Client
from CoolwalletLib.tools.base58 import encode

import sys
import random
import string
import json
import hashlib
import hmac
from Crypto.Cipher import AES

def Bind_session_key(hostCred, Regotp, loginChlng, mtrl):
    ## otpKey = sha256(hstCred||otp)
    sha256 = hashlib.sha256()
    sha256.update(hstCred)
    sha256.update(Regotp)
    otpKey = sha256.digest()
    print('->otpkey:', otpKey.hex())
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

def Readkey():
    print('[read key]')
    try:
        fr = open("CoolwalletLib/tools/key.bin", "rb")
    except Exception as e:
        print(e)
        sys.exit()
    else:
        fr.seek(0, 0)
        data = fr.readline(1 + 6 + 16)
        #print(data.hex()[:2]) # id
        #print(data.hex()[2:2+12]) # otp
        #print(data.hex()[2+12:2+12+32]) #login chlng
        fr.close()
        return data.hex()

def test_readkey():
    print('\n[read file]')

    try:
        fr = open("CoolwalletLib/tools/key.bin", "rb")
    except Exception as e:
        print(e)
        sys.exit()
    else:
        hstID = fr.readline(1)
        print('hstID:', hstID.hex())
        otp = fr.readline(6)
        print('otp:', otp.hex())
        login_chlng = fr.readline(16)
        print('login_chlng:', login_chlng.hex())
        fr.close()

def analysisReData(data):
    if not data:
        print('Transport Failed')
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

def getModeState(conn):
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

def BindRegTest(conn, hstCred, hstDesc):
    print('\n========BindRegTest========')
    # if mode is not NOHOST(06) or DISCONN(07), exit
    mode = getModeState(conn)
    if mode == '06' or mode == '07':
        pass
    else:
        print('MODE should be [NOHOST] or [DISCONN]')
        print('====================================')
        return None 
    
    print('\n[se_bind_reg_init]')
    firstHost = '01'
    sha256 = hashlib.sha256()
    sha256.update(hstCred)
    sha256.update(hstDesc)
    hstHash = sha256.digest()
    ret = conn.se_bind_reg_init(firstHost, hstCred.hex(), hstDesc.hex(), hstHash.hex())
    ret = analysisReData(ret)
    brHandle = ret[:8]
    otp = input('otp:')
    otpbyte = ''.join([r'%x' % ord(c) for c in otp]) # str to ascii hex str
    #print('brHandle:', brHandle)
    #print('otpbyte:', otpbyte)

    print('\n[se_bind_reg_chlng]')
    ret = conn.se_bind_reg_chlng(brHandle)
    if not ret:
        ret = conn.se_bind_reg_chlng(brHandle)
    chlng = analysisReData(ret)
    print('chlng:', chlng)
    
    print('\n[se_bind_reg_finish]')
    # otpKey = SHA256(hstCred||OTP)
    sha256 = hashlib.sha256()
    sha256.update(hstCred)
    sha256.update(bytes.fromhex(otpbyte)) # 6 byte
    otpKey = sha256.hexdigest() # str
    print('otpKey:', otpKey)
    
    #regResp = AES256(otpKey, chlng)
    cryptor = AES.new(bytes.fromhex(otpKey), AES.MODE_ECB)
    regResp = cryptor.encrypt(bytes.fromhex(chlng))
    print('regResp:', regResp.hex())
    ret = conn.se_bind_reg_finish(brHandle, regResp.hex())
    ret = analysisReData(ret)
    hstID = ret[:2]
    print('HostID:', hstID)
    if ret[2:] == '00':
        print('Confirmation')
    elif ret[2:] == '01':
        print('Not Confirmation')

    # save otp key for login
    try:
        fw = open("key.bin", "wb") # wb/xb
    except Exception as e:
        print('key exist')
        sys.exit()
    else:
        fw.write(bytes.fromhex(hstID)) #firstHost 1 byte
        fw.write(bytes.fromhex(otpbyte)) # otp 6 bytes
        #fw.write(bytes.fromhex(chlng)) # challenge 16 bytes
        print('write key')
        fw.close()


def BindLoginTest(conn, hstCred):

    print('\n========BindLoginTest========')
    ret = conn.se_get_mode_state()
    mode = analysisReData(ret)
    # if mode != DISCONN
    if not mode[:2] == '07':
        print('MODE should be DISCONN(07)')
        return None

    # read key
    data = Readkey()
    hstID = bytes.fromhex(data[:2])
    print('hstID:', hstID.hex())
    otp = bytes.fromhex(data[2:2+12])
    print('otp:', otp, otp.hex())
    #loginChlng = bytes.fromhex(data[2+12:2+12+32])
    #print('loginChlng:', loginChlng.hex())

    #test_readkey() # test
    print('\n[se_bind_login_chlng]')
    ret = conn.se_bind_login_chlng(hstID.hex())
    login_chlng = analysisReData(ret)
    print('login_chlng:', login_chlng)

    # store login_chlng
    try:
        fw = open("key.bin", "wb")
    except Exception as e:
        print('key not exist')
        sys.exit()
    else:
        #fw.seek(1 + 6 + 16, 0)
        fw.write(hstID) # hostID 1 bytes
        fw.write(otp) # otp 6 bytes
        fw.write(bytes.fromhex(login_chlng)) # login_chlng 16 bytes
        fw.close()
        print('write login chlng')
    test_readkey() # test
    print('\n[se_bind_login]')
    print('hstCred:', hstCred)
    print('otp:', otp.hex())
    #otpKey = sha256(hstCred||otp)
    sha256 = hashlib.sha256()
    sha256.update(hstCred)
    sha256.update(otp)
    otpKey = sha256.hexdigest() # str
    print('otpKey:', otpKey)
    #resp = aes-ebc(chlng, otpKey)
    cryptor = AES.new(bytes.fromhex(otpKey), AES.MODE_ECB)
    login_resp = cryptor.encrypt(bytes.fromhex(login_chlng))
    print('login_resp:', login_resp.hex())
    ret = conn.se_bind_login(hstID.hex(), login_resp.hex())
    ret = analysisReData(ret)

    print('\n[se_get_mode_state]')
    ret = conn.se_get_mode_state()
    mode = analysisReData(ret)
    data = bytes(4) # bytes
    if mode[:2] == '01': # perso mode, set the perso data then enter normal mode
        PersoSet(conn, data, hstCred, otp, bytes.fromhex(login_chlng), 'MAC')
    else:
       pass

def BindLogout(conn):
    ret = conn.se_bind_logout()
    result = analysisReData(ret)

def BindBackToNoHost(conn): #error: 69 86
    pin_resp = '00' * 16
    pin_hash = '00' * 32
    ret = conn.se_bind_back_nohost(pin_resp, pin_hash)
    result = analysisReData(ret)

def PersoSet(conn, data, hostCred, Regotp, loginChlng, mtrl):
    print('\n========PersoSet========')

    #bind_session_key(hostCred, Regotp, loginChlng, mtrl, OUT sessKey)
    sessKey = Bind_session_key(hostCred, Regotp, loginChlng, mtrl)

    #bind_session_mac(data, hostCred, Regotp, loginChlng, OUT mac)
    mac = Bind_session_mac(data, hostCred, Regotp, loginChlng)

    ret = conn.se_perso_set_data('00', data.hex(), mac.hex())
    result = analysisReData(ret)
    ret = conn.se_perso_confirm()
    result = analysisReData(ret)
    ret = conn.se_get_mode_state()
    result = analysisReData(ret)

def InitWallet_test(conn, hwdName, hostCred):
    print('\n========InitWallet_test========')
    ret = conn.se_get_mode_state()
    mode = analysisReData(ret)
    # if mode != 02 or 03
    if mode[:2] != '02':
        print(mode[:2])
        print('MODE should be 02 or 03')
        sys.exit()

    if len(hwdName) != 32:
        print('hwdName len should be 32, hwdName:', len(hwdName))
        sys.exit()

    BIP39_Seed = "5390c201d64e9c303da7cd85a36a2a0d010a55904508415a02f08bef59fd51db81ba5d632817ad199da9bc77d11da485f0a20ae8f787da2e0cba61aab1306633"
    BIP39_Seed_byte = bytes.fromhex(BIP39_Seed)
    print(BIP39_Seed_byte)
    sys.exit()


    mkseed = bytes([120, 49, 137, 155, 199, 15, 221, 96,
                    109, 154, 230, 172, 68, 226, 82, 34,
                    225, 127, 216, 200, 239, 106, 4, 27, 
                    254, 231, 227, 216, 126, 153, 34, 193, 
                    237, 80, 208, 253, 161, 141, 208, 198, 
                    33, 185, 255, 75, 246, 22, 64, 92, 
                    14, 87, 208, 174, 231, 221, 251, 111,
                    186, 233, 77, 74, 149, 212, 157, 181])

    data = Readkey()
    Regotp = bytes.fromhex(data[2:2+12])
    print('<-otp:', Regotp, Regotp.hex())
    loginChlng = bytes.fromhex(data[2+12:2+12+32])
    print('<-loginChlng:', loginChlng.hex())

    # bind_session_key(hostCred, Regotp, loginChlng, mtrl, OUT sessKey)
    bind_senck = Bind_session_key(hostCred, Regotp, loginChlng, 'ENC')
    print('->bind_senck:', bind_senck.hex())
    # emkseed = AES-ECB(bind_senck, mkseed)
    cryptor = AES.new(bind_senck, AES.MODE_ECB)
    emkseed = cryptor.encrypt(mkseed)
    print('<-mkseed:', mkseed.hex())
    print('->emkseed:', emkseed.hex())

    # bind_session_mac(data, hostCred, Regotp, loginChlng, OUT mac)
    mac = Bind_session_mac(emkseed, hostCred, Regotp, loginChlng)
    print('->mac:', mac.hex())
    nameAscii = ''.join([r'%x' % ord(c) for c in hwdName]) # str to ascii hex str
    print('<-hwdName:', nameAscii)
    ret = conn.se_hdw_init_wallet(nameAscii, emkseed.hex(), mac.hex())
    result = analysisReData(ret)

def hdw_query_wallet_info(conn):
    infoID = '00' # status
    ret = conn.se_hdw_qry_wa_info(infoID)
    result = analysisReData(ret)

def hdw_create_account_test(conn):
    acc_id = '00000000'
    tmp = 'ikv_test'
    tmpAscii = ''.join([r'%x' % ord(c) for c in tmp])
    comp = 64 - len(tmpAscii)
    acc_name = tmpAscii + '0' * comp
    '''
    print(comp)
    print(acc_name, len(acc_name))
    '''
    #acc_name = '11' * 32
    ret = conn.se_hdw_create_account(acc_id, acc_name)
    result = analysisReData(ret)

def hdw_query_acc_info(conn):
    acc_id = '00000000'
    infoID = '05'
    balanceFormat = '00'
    ret = conn.se_hdw_qry_acc_info(infoID, balanceFormat, acc_id)

def hdw_query_xpub_test(conn, hostCred):
    # little endian
    acc_purpose = '2c000080' # 44
    acc_cointype = '01000080' # Bitcoin Testnet
    acc_val = '00000080'
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
    Regotp = bytes.fromhex(data[2:2+12])
    loginChlng = bytes.fromhex(data[2+12:2+12+32])
    mac = Bind_session_mac(rdata[:64+32+4], hostCred, Regotp, loginChlng)
    #print('my MAC:', mac.hex())
    if rmac != mac:
        print('mac failed')
        print('return MAC:', rmac.hex())
        print('my MAC:', mac.hex())
        sys.exit()

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
    print(ex_pubkey)
    #print(encode(bytes.fromhex(ex_pubkey)))
    return {'xpub':encode(bytes.fromhex(ex_pubkey))}


    

if __name__ == '__main__':
    T_CwHttpTransport = False
    T_CwAPI = True
    T_CwAPI_FUNC = False
    T_CwClient = False

    print('[CwTester]')
    with open('CoolwalletLib/tools/ip.config') as f:
        data = json.load(f)
        f.close()
    print('ip:', data['ip'], 'port', data['port'])

#CoolwalletLib.CwClient Test
    if T_CwClient:
        print('CwClient test')
        hwdName = 'abcdefghijklmnopqrstuvwxyz012345' #bytes(range(32))
        '''
        conn3 = cw_client()
        conn3.setup_device(hwdName)
        conn3.get_pubkey_at_path()
        conn3.close()
        '''
        conn5 = Client()
        #conn5.setup_device(hwdName)

        path = [2147483692, 2147483648, 2147483648]
        output = conn5.get_pubkey_at_path(path)
        print(output)
        conn5.close()

#CoolwalletLib.CwAPI Function test
    if T_CwAPI_FUNC:
        print('CwAPI Function test')
        conn4 = cwse_apdu_command(data['ip'], data['port']) 

        hstCred = bytes(range(32))
        hstDesc = bytes(range(32, 96))
        hwdName = 'abcdefghijklmnopqrstuvwxyz012345' #bytes(range(32))

        #test_readkey()

        se_info(conn4)

        BindRegTest(conn4, hstCred, hstDesc)
        BindLogout(conn4)
        BindLoginTest(conn4, hstCred)

        hdw_query_wallet_info(conn4)
        InitWallet_test(conn4, hwdName, hstCred)

        hdw_create_account_test(conn4)
        hdw_query_wallet_info(conn4)

        hdw_query_xpub_test(conn4, hstCred)

        #BindBackToNoHost(conn4)

#CoolwalletLib.CwAPI Test
    if T_CwAPI:
        print('[CoolwalletLib.CwAPI]')
        conn2 = cwse_apdu_command(data['ip'], data['port'])
        
        print('#SE Information')
        print('Test [se_get_mode_state]:', conn2.se_get_mode_state())
        print('Test [se_get_fw_version]:', conn2.se_get_fw_version())
        print('Test [se_get_unique_id]:', conn2.se_get_unique_id())
        print('Test [se_get_mod_err]:', conn2.se_get_mod_err())
        print('Test [se_get_basic_info]:', conn2.se_get_basic_info())
            
        print('\n#Host Binding')
        hostCred = '00' * 32 # 32 bytes
        hostDesc = '00' * 64
        HASH = '00' * 32
        BRHANDLE = '00' * 4
        REGRESP = '00' * 16
        PINRESP = '00' * 16
        HST_ID = '00'
        BINDRESP = '00' * 16
        HSTCRED = '00' * 32
        PINHASH = '00' * 32

        print('Test [se_bind_reg_init]:', conn2.se_bind_reg_init('00', hostCred, hostDesc, HASH))
        print('Test [se_bind_reg_chlng]:', conn2.se_bind_reg_chlng(BRHANDLE))
        print('Test [se_bind_reg_finish with PINRESP]:', conn2.se_bind_reg_finish(BRHANDLE, REGRESP, PINRESP))
        print('Test [se_bind_reg_finish]:', conn2.se_bind_reg_finish(BRHANDLE, REGRESP))
        
        print('Test [se_bind_reg_info]:', conn2.se_bind_reg_info(HST_ID))
        print('Test [se_bind_reg_approve]:', conn2.se_bind_reg_approve(HST_ID))
        print('Test [se_bind_reg_remove]:', conn2.se_bind_reg_remove(HST_ID))
        
        print('Test [se_bind_login_chlng]:', conn2.se_bind_login_chlng(HST_ID))
        print('Test [se_bind_login]:', conn2.se_bind_login(HST_ID, BINDRESP))
        print('Test [se_bind_logout]:', conn2.se_bind_logout())

        print('Test [se_bind_find_hst_id]:', conn2.se_bind_find_hst_id(HSTCRED))
        print('Test [se_bind_back_nohost]:', conn2.se_bind_back_nohost(PINRESP, PINHASH))

        print('\n#Personalization')
        PDID = '00'
        PERDATA = '00' *  4
        PDMAC = '00' * 32
        PINHASH = '00' * 32
        print('Test [se_perso_set_data]:', conn2.se_perso_set_data(PDID, PERDATA, PDMAC))
        print('Test [se_perso_get_data_hash]:', conn2.se_perso_get_data_hash(PDID))
        print('Test [se_perso_confirm]:', conn2.se_perso_confirm())
        print('Test [se_perso_back_perso]:', conn2.se_perso_back_perso(PINHASH))
        
        
        print('\n#Authentication')
        PINRESP = '00' * 16
        WRPINHASH = '00' * 32
        MAC = '00' * 32
        print('Test [se_pin_chlng]:', conn2.se_pin_chlng())
        print('Test [se_pin_auth]:', conn2.se_pin_auth(PINRESP))
        print('Test [se_pin_change]:', conn2.se_pin_change(WRPINHASH, MAC))
        print('Test [se_pin_logout]:', conn2.se_pin_logout())

        print('\n#BCDC Setting')
        CARDNAME = '00' * 32
        SECPO = '00' * 4
        print('Test [se_get_card_name]:', conn2.se_get_card_name())
        print('Test [se_set_card_name]:', conn2.se_set_card_name(CARDNAME))
        print('Test [se_get_secpo]:', conn2.se_get_secpo())
        print('Test [se_set_secpo]:', conn2.se_set_secpo(SECPO))

        print('\n#Transaction Signing')
        AMOUNT = '00' * 32
        ENCOUTADDR = '00' * 48
        IN_ID = '01'
        print('Test [se_trx_status]:', conn2.se_trx_status())
        print('Test [se_trx_begin]:', conn2.se_trx_begin(AMOUNT, ENCOUTADDR))
        print('Test [se_trx_get_ctxinfo]:', conn2.se_trx_get_ctxinfo(IN_ID))
        print('Test [se_trx_sign]:', conn2.se_trx_sign(IN_ID))
        print('Test [se_trx_finish]:', conn2.se_trx_finish())
        
        print('\n#HD Wallet')
        HDWNAME = '00' * 32
        EMKSEED = '00' * 64
        MAC = '00' * 32
        INFOID = '00'
        HDWINFO = '00' * 32

        conn2.se_hdw_init_wallet(HDWNAME, EMKSEED, MAC)
        conn2.se_hdw_qry_wa_info(INFOID)
        conn2.se_hdw_set_wa_info('01', HDWINFO)
        '''
        conn2.se_hdw_create_account(self, ACCID, ACCNAME)
        conn2.se_hdw_qry_acc_info(self, INFOID, BalanceFormat, ACCID)
        conn2.se_hdw_set_acc_info(self, INFOID, ACCID, ACCINFO, MAC)
        conn2.se_hdw_next_trx_addr(self, KCID, ACCID)
        conn2.se_hdw_prep_trx_sign(self, IN_ID, KCID, ACCID, KID, BALNC, SIGMTRL, MAC)
        conn2.se_hdw_init_wallet_gen_confirm(self, ACTVCODE, NUCHKSUM)
        '''
#CoolwalletLib.CwHttpTransport Test
    if T_CwHttpTransport:
        print('[CoolwalletLib.CwHttpTransport] test CMD:80100000')
        conn1 = CoolwalletClient(data['ip'], data['port'])
        conn1.CwWrite('80100000')
        print(conn1.CwRead())