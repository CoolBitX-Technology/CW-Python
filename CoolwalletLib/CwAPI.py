#Coolwallet API implement

from .CwHttpTransport import CoolwalletClient

class cwse_apdu_command:

    def __init__(self, server, port):
        self.server = server
        self.port = port
        self.connet = CoolwalletClient(self.server, self.port)
        self.apdu_CLA = 80

    def close(self):
        self.connet.CwCloseHTTP()

#SE Information

    #Get SE mode and state 
    def se_get_mode_state(self):
        cmd = '80100000'
        if self.apdu_CLA == 81:
            cmd = '81100000'        
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Get SE firmware version
    def se_get_fw_version(self):
        cmd = '80110000'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Get SE unique ID
    def se_get_unique_id(self):
        cmd = '80120000'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Get internal module error
    def se_get_mod_err(self):
        cmd = '80130000'
        if self.apdu_CLA == 81:
            cmd = '81130000'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Get SE basic info
    def se_get_basic_info(self):
        cmd = '80140000'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Back to IKV loader
    def se_back_ikvldr(self):
        pass

#Host Binding

    #Init binding registeration
    def se_bind_reg_init(self, FIRST, HSTCRED, HSTDESC, HASH):
        cmd = '80D0' + FIRST + '00'
        data = HSTCRED + HSTDESC + HASH # 32 bytes + 64 bytes + (HASH of HSTCRED || HSTDESC)32 bytes
        if self.connet.CwWrite(cmd, data):
            return self.connet.CwRead()
        else:
            return False

    #Get registration challenge
    def se_bind_reg_chlng(self, BRHANDLE):
        cmd = '80D10000'
        data = BRHANDLE # 4 bytes
        if self.connet.CwWrite(cmd, data):
            return self.connet.CwRead()
        else:
            return False

    #Finish binding registration
    #PINRESP irrelevant for the "add host" case
    def se_bind_reg_finish(self, BRHANDLE, REGRESP, PINRESP=''):
        #self.connet.= CoolwalletClient(self.server, self.port)
        PINRESP = '00' * 16
        cmd ='80D20000' 
        data = BRHANDLE + REGRESP + PINRESP # 4 bytes + 16 bytes + 16 bytes
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Get registered host info
    def se_bind_reg_info(self, HST_ID):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '80D3' + HST_ID + '00'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Approve unconfirmed registered host
    def se_bind_reg_approve(self, HST_ID):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '80D4'+ HST_ID + '00'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Remove registered host
    def se_bind_reg_remove(self, HST_ID):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '80D5'+ HST_ID + '00'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Get login challenge
    def se_bind_login_chlng(self, HST_ID):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '80D6'+ HST_ID + '00'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Host binding login
    def se_bind_login(self, HST_ID, BINDRESP):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '80D7'+ HST_ID + '00'
        data = BINDRESP # 16 bytes
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Host binding logout
    def se_bind_logout(self):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '80D80000'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Find registered host ID by host credential
    def se_bind_find_hst_id(self, HSTCRED):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '80D90000'
        data = HSTCRED # 32 bytes
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Back to NOHOST mode
    def se_bind_back_nohost(self, PINRESP, PINHASH):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '80DA0000'
        data =  PINRESP + PINHASH # 16 bytes + 32 bytes
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

#Personalization

    #Set perso data
    def se_perso_set_data(self, PDID, PERDATA, PDMAC):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '8030' + PDID + '00'
        data = PERDATA + PDMAC # var bytes + (MAC of PERDATA)32 bytes
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Get perso data hash
    def se_perso_get_data_hash(self, PDID):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '8031' + PDID + '00'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Confirm perso data
    def se_perso_confirm(self):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '80320000'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Back to PERSO state
    def se_perso_back_perso(self, PINHASH):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '80330000'
        data = PINHASH # 32 bytes
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

#Authentication

    #Get PIN auth challenge
    def se_pin_chlng(self):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '80200000'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #PIN authentication
    def se_pin_auth(self, PINRESP):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '80210000'
        data = PINRESP # 16 bytes
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Change PIN
    def se_pin_change(self, WRPINHASH, MAC):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '80220000'
        data = WRPINHASH + MAC # 32 bytes + (MAC of WRPINHASH)32 bytes
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #PIN logout
    def se_pin_logout(self):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '80230000'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

#BCDC Setting

    #Get SE card name
    def se_get_card_name(self):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '80420000'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Set SE card name
    def se_set_card_name(self, CARDNAME):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '80430000'
        data = CARDNAME # 32 bytes
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Get security policy setting
    def se_get_secpo(self):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '80440000'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Set security policy setting
    def se_set_secpo(self, SECPO):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '80450000'
        data = SECPO # 4 bytes
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

#Transaction Signing

    #Get transaction signing status
    def se_trx_status(self):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '80800000'
        if self.apdu_CLA == 81:
            cmd = '81800000'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()


    #Transaction signing begins
    def se_trx_begin(self, AMOUNT, ENCOUTADDR):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '80720000'
        if self.apdu_CLA == 81:
            cmd = '81720000'
        data = AMOUNT + ENCOUTADDR # 32 bytes + 48 bytes
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Get transaction signing context info
    def se_trx_get_ctxinfo(self, IN_ID):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '8075' + IN_ID + '00'
        if self.apdu_CLA == 81:
            cmd = '8175' + IN_ID + '00'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Sign transaction
    def se_trx_sign(self, IN_ID):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '8074' + IN_ID + '00'
        if self.apdu_CLA == 81:
            cmd = '8174' + IN_ID + '00'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Finish transaction signing
    def se_trx_finish(self):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '80760000'
        if self.apdu_CLA == 81:
            cmd = '81760000'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

#HD Wallet

    #Initialize HDW
    def se_hdw_init_wallet(self, HDWNAME, EMKSEED, MAC):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '80B00000'
        data = HDWNAME + EMKSEED + MAC # 32 bytes + 64 bytes + 32 bytes
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Query HDW info
    def se_hdw_qry_wa_info(self, INFOID):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '80B2' + INFOID + '00'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Set HDW info
    def se_hdw_set_wa_info(self, INFOID, HDWINFO):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '80B3' + INFOID + '00'
        data = HDWINFO # variable length
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Create HDW account
    def se_hdw_create_account(self, ACCID, ACCNAME):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '80B40000'
        data = ACCID + ACCNAME # 4 bytes + 32 bytes
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Query HDW account info
    def se_hdw_qry_acc_info(self, INFOID, BalanceFormat, ACCID):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '80B5' + INFOID + BalanceFormat
        data = ACCID # 4 bytes
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Set HDW account info
    def se_hdw_set_acc_info(self, INFOID, ACCID, ACCINFO, MAC):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '80B6' + INFOID + '00'
        data = ACCID + ACCINFO + MAC # 4 bytes + Vari bytes + (MAC value for ACCINFO)32 bytes
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Get next trx address
    def se_hdw_next_trx_addr(self, KCID, ACCID):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '80B7' + KCID + '00'
        #cmd = '81B7' + KCID + '00'
        data = ACCID # 4 bytes
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Prepare HDW trx signing
    def se_hdw_prep_trx_sign(self, IN_ID, KCID, ACCID, KID, BALNC, SIGMTRL, MAC):
        #self.connet.= CoolwalletClient(self.server, self.port)
        #cmd = '80B8' + IN_ID + KCID
        cmd = '81B8' + IN_ID + KCID
        data = ACCID + KID + BALNC + SIGMTRL + MAC  #4 bytes + 4 bytes + 32 bytes + 32 bytes + 32 bytes
        #data = '00' * (4+4+8+32+32)
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Confirm HDW initialization (gen key)
    def se_hdw_init_wallet_gen_confirm(self, ACTVCODE, NUCHKSUM):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '80B90000'
        data = ACTVCODE + NUCHKSUM # 4 bytes + 6 bytes, ASCII format
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Query HDW account key info
    def se_hdw_qry_acc_keyinfo(self, KINFOID, KCID, ACCID, KID):
        #self.connet.= CoolwalletClient(self.server, self.port)
        cmd = '80BA' + KINFOID + KCID
        data = ACCID + KID # 4 bytes + 4 bytes
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Query HDW extended public key by BIP32 path, Add by Bob
    def se_hdw_qry_xpub(self, PURPOSE, COINTYPE='', ACC_VAL='', CHANGE='', index=''):
        cmd = '80BB0000'
        data = PURPOSE + COINTYPE + ACC_VAL + CHANGE + index # 4 + 4 + 4 + 4 + 4
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

#MCU Command
    
    #Verify OTP
    def mcu_verify_otp(self, OTP):
        cmd = '8064'+'0000'
        data = OTP
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

#Change CLA
    def change_apdu_CLA(self, CLA):
        self.apdu_CLA = CLA
