#Coolwallet API implement

from .CwHttpTransport import CoolwalletClient

class cwse_apdu_command:

    def __init__(self, server, port):
        self.server = server
        self.port = port
        self.connet = CoolwalletClient(self.server, self.port)
        self.apdu_CLA = '80'

    def close(self):
        self.connet.CwCloseHTTP()

#SE Information

    #Get SE mode and state 
    def se_get_mode_state(self):
        cmd = self.apdu_CLA + '10' + '0000'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Get SE firmware version
    def se_get_fw_version(self):
        cmd = self.apdu_CLA + '11' + '0000'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Get SE unique ID
    def se_get_unique_id(self):
        cmd = self.apdu_CLA + '12' + '0000'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Get internal module error
    def se_get_mod_err(self):
        cmd = self.apdu_CLA + '13' + '0000'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Get SE basic info
    def se_get_basic_info(self):
        cmd = self.apdu_CLA + '14' + '0000'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Back to IKV loader
    def se_back_ikvldr(self):
        pass

#Host Binding 

    #Init binding registeration
    def se_bind_reg_init(self, FIRST, HSTCRED, HSTDESC, HASH):
        cmd = self.apdu_CLA + 'D0' + FIRST + '00'
        data = HSTCRED + HSTDESC + HASH
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Get registration challenge
    def se_bind_reg_chlng(self, BRHANDLE):
        cmd = self.apdu_CLA + 'D1' + '0000'
        data = BRHANDLE
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Finish binding registration
    #PINRESP irrelevant for the "add host" case
    def se_bind_reg_finish(self, BRHANDLE, REGRESP, PINRESP=''):
        cmd = self.apdu_CLA + 'D2' + '0000'
        data = BRHANDLE + REGRESP + PINRESP
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Get registered host info
    def se_bind_reg_info(self, HST_ID):
        cmd = self.apdu_CLA + 'D3' + HST_ID + '00'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Approve unconfirmed registered host
    def se_bind_reg_approve(self, HST_ID):
        cmd = self.apdu_CLA + 'D4' + HST_ID + '00'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Remove registered host
    def se_bind_reg_remove(self, HST_ID):
        cmd = self.apdu_CLA + 'D5' + HST_ID + '00'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Get login challenge
    def se_bind_login_chlng(self, HST_ID):
        cmd = self.apdu_CLA + 'D6' + HST_ID + '00'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Host binding login
    def se_bind_login(self, HST_ID, BINDRESP):
        cmd = self.apdu_CLA + 'D7' + HST_ID + '00'
        data = BINDRESP
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Host binding logout
    def se_bind_logout(self):
        cmd = self.apdu_CLA + 'D8' + '0000'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Find registered host ID by host credential
    def se_bind_find_hst_id(self, HSTCRED):
        cmd = self.apdu_CLA + 'D9' + '0000'
        data = HSTCRED 
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Back to NOHOST mode
    def se_bind_back_nohost(self, PINRESP, PINHASH):
        cmd = self.apdu_CLA + 'DA' + '0000'
        data =  PINRESP + PINHASH
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

#Personalization

    #Set perso data
    def se_perso_set_data(self, PDID, PERDATA, PDMAC):
        cmd = self.apdu_CLA + '30' + PDID + '00'
        data = PERDATA + PDMAC
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Get perso data hash
    def se_perso_get_data_hash(self, PDID):
        cmd = self.apdu_CLA + '31' + PDID + '00'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Confirm perso data
    def se_perso_confirm(self):
        cmd = self.apdu_CLA + '32' + '0000'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Back to PERSO state
    def se_perso_back_perso(self, PINHASH):
        cmd = self.apdu_CLA + '33' + '0000'
        data = PINHASH
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

#Authentication

    #Get PIN auth challenge
    def se_pin_chlng(self):
        cmd = self.apdu_CLA + '20' + '0000'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #PIN authentication
    def se_pin_auth(self, PINRESP):
        cmd = self.apdu_CLA + '21' + '0000'
        data = PINRESP
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Change PIN
    def se_pin_change(self, WRPINHASH, MAC):
        cmd = self.apdu_CLA + '22' + '0000'
        data = WRPINHASH + MAC
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #PIN logout
    def se_pin_logout(self):
        cmd = self.apdu_CLA + '23' + '0000'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

#BCDC Setting

    #Get SE card name
    def se_get_card_name(self):
        cmd = self.apdu_CLA + '42' + '0000'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Set SE card name
    def se_set_card_name(self, CARDNAME):
        cmd = self.apdu_CLA + '43' + '0000'
        data = CARDNAME
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Get security policy setting
    def se_get_secpo(self):
        cmd = self.apdu_CLA + '44' + '0000'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Set security policy setting
    def se_set_secpo(self, SECPO):
        cmd = self.apdu_CLA + '45' + '0000'
        data = SECPO
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

#Transaction Signing

    #Get transaction signing status
    def se_trx_status(self):
        cmd = self.apdu_CLA + '80' + '0000'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Transaction signing begins
    def se_trx_begin(self, AMOUNT, ENCOUTADDR):
        cmd = self.apdu_CLA + '72' + '0000'
        data = AMOUNT + ENCOUTADDR
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Get transaction signing context info
    def se_trx_get_ctxinfo(self, IN_ID):
        cmd = self.apdu_CLA + '75' + IN_ID + '00'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Sign transaction
    def se_trx_sign(self, IN_ID):
        cmd = self.apdu_CLA + '74' + IN_ID + '00'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Finish transaction signing
    def se_trx_finish(self):
        cmd = self.apdu_CLA + '76' + '0000'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

#HD Wallet----------------------------------------------------

    #Initialize HDW
    def se_hdw_init_wallet(self, HDWNAME, EMKSEED, MAC):
        cmd = self.apdu_CLA + 'B0' + '0000'
        data = HDWNAME + EMKSEED + MAC # 32 bytes + 64 bytes + 32 bytes
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Query HDW info
    def se_hdw_qry_wa_info(self, INFOID):
        cmd = self.apdu_CLA + 'B2' + INFOID + '00'
        self.connet.CwWrite(cmd)
        return self.connet.CwRead()

    #Set HDW info
    def se_hdw_set_wa_info(self, INFOID, HDWINFO):
        cmd = self.apdu_CLA + 'B3' + INFOID + '00'
        data = HDWINFO # variable length
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Create HDW account
    def se_hdw_create_account(self, ACCID, ACCNAME):
        cmd = self.apdu_CLA + 'B4' + '0000'
        data = ACCID + ACCNAME # 4 bytes + 32 bytes
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Query HDW account info
    def se_hdw_qry_acc_info(self, INFOID, BalanceFormat, ACCID):
        cmd = self.apdu_CLA + 'B5' + INFOID + BalanceFormat
        data = ACCID # 4 bytes
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Set HDW account info
    def se_hdw_set_acc_info(self, INFOID, ACCID, ACCINFO, MAC):
        cmd = self.apdu_CLA + 'B6' + INFOID + '00'
        data = ACCID + ACCINFO + MAC # 4 bytes + Vari bytes + (MAC value for ACCINFO)32 bytes
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Get next trx address
    def se_hdw_next_trx_addr(self, KCID, ACCID):
        cmd = self.apdu_CLA + 'B7' + KCID + '00'
        data = ACCID # 4 bytes
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Prepare HDW trx signing
    def se_hdw_prep_trx_sign(self, IN_ID, KCID, ACCID, KID, BALNC, SIGMTRL, MAC):
        cmd = self.apdu_CLA + 'B8' + IN_ID + KCID
        data = ACCID + KID + BALNC + SIGMTRL + MAC  #4 bytes + 4 bytes + 32 bytes + 32 bytes + 32 bytes
        #data = '00' * (4+4+8+32+32)
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Confirm HDW initialization (gen key)
    def se_hdw_init_wallet_gen_confirm(self, ACTVCODE, NUCHKSUM):
        cmd = self.apdu_CLA + 'B9' + '0000'
        data = ACTVCODE + NUCHKSUM # 4 bytes + 6 bytes, ASCII format
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Query HDW account key info
    def se_hdw_qry_acc_keyinfo(self, KINFOID, KCID, ACCID, KID):
        cmd = self.apdu_CLA + 'BA' + KINFOID + KCID
        data = ACCID + KID # 4 bytes + 4 bytes
        self.connet.CwWrite(cmd, data)
        return self.connet.CwRead()

    #Query HDW extended public key by BIP32 path, Add by Bob
    def se_hdw_qry_xpub(self, PURPOSE, COINTYPE='', ACC_VAL='', CHANGE='', index=''):
        cmd = self.apdu_CLA + 'BB' + '0000'
        data = PURPOSE + COINTYPE + ACC_VAL + CHANGE + index
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
