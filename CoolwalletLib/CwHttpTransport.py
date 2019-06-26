#Coolwallet Http Transport

from .CwTransport import CoolWalletTransport

import http.client
import logging

logger = logging.getLogger( __name__ )
logger.setLevel(logging.INFO)

#This class entends the CoolWalletTransportClient for Http client
class CoolwalletClient(CoolWalletTransport):

    def __init__(self, server, port):
        self.server = server
        self.port = port
        self.data = ''
        conn = http.client.HTTPConnection(self.server, self.port, timeout=10)
        self.conn = conn


    def CwWrite(self, cmd, data=''):
        self.cmd = cmd
        self.data = data
        url = '/?cmd=' + cmd + '&data=' + data

        logger.debug(' #cmd: %s', cmd)
        logger.debug(' #data: %s', data)

        try:
            self.conn.request('GET', url)
            resp = self.conn.getresponse()

        except Exception as e:
            print(e)
            self.data = ''
            return False

        else:
            self.data = resp.read()
            return True

    def CwRead(self):
        if not self.data:
            return False

        data_get = self.data.decode('utf-8').split('<!DOCTYPE html>')[-1]
        '''
        data_time = data_get[data_get.find('Time:') + 5 : data_get.find('<br>')]
        data_command = data_get[data_get.find('Command:') + 8 : data_get.find('<br>Data:')]
        data_data = data_get[data_get.find('Data:') + 5 : data_get.find('<br>Response:')]
        logger.debug('time:', data_time, '\ncommand:', data_command, '\ndata:', data_data, '\nresponse:', data_response)
        '''
        data_response = data_get[data_get.find('Response:') + 9 : data_get.find('<br><br>')]        
        logger.debug(' #response: %s\n', data_response)
        return data_response

    def CwCloseHTTP(self):
        self.conn.close()

