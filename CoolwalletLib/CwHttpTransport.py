#Coolwallet Http Transport

from .CwTransport import CoolWalletTransport

import http.client

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
        #print('[url]:', url)
        print('#--------------------\n#cmd:', cmd)
        print('#data:', data)
        #conn = http.client.HTTPConnection(self.server, self.port, timeout=10)
        try:
            self.conn.request('GET', url)
            resp = self.conn.getresponse()
        except Exception as e:
            print(e)
            self.data = ''
            return False
        else:
            #print(resp.status, resp.reason)
            self.data = resp.read()
            return True

    def CwRead(self):
        if not self.data:
            print('#None data')
            return False
        data_get = self.data.decode('utf-8').split('<!DOCTYPE html>')[-1]

        data_time = data_get[data_get.find('Time:') + 5 : data_get.find('<br>')]
        data_command = data_get[data_get.find('Command:') + 8 : data_get.find('<br>Data:')]
        data_data = data_get[data_get.find('Data:') + 5 : data_get.find('<br>Response:')]
        data_response = data_get[data_get.find('Response:') + 9 : data_get.find('<br><br>')]

        #print('time:', data_time, '\ncommand:', data_command, '\ndata:', data_data, '\nresponse:', data_response)
        print('#response:', data_response)
        return data_response

    def CwCloseHTTP(self):
        #conn = http.client.HTTPConnection(self.server, self.port, timeout=10)
        self.conn.close()

