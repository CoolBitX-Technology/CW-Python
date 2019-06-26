# This is an abstract class that defines all of method that each CoolWallet 
# Transport must implement
class CoolWalletTransport:

    def CwWrite(self, cmd, data):
        raise NotImplementedError('The CoolWalletTransport base class does not implement this method')

    def CwRead(self):
        raise NotImplementedError('The CoolWalletTransport base class does not implement this method')
