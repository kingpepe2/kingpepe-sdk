from bitcoin import *

class KingPepeWallet:
    def __init__(self):
        """ إنشاء محفظة جديدة تحتوي على مفتاح خاص وعام وعنوان. """
        self.private_key = random_key()
        self.public_key = privtopub(self.private_key)
        self.address = pubtoaddr(self.public_key)

    def get_address(self):
        """ إرجاع عنوان المحفظة """
        return self.address

    def get_private_key(self):
        """ إرجاع المفتاح الخاص (للاستخدام المتقدم) """
        return self.private_key
