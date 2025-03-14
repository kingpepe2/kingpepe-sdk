import requests
from kpepe.config import API_URL

class KingPepeBlockchain:
    @staticmethod
    def get_blockchain_info():
        """ جلب معلومات البلوكشين مثل عدد الكتل، الصعوبة، ومعدل الهاش """
        url = f"{API_URL}/blockchaininfo"
        response = requests.get(url)
        return response.json()
    
    @staticmethod
    def get_latest_block():
        """ جلب أحدث بلوك على الشبكة """
        url = f"{API_URL}/latestblock"
        response = requests.get(url)
        return response.json()
