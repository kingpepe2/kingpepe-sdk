import requests
from kpepe.config import API_URL

class KingPepeAPI:
    @staticmethod
    def get_balance(address):
        """ استعلام عن رصيد عنوان معين """
        url = f"{API_URL}/address/{address}"
        response = requests.get(url)
        data = response.json()
        return data.get("balance", 0)

    @staticmethod
    def get_transaction(txid):
        """ البحث عن تفاصيل معاملة معينة """
        url = f"{API_URL}/tx/{txid}"
        response = requests.get(url)
        return response.json()
