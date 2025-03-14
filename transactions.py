import requests
from kpepe.config import API_URL

class KingPepeTransaction:
    @staticmethod
    def send_kpepe(from_address, to_address, amount, private_key):
        """ إرسال KPEPE إلى عنوان آخر """
        url = f"{API_URL}/send"
        payload = {
            "from": from_address,
            "to": to_address,
            "amount": amount,
            "private_key": private_key
        }
        response = requests.post(url, json=payload)
        return response.json()
