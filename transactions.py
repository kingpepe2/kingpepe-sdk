import requests

class KingPepeTransaction:
    API_URL = "https://kpepe-explorer.pool.sexy/api"

    @staticmethod
    def get_balance(address):
        response = requests.get(f"{KingPepeTransaction.API_URL}/address/{address}")
        return response.json().get("balance", 0)

    @staticmethod
    def send_kpepe(from_address, to_address, amount, private_key):
        # Placeholder for real transaction signing and sending
        return f"Transaction of {amount} KPEPE from {from_address} to {to_address} simulated."
