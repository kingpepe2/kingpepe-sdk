import requests

class KingPepeMarket:
    API_URL = "https://api.coinpaprika.com/v1/tickers/kpepe-kingpepe-1"

    @staticmethod
    def get_price(pair="KPEPE/USDT"):
        response = requests.get(KingPepeMarket.API_URL)
        return {"price": response.json().get("quotes", {}).get("USD", {}).get("price", "N/A")}
