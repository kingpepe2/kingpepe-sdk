import requests
import time
from kpepe.config import API_URL

class KingPepeNotifications:
    def __init__(self):
        self.last_price = None  # لتتبع آخر سعر تم تحديثه

    def get_kpepe_price(self):
        """ جلب سعر KPEPE/USDT من API """
        url = f"{API_URL}/price/kpepe_usdt"
        response = requests.get(url)
        if response.status_code == 200:
            return response.json().get("price", 0)
        return None

    def send_notification(self, message):
        """ محاكاة إرسال إشعار للمستخدم (يمكنك دمجها مع Firebase لاحقًا) """
        print(f"🔔 NOTIFICATION: {message}")

    def price_alert(self, threshold_up, threshold_down):
        """ إرسال إشعار عندما يتجاوز السعر حداً معينًا """
        current_price = self.get_kpepe_price()
        if current_price is None:
            return

        if self.last_price is None:
            self.last_price = current_price  # تعيين السعر الأولي

        if current_price >= threshold_up:
            self.send_notification(f"🚀 سعر KPEPE ارتفع إلى {current_price} USDT! 📈")
        elif current_price <= threshold_down:
            self.send_notification(f"📉 سعر KPEPE انخفض إلى {current_price} USDT! 😢")

        self.last_price = current_price  # تحديث السعر الأخير

    def track_transactions(self, address):
        """ مراقبة عنوان معين والإشعار عند حدوث معاملة """
        url = f"{API_URL}/address/{address}"
        response = requests.get(url)
        if response.status_code == 200:
            transactions = response.json().get("transactions", [])
            if transactions:
                last_tx = transactions[0]  # أحدث معاملة
                self.send_notification(f"💰 تمت معاملة جديدة على عنوانك: {last_tx}")

    def start_tracking(self, address, threshold_up, threshold_down, interval=60):
        """ تشغيل نظام الإشعارات بشكل دوري """
        while True:
            self.price_alert(threshold_up, threshold_down)
            self.track_transactions(address)
            time.sleep(interval)  # تحديث كل دقيقة
