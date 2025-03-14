import os
import hashlib
from bitcoinlib.wallets import Wallet
from bitcoinlib.mnemonic import Mnemonic

class KingPepeWallet:
    def __init__(self, name="kingpepe_wallet"):
        self.name = name
        self.wallet = Wallet.create(name, keys=Mnemonic().generate(), network='bitcoin')

    def get_address(self):
        return self.wallet.get_key().address

    def send_kpepe(self, to_address, amount, private_key):
        try:
            tx = self.wallet.send_to(to_address, amount)
            return f"Transaction Sent: {tx.txid}"
        except Exception as e:
            return f"Error: {e}"
