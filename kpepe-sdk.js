const bitcoin = require('bitcoinjs-lib');
const bs58check = require('bs58check');
const crypto = require('crypto');
const axios = require('axios');

const NETWORKS = {
    mainnet: {
        messagePrefix: '\u0018KingPepe Signed Message:\n',
        bech32: 'kpepe',
        bip32: { public: 0x0488B21E, private: 0x0488ADE4 },
        pubKeyHash: 0x01,
        scriptHash: 0x00,
        wif: 0x80,
        apiBase: 'https://kpepe-explorer.pool.sexy/api/'
    }
};

/**
 * 🟢 توليد محفظة جديدة (عنوان + مفتاح عام + مفتاح خاص مشفر)
 */
function generateKeyPair(network = 'mainnet') {
    const keyPair = bitcoin.ECPair.makeRandom({ network: NETWORKS[network] });
    const encryptedPrivateKey = encryptPrivateKey(keyPair.toWIF());

    return {
        privateKey: encryptedPrivateKey,
        publicKey: keyPair.publicKey.toString('hex'),
        address: bitcoin.payments.p2pkh({ pubkey: keyPair.publicKey, network: NETWORKS[network] }).address,
    };
}

/**
 * 🔒 تشفير المفتاح الخاص لحمايته
 */
function encryptPrivateKey(privateKey) {
    const algorithm = 'aes-256-cbc';
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(privateKey, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return `${iv.toString('hex')}:${encrypted}`;
}

/**
 * 🔓 فك تشفير المفتاح الخاص
 */
function decryptPrivateKey(encryptedKey) {
    const [ivHex, encrypted] = encryptedKey.split(':');
    const algorithm = 'aes-256-cbc';
    const key = crypto.randomBytes(32);
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

/**
 * ✅ التحقق من صحة العنوان
 */
function isValidAddress(address, network = 'mainnet') {
    try {
        const decoded = bs58check.decode(address);
        return decoded[0] === NETWORKS[network].pubKeyHash || decoded[0] === NETWORKS[network].scriptHash;
    } catch (error) {
        return false;
    }
}

/**
 * 📤 إرسال معاملة
 */
async function sendTransaction(privateKey, toAddress, amount, network = 'mainnet') {
    try {
        // فك تشفير المفتاح الخاص
        const decryptedPrivateKey = decryptPrivateKey(privateKey);
        const keyPair = bitcoin.ECPair.fromWIF(decryptedPrivateKey, NETWORKS[network]);

        // جلب UTXOs (المخرجات غير المنفقة)
        const fromAddress = bitcoin.payments.p2pkh({ pubkey: keyPair.publicKey, network: NETWORKS[network] }).address;
        const utxos = await axios.get(`${NETWORKS[network].apiBase}getaddress?address=${fromAddress}`);
        
        if (!utxos.data || !utxos.data.transactions.length) {
            throw new Error("لا يوجد رصيد متاح لإجراء المعاملة.");
        }

        // إنشاء معاملة جديدة
        const psbt = new bitcoin.Psbt({ network: NETWORKS[network] });

        let inputAmount = 0;
        utxos.data.transactions.forEach(tx => {
            tx.vout.forEach((out, index) => {
                if (out.scriptPubKey.addresses.includes(fromAddress)) {
                    psbt.addInput({
                        hash: tx.txid,
                        index,
                        nonWitnessUtxo: Buffer.from(tx.hex, 'hex'),
                    });
                    inputAmount += out.value;
                }
            });
        });

        if (inputAmount < amount) {
            throw new Error("الرصيد غير كافٍ لإرسال هذه المعاملة.");
        }

        // إضافة الإخراج (المرسل إليه)
        psbt.addOutput({
            address: toAddress,
            value: amount,
        });

        // إضافة الباقي إلى نفس العنوان
        const fee = 1000; // الرسوم التقريبية
        if (inputAmount - amount - fee > 0) {
            psbt.addOutput({
                address: fromAddress,
                value: inputAmount - amount - fee,
            });
        }

        // توقيع المعاملة
        psbt.signAllInputs(keyPair);
        psbt.finalizeAllInputs();
        const rawTransaction = psbt.extractTransaction().toHex();

        // بث المعاملة إلى الشبكة
        const response = await axios.post(`${NETWORKS[network].apiBase}sendrawtransaction`, {
            hex: rawTransaction
        });

        return response.data;
    } catch (error) {
        console.error("خطأ في إرسال المعاملة:", error);
        throw error;
    }
}

/**
 * 📥 استلام تفاصيل المعاملة
 */
async function getTransaction(txid, network = 'mainnet') {
    try {
        const response = await axios.get(`${NETWORKS[network].apiBase}getrawtransaction?txid=${txid}&decrypt=1`);
        return response.data;
    } catch (error) {
        console.error("خطأ في جلب بيانات المعاملة:", error);
        throw error;
    }
}

module.exports = {
    generateKeyPair,
    encryptPrivateKey,
    decryptPrivateKey,
    isValidAddress,
    sendTransaction,
    getTransaction,
    NETWORKS,
};
