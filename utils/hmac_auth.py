import hmac
import hashlib

def generate_mac(message, key):
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()

def verify_mac(message, key, mac):
    new_mac = generate_mac(message, key)
    return hmac.compare_digest(new_mac, mac)