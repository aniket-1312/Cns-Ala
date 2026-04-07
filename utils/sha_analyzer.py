import hashlib

def generate_hashes(message):
    return {
        "SHA-1": hashlib.sha1(message.encode()).hexdigest(),
        "SHA-256": hashlib.sha256(message.encode()).hexdigest(),
        "SHA-512": hashlib.sha512(message.encode()).hexdigest()
    }