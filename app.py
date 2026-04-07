from flask import Flask, render_template, request
from cryptography.hazmat.primitives import serialization
from utils.digital_signature import sign_message, verify_signature
from utils.sha_analyzer import generate_hashes
from utils.hmac_auth import generate_mac, verify_mac

app = Flask(__name__)


def count_hex_differences(first_value, second_value):
    return sum(1 for first_char, second_char in zip(first_value, second_value) if first_char != second_char)

@app.route('/')
def home():
    return render_template('index.html')

# ---------------- ALA 1 ----------------
@app.route('/ala1', methods=['GET', 'POST'])
def ala1():
    result = None
    if request.method == 'POST':
        message = request.form['message']
        received_message = request.form.get('received_message') or message
        signature, public_key = sign_message(message)
        is_valid = verify_signature(message, signature, public_key)
        received_valid = verify_signature(received_message, signature, public_key)
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        result = {
            "message": message,
            "received_message": received_message,
            "signature": signature,
            "valid": is_valid,
            "received_valid": received_valid,
            "public_key": public_key_pem
        }

    return render_template('ala1.html', result=result)

# ---------------- ALA 2 ----------------
@app.route('/ala2', methods=['GET', 'POST'])
def ala2():
    comparison = None
    if request.method == 'POST':
        message = request.form['message']
        modified_message = request.form.get('modified_message') or f"{message}!"
        original_hashes = generate_hashes(message)
        modified_hashes = generate_hashes(modified_message)

        comparison = {
            "tampered": message != modified_message,
            "algorithms": {
                algorithm: {
                    "original": original_hashes[algorithm],
                    "modified": modified_hashes[algorithm],
                    "difference": count_hex_differences(original_hashes[algorithm], modified_hashes[algorithm])
                }
                for algorithm in original_hashes
            }
        }

    return render_template('ala2.html', comparison=comparison)

# ---------------- ALA 3 ----------------
@app.route('/ala3', methods=['GET', 'POST'])
def ala3():
    result = None
    if request.method == 'POST':
        message = request.form['message']
        key = request.form['key']
        tampered_message = request.form.get('tampered_message') or f"{message} changed"

        mac = generate_mac(message, key)
        receiver_valid = verify_mac(message, key, mac)
        tampered_valid = verify_mac(tampered_message, key, mac)
        is_tampered = not tampered_valid

        result = {
            "message": message,
            "tampered_message": tampered_message,
            "mac": mac,
            "receiver_valid": receiver_valid,
            "tampered_valid": tampered_valid,
            "tampered": is_tampered
        }

    return render_template('ala3.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)