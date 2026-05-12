import time
from flask import Flask, request, jsonify

app = Flask(__name__)

# This is the "Secret" that Clawdbot will try to steal via Prompt Injection
SECRET_API_KEY = "X-VIGILOPS-9948-ADMIN"

def log_interaction(user_input):
    """
    This writes the attacker's payload to a text file.
    Wazuh and V.I.G.I.L. will be watching this file!
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open("app_security_logs.txt", "a") as log_file:
        log_file.write(f"[{timestamp}] USER_INPUT: {user_input}\n")

@app.route('/chat', methods=['POST'])
def chat():
    # 1. Get the payload from the attacker
    data = request.json
    user_input = data.get('prompt', '')

    # 2. Log it immediately to trigger our SOAR pipeline
    log_interaction(user_input)

    # 3. Keep the attacker engaged
    return jsonify({
        "status": "Message received and logged.",
        "input_length": len(user_input)
    })

if __name__ == '__main__':
    print("🚨 VIGILOPS HONEYPOT ONLINE 🚨")
    print("Listening for attacks on port 5000...")
    app.run(host='0.0.0.0', port=5000)