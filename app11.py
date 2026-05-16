from flask import Flask, render_template, request
import re

app = Flask(__name__)

def analyze_message(text):
    score = 0
    reasons = []
    highlights = []
    
    # 1. Check for Links
    links = re.findall(r'(https?://\S+|www\.\S+)', text)
    if links:
        score += 40
        reasons.append("Contains external links (primary delivery method for malware/phishing).")
        highlights.extend(links)
    
    # 2. Urgency & Pressure
    urgency_words = ["urgent", "immediately", "act now", "limited time", "expires", "last warning", "final notice"]
    found_urgency = [word for word in urgency_words if word in text.lower()]
    if found_urgency:
        score += 25
        reasons.append("Uses urgency language designed to bypass critical thinking.")
        highlights.extend(found_urgency)

    # 3. Sensitive Data Requests
    data_words = ["otp", "password", "pin", "verify", "social security", "ssn", "login", "credentials"]
    found_data = [word for word in data_words if word in text.lower()]
    if found_data:
        score += 30
        reasons.append("Asks for sensitive credentials or identity verification.")
        highlights.extend(found_data)

    # 4. Financial/Reward Manipulation
    reward_words = ["winner", "prize", "cash", "refund", "bank", "account", "transaction", "unauthorized"]
    found_reward = [word for word in reward_words if word in text.lower()]
    if found_reward:
        score += 20
        reasons.append("Mentions financial accounts or rewards to trigger emotional responses.")
        highlights.extend(found_reward)

    # Final Classification
    confidence = min(score, 99) # Cap at 99% for realism
    if score >= 50:
        label = "Smishing Detected"
        category = "danger"
    elif score > 0:
        label = "Suspicious Activity"
        category = "warning"
        confidence = 45
    else:
        label = "Legitimate Message"
        category = "success"
        confidence = 98
        reasons.append("No common phishing patterns or malicious triggers identified.")

    return {
        "label": label,
        "category": category,
        "confidence": confidence,
        "reasons": reasons,
        "highlights": list(set(highlights))
    }

@app.route('/')
def awareness():
    return render_template('awareness.html')

@app.route('/detector', methods=['GET', 'POST'])
def detector():
    analysis = None
    original_text = ""
    if request.method == 'POST':
        original_text = request.form.get('sms_text', '').strip()
        if original_text:
            analysis = analyze_message(original_text)
    return render_template('index.html', analysis=analysis, original_text=original_text)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)