import re
import json
from curl_cffi import requests
from flask import Flask, request, render_template, redirect, url_for
from bs4 import BeautifulSoup
from models import db, ScanRecord

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///linkshield.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)


def take_screenshot(url):
    # 1. Onion link
    if '.onion' in url.lower():
        return None, "Yeh .onion (Tor) link hai. Tor network ke bahar se iska screenshot nahi liya ja sakta."

    # 2. Invalid characters
    domain_part = url.split('//')[-1].split('/')[0]
    invalid_chars = set(re.findall(r'[^a-zA-Z0-9.\-:]', domain_part))
    if invalid_chars:
        return None, f"Domain naam mein invalid character(s) hain: {', '.join(invalid_chars)}. Screenshot API aise domain ko resolve nahi kar sakti."

    # 3. Microlink API call
    try:
        resp = requests.get("https://api.microlink.io", params={
            'url': url, 'screenshot': 'true', 'meta': 'false'
        }, timeout=30)
        data = resp.json()
        if data.get('status') == 'success':
            return data['data']['screenshot']['url'], None
        else:
            return None, "Microlink API ne screenshot nahi diya. Ho sakta hai website ne block kiya ho ya load hone mein zyada time laga ho."
    except Exception as e:
        return None, f"API call fail ho gayi: {str(e)[:80]}"


def analyze(url):
    flags, score = [], 0

    # Onion link
    if '.onion' in url.lower():
        flags.append("Onion (.onion) link detected — Tor network link, cannot be verified")
        return flags, 100

    # Invalid domain characters
    domain_part = url.split('//')[-1].split('/')[0]
    invalid_chars = set(re.findall(r'[^a-zA-Z0-9.\-:]', domain_part))
    if invalid_chars:
        flags.append(f"Invalid character(s) in domain: {', '.join(invalid_chars)}")
        return flags, 80

    # HTTP check
    if url.startswith('http://'):
        flags.append("Non-HTTPS connection (insecure)")
        score += 20

    # Suspicious keywords
    for kw in ['login', 'verify', 'secure', 'update', 'bank', 'signin']:
        if kw in url.lower():
            flags.append(f"Suspicious keyword in URL: '{kw}'")
            score += 15
            break

    # Suspicious TLDs
    suspicious_tlds = ['.xyz', '.top', '.click', '.shop', '.tk']
    for tld in suspicious_tlds:
        if url.lower().endswith(tld) or tld + '/' in url.lower():
            flags.append(f"Suspicious TLD detected: '{tld}'")
            score += 20
            break

    # Fetch page content
    try:
        resp = requests.get(url, timeout=15, impersonate="chrome")
        soup = BeautifulSoup(resp.text, 'html.parser')

        if soup.find_all('input', {'type': 'password'}):
            flags.append("Password input field detected (possible phishing)")
            score += 30

        text = soup.get_text().lower()
        for phrase in ['verify your account', 'suspended', 'unusual activity', 'click here to unlock', 'account locked']:
            if phrase in text:
                flags.append(f"Suspicious phrase detected: '{phrase}'")
                score += 25
                break
    except Exception as e:
        flags.append(f"Content fetch failed: {str(e)[:50]}")
        score += 40

    # Agar koi flag nahi mila, to safe message
    if not flags:
        flags.append("Koi suspicious pattern nahi mila. Yeh link safe lag raha hai.")

    return flags, min(score, 100)


@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if url and not url.startswith('http'):
            url = 'https://' + url

        if url:
            flags, score = analyze(url)
            screenshot, screenshot_reason = take_screenshot(url)

            if score >= 50:
                verdict, color = "HIGH RISK (Likely Scam)", "red"
            elif score >= 20:
                verdict, color = "SUSPICIOUS", "orange"
            else:
                verdict, color = "LOW RISK", "green"

            # DATABASE MEIN SAVE KAREIN
            record = ScanRecord(
                url=url,
                risk_score=score,
                verdict=verdict,
                flags=json.dumps(flags),
                screenshot_url=screenshot or ""
            )
            db.session.add(record)
            db.session.commit()

            result = {
                'url': url,
                'screenshot': screenshot,
                'screenshot_reason': screenshot_reason,
                'flags': flags,
                'score': score,
                'verdict': verdict,
                'color': color
            }

    return render_template('index.html', result=result)


@app.route('/history')
def history():
    records = ScanRecord.query.order_by(ScanRecord.scanned_at.desc()).all()
    return render_template('history.html', records=records)


@app.route('/delete/<int:record_id>', methods=['POST'])
def delete_record(record_id):
    record = ScanRecord.query.get_or_404(record_id)
    db.session.delete(record)
    db.session.commit()
    return redirect(url_for('history'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()      # Pehli baar database tables banayega
    app.run(debug=True, port=5000)