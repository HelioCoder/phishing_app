from flask import Flask, render_template, request
import joblib
import pandas as pd
import re
from urllib.parse import urlparse

app = Flask(__name__)

# Load model and feature list
model = joblib.load('phishing_url_detector.pkl')
features = joblib.load('feature_list.pkl')

# Feature extraction
def extract_features(url):
    parsed = urlparse(url)
    return pd.Series({
        'url_length': len(url),
        'hostname_length': len(parsed.hostname) if parsed.hostname else 0,
        'path_length': len(parsed.path),
        'count_dots': url.count('.'),
        'count_hyphens': url.count('-'),
        'count_slashes': url.count('/'),
        'count_at': url.count('@'),
        'count_question': url.count('?'),
        'count_equal': url.count('='),
        'count_https': 1 if 'https' in url else 0,
        'count_www': 1 if 'www' in url else 0,
        'is_ip': 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}", parsed.netloc) else 0
    })

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        url = request.form['url']
        input_data = extract_features(url).reindex(features).fillna(0).values.reshape(1, -1)
        prediction = model.predict(input_data)[0]
        result = "Phishing ⚠️" if prediction == 1 else "Legitimate ✅"
    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
