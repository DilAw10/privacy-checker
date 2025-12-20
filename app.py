from flask import Flask, render_template, request
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form.get("url")
        try:
            # Fetch the website HTML
            response = requests.get(url, timeout=5)
            response.raise_for_status()  # Raise error for bad status codes

            # Parse HTML with BeautifulSoup
            soup = BeautifulSoup(response.text, "html.parser")

            # Just show the first 500 characters for now
            preview = soup.get_text()[:500]

            return render_template("result.html", url=url, preview=preview)

        except Exception as e:
            return f"Error fetching {url}: {e}"

    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)

