# 🧪 VirusTotal URL Sandbox

A simple Python tool that checks if a URL may contain malware using the [VirusTotal API](https://www.virustotal.com/gui/home/upload).

## 🚀 Features
- Submits a URL to VirusTotal for scanning  
- Returns detection stats (malicious, suspicious, harmless)  
- Uses the official VirusTotal REST API v3  

## ⚙️ Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/Elybk/vt-url-sandbox.git
   cd vt-url-sandbox
Install dependencies:

bash
Copy code
pip install -r requirements.txt
Create a .env file and add your VirusTotal API key:

ini
Copy code
VIRUSTOTAL_API_KEY=your_api_key_here
Run the script:

bash
Copy code
python main.py
🔒 Security Notes
Never commit your .env file (it contains your API key).

Respect VirusTotal’s usage limits and terms of service.

For testing, you can sign up for a free API key at https://www.virustotal.com/gui/join-us.

📄 License
MIT License

yaml
Copy code

Commit your changes.

---

## 🧠 Step 4 — Add a `.env` file locally (optional test)
If you want to test it on your own computer later:

```bash
git clone https://github.com/YOUR-USERNAME/vt-url-sandbox.git
cd vt-url-sandbox
pip install -r requirements.txt
echo "VIRUSTOTAL_API_KEY=your_api_key_here" > .env
python main.py
