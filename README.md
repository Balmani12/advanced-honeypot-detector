## ⚠️ Disclaimer

This tool is intended for **educational purposes and authorized security testing only**.
Only scan systems you own or have explicit written permission to test.
The author is not responsible for any misuse.

---

## 📂 Project Structure

advanced-honeypot-detector/
├── ad_honeypot_detect.py      # Main detection script
├── signatures_grouped.json    # Honeypot signature database
├── README.md                  # This file
└── .gitignore

`cache/`, `logs/` and `reports/` are created automatically at runtime and are git-ignored.

---

## 📥 Installation

```bash
git clone https://github.com/Balmani12/advanced-honeypot-detector.git
cd advanced-honeypot-detector
```

## ▶️ Usage

```bash
python3 ad_honeypot_detect.py --help
```
