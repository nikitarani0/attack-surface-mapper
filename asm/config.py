import os
from dotenv import load_dotenv

load_dotenv()  # reads .env from project root into environment

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
