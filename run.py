"""
IoCManager - Baslatici (waitress ile).

Windows: NSSM bu dosyayi dogrudan uretim sunucusu olarak calistirir.
Linux:   Uretimde systemd + gunicorn kullanilir (bu dosyaya gerek yok);
         bu script sadece kurulum sonrasi hizli manuel test icindir.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from waitress import serve
from app import app

HOST = "0.0.0.0"
PORT = 5000

if __name__ == "__main__":
    print("[IoCManager] http://{}:{} uzerinde baslatiliyor...".format(HOST, PORT))
    serve(app, host=HOST, port=PORT, threads=4)
