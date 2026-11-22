import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from waitress import serve
from app import app

HOST = "0.0.0.0"
PORT = 5000

print("[IoCManager v1.12.1] http://{}:{} uzerinde baslatiliyor...".format(HOST, PORT))
serve(app, host=HOST, port=PORT, threads=4)
