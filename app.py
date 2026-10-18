from flask import Flask, render_template
from flask_socketio import SocketIO
import time

# TODO: Uncomment when capture.py is fully integrated
# from devflow.capture import CaptureEngine

app = Flask(__name__)
app.config['SECRET_KEY'] = 'devflow_secret'
socketio = SocketIO(app, cors_allowed_origins="*")

@app.route('/')
def index():
    return render_template('index.html')

def run_dummy_emitter():
    """Temporary data stream for Teammate 2 to build the UI against."""
    while True:
        time.sleep(3)
        data = {
            "type": "HTTP Request",
            "connection": "127.0.0.1:34512 -> 127.0.0.1:8080",
            "payload": "GET / HTTP/1.1",
            "latency": None
        }
        socketio.emit('network_event', data)

if __name__ == '__main__':
    # Start the dummy task
    socketio.start_background_task(run_dummy_emitter)
    
    # TODO: Once devflow is ready, swap the dummy task for the real engine:
    # engine = CaptureEngine(socketio=socketio, interface="lo")
    # socketio.start_background_task(engine.start)

    print("[*] Starting Flask-SocketIO server on http://127.0.0.1:5000")
    socketio.run(app, host='127.0.0.1', port=5000, allow_unsafe_werkzeug=True)