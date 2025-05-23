from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import pandas as pd
import threading
import os
from packet_sniffer import start_sniffer

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Replace with a secure key for session management

# Global variable for the dynamic threshold
anomaly_threshold = 1500

# Ensure the data directory and file exist
os.makedirs("data", exist_ok=True)
if not os.path.exists("data/traffic_data.csv"):
    with open("data/traffic_data.csv", "w") as f:
        f.write("timestamp,src_ip,dst_ip,protocol,packet_size\n")


@app.route('/')
def index():
    """Redirect to login or dashboard based on session."""
    app.logger.debug(f"Index route accessed. Session content: {session}")  # Debugging log
    if "user" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    app.logger.debug(f"Login route accessed. Session content: {session}")  # Debugging log
    if "user" in session:
        return redirect(url_for("dashboard"))  # Redirect if already logged in

    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Validate credentials
        if username == "admin" and password == "password":  # Replace with secure validation
            session["user"] = username
            app.logger.debug(f"User {username} logged in successfully.")  # Debugging log
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid Username or Password"
            app.logger.debug("Invalid login attempt.")  # Debugging log

    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    """Log the user out and clear the session."""
    app.logger.debug(f"Logout route accessed. Clearing session: {session}")  # Debugging log
    session.clear()  # Completely clear session
    return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    """Display the dashboard if the user is logged in."""
    app.logger.debug(f"Dashboard route accessed. Session content: {session}")  # Debugging log
    if "user" not in session:  # Ensure the user is logged in
        app.logger.debug("Unauthorized access to dashboard. Redirecting to login.")  # Debugging log
        return redirect(url_for("login"))
    return render_template('index.html')


@app.route('/get_packets')
def get_packets():
    """Fetch the latest packets from the CSV file."""
    data = pd.read_csv("data/traffic_data.csv", header=None, names=["timestamp", "src_ip", "dst_ip", "protocol", "packet_size"])
    return data.tail(20).to_json(orient='records')


@app.route('/get_alerts')
def get_alerts():
    """Fetch alerts based on anomalies detected."""
    data = pd.read_csv("data/traffic_data.csv", header=None, names=["timestamp", "src_ip", "dst_ip", "protocol", "packet_size"])
    alerts = detect_anomalies(data)
    return jsonify(alerts)


@app.route('/get_traffic_stats')
def get_traffic_stats():
    """Fetch traffic statistics for visualization."""
    data = pd.read_csv("data/traffic_data.csv", header=None, names=["timestamp", "src_ip", "dst_ip", "protocol", "packet_size"])
    stats = {
        "timestamps": data["timestamp"].tolist(),
        "sizes": data["packet_size"].tolist()
    }
    return jsonify(stats)


@app.route('/set_threshold', methods=['POST'])
def set_threshold():
    """Set a new anomaly detection threshold."""
    global anomaly_threshold
    threshold = request.json.get("threshold")
    if threshold:
        anomaly_threshold = int(threshold)
        app.logger.debug(f"Threshold updated to: {anomaly_threshold}")  # Debugging log
        return jsonify({"status": "success", "threshold": anomaly_threshold})
    return jsonify({"status": "error", "message": "Invalid threshold value"}), 400



@app.route('/get_threshold')
def get_threshold():
    """Return the current anomaly detection threshold."""
    return jsonify({"threshold": anomaly_threshold})

def detect_anomalies(data):
    """Detect anomalies based on the dynamic threshold."""
    global anomaly_threshold
    alerts = []
    for _, row in data.iterrows():
        if row['packet_size'] > anomaly_threshold:
            alerts.append(f"Large packet detected: {row['src_ip']} -> {row['dst_ip']} (Size: {row['packet_size']})")
    return alerts


if __name__ == "__main__":
    # Start the packet sniffer in a separate thread
    sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
    sniffer_thread.start()

    # Run the Flask application
    app.run(debug=True)