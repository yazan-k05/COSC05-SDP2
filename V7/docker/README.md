# LLM-Empowered Vehicular IDS - Implementation Phase



## Project Overview
This is the implementation of our Senior Design Project: LLM-based Intrusion Detection System for vehicular networks with hierarchical Federated Learning.

## Current Status
Phase 1 Complete: Basic vehicle-to-fog communication working
- Normal traffic transmission
- Attack simulation (DDoS, GPS Spoofing)
- Web-based control panel

## Setup Instructions

### Prerequisites
- Python 3.8 or higher
- 2 laptops on same WiFi network

### Installation Steps

#### 1. Download Project
Download all files from OneDrive to a folder called `vehicular-ids-network`

#### 2. Create Virtual Environment
```bash
# Windows:
cd vehicular-ids-network
python -m venv venv
venv\Scripts\activate

# macOS/Linux:
cd vehicular-ids-network
python3 -m venv venv
source venv/bin/activate
```

#### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

#### 4. Configure IP Addresses

**Important:** Update the fog server IP in `web_vehicle_client.py`

Edit line 13:
```python
FOG_SERVER_URL = "http://192.168.1.100:8080"  # Change to your fog server IP
```

### Running the System

#### On Fog Server (Laptop 1):
```bash
cd vehicular-ids-network
venv\Scripts\activate  # Windows
# or: source venv/bin/activate  # macOS

python fog_server_flask.py
```

Server will start on: `http://0.0.0.0:8080`

#### On Vehicle Client (Laptop 2):
```bash
cd vehicular-ids-network
venv\Scripts\activate

python web_vehicle_client.py
```

Web interface: `http://localhost:5000`

### Using the Web Interface

1. Open browser: `http://localhost:5000` (or use Laptop 2 IP from any device)
2. Click "Send Single Packet" to send normal traffic
3. Click "Launch DDoS Attack" to simulate attack
4. Click "Launch GPS Spoofing" to simulate GPS attack
5. Watch Laptop 1 terminal for colored detection messages

### Troubleshooting

**Issue: Can't connect between laptops**
- Make sure both on same WiFi
- Check Windows Firewall allows ports 8080 and 5000
- Verify IP addresses with `ipconfig` (Windows) or `ifconfig` (macOS)

**Issue: Template not found**
- Make sure `templates` folder exists
- `control_panel.html` must be inside `templates/`

**Issue: Module not found**
- Activate virtual environment first
- Run `pip install -r requirements.txt`

## File Descriptions

| File | Purpose |
|------|---------|
| `fog_server_flask.py` | Fog node server (Laptop 1) - receives telemetry |
| `web_vehicle_client.py` | Vehicle client with web UI (Laptop 2) |
| `templates/control_panel.html` | Web-based control panel interface |
| `requirements.txt` | Python package dependencies |

## Network Configuration
```
Laptop 1 (Fog Server)          Laptop 2 (Vehicle Client)
Port: 8080                     Port: 5000 (web UI)
Role: Receives data            Role: Sends data
```

## Next Steps
- [ ] Add LLM integration (Phi-2 model)
- [ ] Implement second fog server for FL
- [ ] Add federated learning synchronization
- [ ] Integrate differential privacy

