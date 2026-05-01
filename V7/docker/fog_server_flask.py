"""

Flask-based Fog Server
More production-ready with REST API endpoints
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "tiered_xai_ids"))

from flask import Flask, request, jsonify
import datetime
import json
from colorama import Fore, init

try:
    from tiered_xai_ids.shared.fuzzy_trust import TrustRegistry
    _trust = TrustRegistry()
    _FUZZY_AVAILABLE = True
except Exception:
    _trust = None  # type: ignore[assignment]
    _FUZZY_AVAILABLE = False

init(autoreset=True)

app = Flask(__name__)

# Allow the live panel (port 8200) and the attack panel to poll this server
@app.after_request
def _add_cors(response):
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response

# Storage for received data (in-memory for now)
received_data = []

# Fog node own trust state — tracked as a node so attack exposure degrades it
_fog_node_id = "fog-server"
_node_under_attack = False

def _fog_trust_state() -> dict:
    """Return the current fog node trust state (score, label, exposure)."""
    if not _FUZZY_AVAILABLE or _trust is None or _fog_node_id not in _trust._store:
        return {"trust_score": 1.0, "trust_label": "TRUSTED", "attack_exposure": 0.0}
    t = _trust._store[_fog_node_id]
    return {
        "trust_score": t.last_result.trust_score if t.last_result else 0.5,
        "trust_label": t.last_result.trust_label if t.last_result else "UNCERTAIN",
        "attack_exposure": round(t._exposure, 4),
    }

def _is_fog_temporarily_offline() -> bool:
    """True when attack exposure is high enough to simulate the fog node going offline."""
    ts = _fog_trust_state()
    return ts["attack_exposure"] >= 0.70 or ts["trust_label"] == "UNTRUSTED"

@app.route('/', methods=['GET'])
def home():
    """Health check endpoint"""
    ts = _fog_trust_state()
    degraded = ts["trust_label"] in ("UNTRUSTED", "LOW") or ts["attack_exposure"] >= 0.5
    return jsonify({
        'status': 'degraded' if degraded else 'online',
        'service': 'Fog Node Server',
        'timestamp': datetime.datetime.now().isoformat(),
        'total_messages_received': len(received_data),
        'fuzzy_trust': ts,
        'temporarily_offline': _is_fog_temporarily_offline(),
    })

@app.route('/v2x/telemetry', methods=['POST'])
def receive_telemetry():
    """
    Endpoint to receive vehicle telemetry

    Expected JSON format:
    {
        "vehicle_id": "V001",
        "speed": 60,
        "location": [25.2048, 55.2708],
        "heading": 90,
        "timestamp": "2025-02-01T14:30:00",
        "message_type": "BSM" or "ATTACK_DDOS" or "ATTACK_GPS_SPOOF"
    }
    """
    # Fog node is temporarily offline under sustained attack
    if _is_fog_temporarily_offline():
        ts = _fog_trust_state()
        print(f"\n{Fore.RED}⛔ FOG NODE TEMPORARILY OFFLINE (attack_exposure={ts['attack_exposure']:.2f}, trust={ts['trust_label']})")
        return jsonify({
            'status': 'service_unavailable',
            'reason': 'fog_node_temporarily_offline',
            'detail': (
                f"Fog node is under attack. "
                f"Attack exposure: {ts['attack_exposure']*100:.0f}%. "
                f"Trust: {ts['trust_label']}. "
                "Service will resume once attack subsides."
            ),
            'fuzzy_trust': ts,
        }), 503

    try:
        # Get JSON data from request
        vehicle_data = request.get_json()
        
        if not vehicle_data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Add server timestamp and source IP
        vehicle_data['server_timestamp'] = datetime.datetime.now().isoformat()
        vehicle_data['source_ip'] = request.remote_addr
        
        # Store data
        received_data.append(vehicle_data)
        
        # CHECK FOR ATTACK TYPES
        message_type = vehicle_data.get('message_type', 'BSM')
        vehicle_id   = vehicle_data.get('vehicle_id', 'unknown')
        is_attack    = message_type.startswith('ATTACK_')

        global _node_under_attack
        _node_under_attack = is_attack

        if message_type == 'ATTACK_DDOS':
            print(f"\n{Fore.RED}🚨 DDoS ATTACK DETECTED!")
            print(f"   Fake Vehicle ID: {vehicle_id}")
            print(f"   Source IP: {request.remote_addr}")
            print(f"   Speed: {vehicle_data.get('speed')} km/h")

        elif message_type == 'ATTACK_GPS_SPOOF':
            print(f"\n{Fore.YELLOW}⚠️  GPS SPOOFING DETECTED!")
            print(f"   Vehicle: {vehicle_id}")
            print(f"   Suspicious Location: {vehicle_data.get('location')}")
            print(f"   Source IP: {request.remote_addr}")

        else:
            # Normal traffic (BSM)
            print(f"\n{Fore.GREEN}🚗 Telemetry received from {request.remote_addr}")
            print(f"   Vehicle ID: {vehicle_id}")
            print(f"   Speed: {vehicle_data.get('speed')} km/h")
            print(f"   Location: {vehicle_data.get('location')}")

        # Basic anomaly detection
        anomalies = detect_anomalies(vehicle_data)
        anomaly_ratio = min(1.0, len(anomalies) / max(1, 3))
        confidence    = 0.30 if is_attack else 0.80

        # Fuzzy trust scoring
        vehicle_trust = None
        fog_trust     = None
        if _FUZZY_AVAILABLE and _trust is not None:
            v_result = _trust.update_vehicle(
                vehicle_id,
                confidence=confidence,
                anomaly_score=anomaly_ratio if not is_attack else max(0.7, anomaly_ratio),
                is_suspicious=is_attack,
                delivered=True,
            )
            f_result = _trust.update_node(
                _fog_node_id, "fog_node",
                under_attack=_node_under_attack,
                delivered=True,
            )
            vehicle_trust = {
                "entity_id": vehicle_id,
                "trust_score": v_result.trust_score,
                "trust_label": v_result.trust_label,
            }
            fog_trust = {
                "entity_id": _fog_node_id,
                "trust_score": f_result.trust_score,
                "trust_label": f_result.trust_label,
                "attack_exposure": _trust._store[_fog_node_id]._exposure if _fog_node_id in _trust._store else 0.0,
            }

        # Prepare response
        response = {
            'status': 'success',
            'message': 'Telemetry received',
            'timestamp': vehicle_data['server_timestamp'],
            'anomalies_detected': len(anomalies) > 0,
            'anomalies': anomalies,
        }
        if vehicle_trust:
            response['vehicle_trust'] = vehicle_trust
        if fog_trust:
            response['fog_node_trust'] = fog_trust
        
        return jsonify(response), 200
        
    except Exception as e:
        print(f"{Fore.RED}✗ Error processing telemetry: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/v2x/attack', methods=['POST'])
def receive_attack():
    """
    Endpoint for simulated attack data
    Used for testing attack detection
    """
    global _node_under_attack
    try:
        attack_data = request.get_json() or {}
        attack_data['server_timestamp'] = datetime.datetime.now().isoformat()
        attack_data['source_ip'] = request.remote_addr
        _node_under_attack = True

        print(f"\n{Fore.RED}🚨 ATTACK DATA RECEIVED")
        print(f"   Type: {attack_data.get('attack_type')}")
        print(f"   Source: {request.remote_addr}")
        print(f"   Details: {attack_data.get('details')}")

        fog_trust = None
        if _FUZZY_AVAILABLE and _trust is not None:
            f_result = _trust.update_node(
                _fog_node_id, "fog_node",
                under_attack=True,
                delivered=True,
                anomaly_score=0.85,
            )
            fog_trust = {
                "trust_score": f_result.trust_score,
                "trust_label": f_result.trust_label,
            }

        resp = {
            'status': 'attack_logged',
            'timestamp': attack_data['server_timestamp'],
        }
        if fog_trust:
            resp['fog_node_trust'] = fog_trust
        return jsonify(resp), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/fuzzy/trust', methods=['GET'])
def fuzzy_trust():
    """Return current fuzzy trust state for all tracked vehicles and this fog node."""
    if not _FUZZY_AVAILABLE or _trust is None:
        return jsonify({'error': 'fuzzy_trust module not available'}), 503
    nodes = _trust.all_nodes()
    # Annotate each node with its live temporarily_offline flag
    ts = _fog_trust_state()
    for n in nodes:
        if n.get("entity_id") == _fog_node_id:
            n["temporarily_offline"] = _is_fog_temporarily_offline()
            n["attack_exposure"] = ts["attack_exposure"]
    return jsonify({
        'fog_node': nodes,
        'vehicles': _trust.all_vehicles(),
        'temporarily_offline': _is_fog_temporarily_offline(),
        'timestamp': datetime.datetime.now().isoformat(),
    }), 200

@app.route('/stats', methods=['GET'])
def get_stats():
    """Get server statistics"""
    if not received_data:
        return jsonify({'message': 'No data received yet'}), 200
    
    # Calculate statistics
    speeds = [d.get('speed', 0) for d in received_data]
    
    stats = {
        'total_messages': len(received_data),
        'unique_vehicles': len(set(d.get('vehicle_id') for d in received_data)),
        'average_speed': sum(speeds) / len(speeds) if speeds else 0,
        'max_speed': max(speeds) if speeds else 0,
        'min_speed': min(speeds) if speeds else 0,
        'last_update': received_data[-1].get('server_timestamp')
    }
    
    return jsonify(stats), 200

def detect_anomalies(data):
    """
    Basic anomaly detection
    Returns list of detected anomalies
    """
    anomalies = []
    
    speed = data.get('speed', 0)
    if speed > 120:
        anomalies.append({
            'type': 'excessive_speed',
            'severity': 'high',
            'value': speed,
            'threshold': 120
        })
    elif speed < 0:
        anomalies.append({
            'type': 'invalid_speed',
            'severity': 'critical',
            'value': speed
        })
    
    return anomalies

if __name__ == '__main__':
    # Configuration from environment variables
    FOG_HOST = os.getenv('FOG_SERVER_HOST', '0.0.0.0')
    FOG_PORT = int(os.getenv('FOG_SERVER_PORT', '8080'))
    DEBUG = os.getenv('FLASK_ENV', 'development') == 'development'
    
    print(f"{Fore.MAGENTA}{'='*60}")
    print(f"{Fore.MAGENTA}       FLASK FOG NODE SERVER")
    print(f"{Fore.MAGENTA}{'='*60}\n")
    
    # Run server
    # host='0.0.0.0' allows connections from any IP
    # debug=True for development (disable in production)
    app.run(host=FOG_HOST, port=FOG_PORT, debug=DEBUG)