import os
import sys
import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from src.exception import CustomException
import dill
import re

def load_object(file_path):
    """Load pickle object from file"""
    try:
        with open(file_path, "rb") as file_obj:
            return joblib.load(file_obj)
    except Exception as e:
        raise Exception(f"Error loading object from {file_path}: {e}")
def parse_security_logs(log_file_path, log_type='suricata'):
    """
    Parse different types of security logs
    """
    try:
        if log_type == 'suricata':
            return parse_suricata_logs(log_file_path)
        elif log_type == 'zeek':
            return parse_zeek_logs(log_file_path)
        elif log_type == 'auth':
            return parse_auth_logs(log_file_path)
        else:
            raise ValueError(f"Unsupported log type: {log_type}")
    except Exception as e:
        raise CustomException(e, sys)

def parse_suricata_logs(file_path):
    """Parse Suricata EVE JSON logs"""
    try:
        logs = []
        with open(file_path, 'r') as f:
            for line in f:
                if line.strip():
                    logs.append(json.loads(line.strip()))
        return pd.DataFrame(logs)
    except Exception as e:
        raise CustomException(e, sys)

def parse_auth_logs(file_path):
    """Parse auth.log for authentication events"""
    try:
        logs = []
        auth_patterns = {
            'failed_password': r'Failed password for',
            'successful_login': r'accepted password for',
            'invalid_user': r'Invalid user',
            'breach_attempt': r'POSSIBLE BREAK-IN ATTEMPT'
        }
        
        with open(file_path, 'r') as f:
            for line in f:
                log_entry = {'timestamp': None, 'message': line.strip()}
                # Extract timestamp (simplified)
                timestamp_match = re.search(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
                if timestamp_match:
                    log_entry['timestamp'] = timestamp_match.group(1)
                
                # Classify log type
                for pattern_name, pattern in auth_patterns.items():
                    if re.search(pattern, line):
                        log_entry['type'] = pattern_name
                        break
                else:
                    log_entry['type'] = 'other'
                
                logs.append(log_entry)
        
        return pd.DataFrame(logs)
    except Exception as e:
        raise CustomException(e, sys)

def detect_anomalies(log_data, threshold_config):
    """
    Basic anomaly detection based on thresholds
    """
    try:
        anomalies = []
        
        # Example: Detect brute force attempts
        if 'failed_password' in log_data['type'].value_counts():
            failed_attempts = log_data['type'].value_counts()['failed_password']
            if failed_attempts > threshold_config.get('max_failed_logins', 5):
                anomalies.append({
                    'type': 'brute_force',
                    'severity': 'high',
                    'description': f'Multiple failed login attempts: {failed_attempts}',
                    'timestamp': datetime.now()
                })
        
        # Add more anomaly detection rules
        return anomalies
    except Exception as e:
        raise CustomException(e, sys)

def save_incident_report(file_path, incident_data):
    """Save incident data for analysis"""
    try:
        dir_path = os.path.dirname(file_path)
        os.makedirs(dir_path, exist_ok=True)

        with open(file_path, 'w') as f:
            json.dump(incident_data, f, indent=2, default=str)

    except Exception as e:
        raise CustomException(e, sys)

def load_incident_history(file_path):
    """Load historical incident data"""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        raise CustomException(e, sys)

def format_alert_message(incident, agent_type):
    """Format alert messages for different channels"""
    templates = {
        'sms': f"ALERT {agent_type}: {incident.get('description', 'Security incident detected')}",
        'email': f"""
        Security Alert - {agent_type}
        
        Incident: {incident.get('description', 'Security incident detected')}
        Severity: {incident.get('severity', 'unknown')}
        Timestamp: {incident.get('timestamp', 'N/A')}
        
        Recommended Action: {incident.get('recommended_action', 'Investigate immediately')}
        """,
        'slack': {
            "text": f"🚨 {agent_type} Alert",
            "attachments": [{
                "color": "danger" if incident.get('severity') == 'high' else "warning",
                "fields": [
                    {"title": "Description", "value": incident.get('description', 'N/A')},
                    {"title": "Severity", "value": incident.get('severity', 'N/A')},
                    {"title": "Action", "value": incident.get('recommended_action', 'N/A')}
                ]
            }]
        }
    }
    return templates