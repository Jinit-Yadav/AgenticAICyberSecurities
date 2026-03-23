"""
Alert Agent for CyberShield AI
Handles alert generation, queuing, and multi-channel delivery.
"""

import os
import json
import smtplib
import logging
import threading
import queue
import hashlib
import sqlite3
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional
from contextlib import contextmanager
from dataclasses import dataclass, field

# =============================================================================
# CONFIGURATION
# =============================================================================
@dataclass
class AlertConfig:
    smtp_server: str = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
    smtp_port: int = int(os.getenv('SMTP_PORT', '587'))
    email_sender: str = os.getenv('EMAIL_SENDER', '')
    email_password: str = os.getenv('EMAIL_PASSWORD', '')
    email_recipients: List[str] = field(default_factory=lambda: os.getenv('EMAIL_RECIPIENTS', '').split(',') if os.getenv('EMAIL_RECIPIENTS') else [])
    slack_webhook: str = os.getenv('SLACK_WEBHOOK', '')
    discord_webhook: str = os.getenv('DISCORD_WEBHOOK', '')
    min_severity_for_alert: str = os.getenv('MIN_SEVERITY_FOR_ALERT', 'medium')
    min_confidence_for_alert: float = float(os.getenv('MIN_CONFIDENCE_FOR_ALERT', '0.6'))

# =============================================================================
# DATABASE SETUP
# =============================================================================
@contextmanager
def get_alert_db_connection():
    conn = sqlite3.connect('alerts.db')
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_alert_db():
    with get_alert_db_connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                source_ip TEXT,
                target_ip TEXT,
                tool TEXT,
                attack_type TEXT,
                description TEXT,
                confidence REAL,
                risk_score INTEGER,
                channels_used TEXT,
                acknowledged INTEGER DEFAULT 0,
                acknowledged_by TEXT,
                acknowledged_at TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        logging.getLogger(__name__).info("Alert database initialized")

# =============================================================================
# ALERT AGENT CLASS
# =============================================================================
class AlertAgent:
    def __init__(self, config: AlertConfig = None):
        self.config = config or AlertConfig()
        self.alert_queue = queue.Queue()
        self.is_running = False
        self.alert_thread = None
        self.logger = logging.getLogger(__name__)
        self.severity_scores = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        init_alert_db()
        self.logger.info(f"Alert Agent initialized (email: {bool(self.config.email_sender)}, slack: {bool(self.config.slack_webhook)})")

    def generate_alert(self, detection_result: Dict, multi_expert_analysis: Dict = None) -> Optional[Dict]:
        """Create an alert from detection result."""
        severity = detection_result.get('severity', 'medium')
        confidence = detection_result.get('final_confidence', 0.5)

        # Threshold check
        min_severity_score = self.severity_scores.get(self.config.min_severity_for_alert, 2)
        if (self.severity_scores.get(severity, 0) < min_severity_score or confidence < self.config.min_confidence_for_alert):
            self.logger.debug(f"Alert suppressed (severity={severity}, confidence={confidence})")
            return None

        alert_id = self._generate_alert_id(detection_result)
        alert = {
            'alert_id': alert_id,
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'alert_type': 'threat_detection',
            'source_ip': detection_result.get('source_ip', 'unknown'),
            'target_ip': detection_result.get('target_ip', 'unknown'),
            'target_port': detection_result.get('target_port', 'unknown'),
            'tool': detection_result.get('tool', 'unknown'),
            'attack_type': detection_result.get('attack_type', 'unknown'),
            'description': detection_result.get('description', 'No description'),
            'confidence': confidence,
            'risk_score': detection_result.get('risk_score', 50),
            'detection_methods': detection_result.get('detection_methods', []),
            'recommendations': detection_result.get('recommendations', []),
            'channels_used': [],
            'acknowledged': False
        }

        if multi_expert_analysis:
            alert['multi_expert_analysis'] = {
                'used': multi_expert_analysis.get('multi_expert_analysis_used', False),
                'expert_count': multi_expert_analysis.get('expert_count', 0),
                'consensus_score': multi_expert_analysis.get('consensus_score', 0),
                'analysis': multi_expert_analysis.get('multi_expert_analysis', {})
            }

        self._store_alert(alert)
        self.logger.info(f"Alert generated: {alert_id} ({severity}) - {alert['attack_type']}")
        return alert

    def queue_alert(self, alert: Dict):
        """Add alert to background processing queue."""
        if alert:
            self.alert_queue.put(alert)
            self.logger.debug(f"Alert {alert['alert_id']} queued")

    def start(self):
        """Start background alert processor thread."""
        self.is_running = True
        self.alert_thread = threading.Thread(target=self._process_queue, daemon=True)
        self.alert_thread.start()
        self.logger.info("Alert processor started")

    def stop(self):
        """Stop background alert processor."""
        self.is_running = False
        if self.alert_thread:
            self.alert_thread.join(timeout=5)
        self.logger.info("Alert processor stopped")

    def deliver_alert(self, alert: Dict, channels: List[str] = None) -> Dict:
        """Deliver alert via specified channels."""
        if not channels:
            channels = ['log']
            if self.config.email_recipients and self.config.email_sender and self.config.email_password:
                channels.append('email')
            if self.config.slack_webhook:
                channels.append('slack')
            if self.config.discord_webhook:
                channels.append('discord')

        results = {}
        for ch in channels:
            try:
                if ch == 'email':
                    results['email'] = self._send_email(alert)
                elif ch == 'slack':
                    results['slack'] = self._send_slack(alert)
                elif ch == 'discord':
                    results['discord'] = self._send_discord(alert)
                elif ch == 'log':
                    results['log'] = self._log_alert(alert)
                if ch not in alert['channels_used']:
                    alert['channels_used'].append(ch)
                if results.get(ch):
                    self.logger.info(f"Alert {alert['alert_id']} delivered via {ch}")
            except Exception as e:
                self.logger.error(f"Failed to deliver via {ch}: {e}")
                results[ch] = False

        self._update_alert_channels(alert)
        return results

    def _process_queue(self):
        while self.is_running:
            try:
                alert = self.alert_queue.get(timeout=1)
                if alert:
                    self.deliver_alert(alert)
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Alert processor error: {e}")

    def _generate_alert_id(self, detection: Dict) -> str:
        base = f"{detection.get('source_ip', '')}_{detection.get('attack_type', '')}_{datetime.now().timestamp()}"
        return f"ALT-{hashlib.md5(base.encode()).hexdigest()[:8].upper()}"

    def _store_alert(self, alert: Dict):
        with get_alert_db_connection() as conn:
            conn.execute('''
                INSERT INTO alerts
                (alert_id, timestamp, severity, alert_type, source_ip, target_ip,
                 tool, attack_type, description, confidence, risk_score, channels_used)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert['alert_id'], alert['timestamp'], alert['severity'], alert['alert_type'],
                alert['source_ip'], alert['target_ip'], alert['tool'], alert['attack_type'],
                alert['description'], alert['confidence'], alert['risk_score'],
                json.dumps(alert.get('channels_used', []))
            ))
            conn.commit()

    def _update_alert_channels(self, alert: Dict):
        with get_alert_db_connection() as conn:
            conn.execute('UPDATE alerts SET channels_used = ? WHERE alert_id = ?',
                         (json.dumps(alert.get('channels_used', [])), alert['alert_id']))
            conn.commit()

    def _send_email(self, alert: Dict) -> bool:
        if not self.config.email_sender or not self.config.email_password:
            return False
        try:
            msg = MIMEMultipart()
            msg['From'] = self.config.email_sender
            msg['To'] = ', '.join(self.config.email_recipients)
            msg['Subject'] = f"[CyberShield AI] {alert['severity'].upper()} Alert: {alert['attack_type']}"
            body = self._format_email_body(alert)
            msg.attach(MIMEText(body, 'html'))

            server = smtplib.SMTP(self.config.smtp_server, self.config.smtp_port)
            server.starttls()
            server.login(self.config.email_sender, self.config.email_password)
            server.send_message(msg)
            server.quit()
            return True
        except Exception as e:
            self.logger.error(f"Email failed: {e}")
            return False

    def _format_email_body(self, alert: Dict) -> str:
        colors = {'low': '#3498db', 'medium': '#f39c12', 'high': '#e67e22', 'critical': '#e74c3c'}
        color = colors.get(alert['severity'], '#3498db')
        recs = ''.join(f'<li>{r}</li>' for r in alert.get('recommendations', []))
        return f'''
        <html><body>
        <div style="background:{color};color:white;padding:20px;">
            <h1>CyberShield AI Alert</h1>
            <h2>{alert['severity'].upper()} THREAT</h2>
        </div>
        <div style="padding:20px;">
            <table style="width:100%">
                <tr><td><strong>Alert ID:</strong></td><td>{alert['alert_id']}</td></tr>
                <tr><td><strong>Time:</strong></td><td>{alert['timestamp']}</td></tr>
                <tr><td><strong>Attack:</strong></td><td>{alert['attack_type']}</td></tr>
                <tr><td><strong>Tool:</strong></td><td>{alert['tool']}</td></tr>
                <tr><td><strong>Source IP:</strong></td><td>{alert['source_ip']}</td></tr>
                <tr><td><strong>Target:</strong></td><td>{alert['target_ip']}:{alert.get('target_port', 'unknown')}</td></tr>
                <tr><td><strong>Confidence:</strong></td><td>{alert['confidence']*100:.1f}%</td></tr>
                <tr><td><strong>Risk Score:</strong></td><td>{alert['risk_score']}</td></tr>
            </table>
            <p>{alert['description']}</p>
            <h3>Recommendations</h3>
            <ul>{recs}</ul>
        </div>
        </body></html>
        '''

    def _send_slack(self, alert: Dict) -> bool:
        if not self.config.slack_webhook:
            return False
        try:
            import requests
            emoji = {'low': ':large_blue_circle:', 'medium': ':yellow_circle:',
                     'high': ':orange_circle:', 'critical': ':red_circle:'}.get(alert['severity'], ':question:')
            color = {'low': '#3498db', 'medium': '#f39c12', 'high': '#e67e22', 'critical': '#e74c3c'}.get(alert['severity'], '#3498db')
            message = {
                "attachments": [{
                    "color": color,
                    "title": f"{emoji} CyberShield AI: {alert['severity'].upper()} Threat",
                    "fields": [
                        {"title": "Attack", "value": alert['attack_type'], "short": True},
                        {"title": "Tool", "value": alert['tool'], "short": True},
                        {"title": "Source", "value": alert['source_ip'], "short": True},
                        {"title": "Target", "value": f"{alert['target_ip']}:{alert.get('target_port', 'unknown')}", "short": True},
                        {"title": "Confidence", "value": f"{alert['confidence']*100:.1f}%", "short": True},
                        {"title": "Risk", "value": alert['risk_score'], "short": True}
                    ],
                    "footer": f"Alert ID: {alert['alert_id']}",
                    "ts": datetime.now().timestamp()
                }]
            }
            resp = requests.post(self.config.slack_webhook, json=message)
            return resp.status_code == 200
        except Exception as e:
            self.logger.error(f"Slack failed: {e}")
            return False

    def _send_discord(self, alert: Dict) -> bool:
        if not self.config.discord_webhook:
            return False
        try:
            import requests
            color = {'low': 3447003, 'medium': 16776960, 'high': 15105570, 'critical': 15548997}.get(alert['severity'], 3447003)
            message = {
                "embeds": [{
                    "title": f"CyberShield AI: {alert['severity'].upper()} Alert",
                    "color": color,
                    "fields": [
                        {"name": "Attack", "value": alert['attack_type'], "inline": True},
                        {"name": "Tool", "value": alert['tool'], "inline": True},
                        {"name": "Source", "value": alert['source_ip'], "inline": True},
                        {"name": "Target", "value": f"{alert['target_ip']}:{alert.get('target_port', 'unknown')}", "inline": True},
                        {"name": "Confidence", "value": f"{alert['confidence']*100:.1f}%", "inline": True},
                        {"name": "Risk", "value": str(alert['risk_score']), "inline": True}
                    ],
                    "description": alert['description'][:200],
                    "footer": {"text": f"Alert ID: {alert['alert_id']}"},
                    "timestamp": alert['timestamp']
                }]
            }
            resp = requests.post(self.config.discord_webhook, json=message)
            return resp.status_code == 204
        except Exception as e:
            self.logger.error(f"Discord failed: {e}")
            return False

    def _log_alert(self, alert: Dict) -> bool:
        log_entry = {
            'timestamp': alert['timestamp'],
            'severity': alert['severity'],
            'alert_id': alert['alert_id'],
            'attack_type': alert['attack_type'],
            'source_ip': alert['source_ip'],
            'description': alert['description'][:100]
        }
        self.logger.warning(f"[ALERT] {json.dumps(log_entry)}")
        with open('alerts.log', 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
        return True

    def get_alert_history(self, limit: int = 100, severity: str = None) -> List[Dict]:
        with get_alert_db_connection() as conn:
            if severity:
                rows = conn.execute('SELECT * FROM alerts WHERE severity = ? ORDER BY created_at DESC LIMIT ?',
                                   (severity, limit)).fetchall()
            else:
                rows = conn.execute('SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?', (limit,)).fetchall()
            return [dict(row) for row in rows]

    def acknowledge_alert(self, alert_id: str, acknowledged_by: str = 'system') -> bool:
        with get_alert_db_connection() as conn:
            conn.execute('''
                UPDATE alerts SET acknowledged = 1, acknowledged_by = ?, acknowledged_at = ?
                WHERE alert_id = ?
            ''', (acknowledged_by, datetime.now().isoformat(), alert_id))
            conn.commit()
            self.logger.info(f"Alert {alert_id} acknowledged by {acknowledged_by}")
            return True