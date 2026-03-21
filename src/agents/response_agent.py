"""
Response Agent for CyberShield AI
Executes automated countermeasures against detected threats.
"""

import os
import json
import logging
import subprocess
import platform
import hashlib
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional
from contextlib import contextmanager

# =============================================================================
# DATABASE SETUP
# =============================================================================
@contextmanager
def get_db_connection():
    conn = sqlite3.connect('alerts.db')
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_response_db():
    with get_db_connection() as conn:
        # Responses table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS responses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                response_id TEXT UNIQUE NOT NULL,
                alert_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT,
                success INTEGER,
                error_message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (alert_id) REFERENCES alerts (alert_id)
            )
        ''')
        # Blocked IPs table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                reason TEXT,
                severity TEXT,
                blocked_at TEXT NOT NULL,
                blocked_until TEXT,
                blocked_by TEXT,
                is_active INTEGER DEFAULT 1,
                unblocked_at TEXT,
                unblocked_by TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # Blocked processes table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS blocked_processes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                process_name TEXT NOT NULL,
                process_pid INTEGER,
                reason TEXT,
                severity TEXT,
                action_taken TEXT,
                blocked_at TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()

# =============================================================================
# RESPONSE AGENT CLASS
# =============================================================================
class ResponseAgent:
    def __init__(self, alert_agent, config: dict = None):
        self.alert_agent = alert_agent  # For follow-up alerts
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.blocked_ips = self._load_blocked_ips()
        self.has_admin = self._check_admin()
        init_response_db()
        self.logger.info(f"Response Agent initialized (admin: {self.has_admin})")

    def _check_admin(self) -> bool:
        try:
            if platform.system() == 'Windows':
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except:
            return False

    def _load_blocked_ips(self) -> Dict:
        blocked = {}
        with get_db_connection() as conn:
            rows = conn.execute('SELECT ip_address, blocked_until FROM blocked_ips WHERE is_active = 1').fetchall()
            for r in rows:
                blocked[r['ip_address']] = r['blocked_until']
        return blocked

    def should_respond(self, alert: Dict) -> bool:
        """Determine if automated response should be triggered."""
        severity = alert.get('severity', 'low')
        confidence = alert.get('confidence', 0)
        auto_enabled = self.config.get('auto_block_ips', False)
        severity_level = {'low':1, 'medium':2, 'high':3, 'critical':4}.get(severity, 1)
        min_level = {'low':1, 'medium':2, 'high':3, 'critical':4}.get(self.config.get('min_severity_for_response', 'high'), 3)
        return (severity_level >= min_level and confidence >= self.config.get('min_confidence_for_response', 0.8) and auto_enabled)

    def execute_response(self, alert: Dict) -> Dict:
        """Execute appropriate actions based on alert."""
        if not self.should_respond(alert):
            return {'executed': False, 'reason': 'Below threshold'}

        response_id = self._generate_response_id(alert)
        actions = []
        attack_type = alert.get('attack_type', '').lower()
        source_ip = alert.get('source_ip', '')
        tool = alert.get('tool', '').lower()

        # 1. Block IP (if not localhost)
        if source_ip and source_ip not in ['localhost', '127.0.0.1', 'unknown'] and self.config.get('auto_block_ips'):
            res = self.block_ip(source_ip, alert)
            actions.append(res)

        # 2. Kill suspicious processes (if configured)
        if self.config.get('auto_kill_processes') and ('resource_consumption' in attack_type or tool in ['resource_tool', 'miner']):
            res = self.kill_suspicious_processes(alert)
            if res:
                actions.append(res)

        # 3. Attack-specific responses
        if 'brute' in attack_type or tool == 'hydra':
            res = self._handle_bruteforce(alert)
            actions.append(res)
        elif 'dos' in attack_type or 'ddos' in attack_type or tool == 'hping3':
            res = self._handle_dos(alert)
            actions.append(res)
        elif 'scan' in attack_type or tool == 'nmap':
            res = self._handle_scan(alert)
            actions.append(res)

        response_record = {
            'response_id': response_id,
            'alert_id': alert['alert_id'],
            'timestamp': datetime.now().isoformat(),
            'actions': actions,
            'success': all(a.get('success', False) for a in actions if a)
        }
        self._store_response(response_record)
        self._send_followup_alert(alert, response_record)
        return response_record

    def block_ip(self, ip: str, alert: Dict = None) -> Dict:
        """Block an IP using system firewall."""
        if ip in self.blocked_ips:
            return {'action': 'block_ip', 'target': ip, 'success': True, 'message': 'Already blocked'}

        result = {'action': 'block_ip', 'target': ip, 'timestamp': datetime.now().isoformat(), 'success': False}
        system = platform.system()
        try:
            if system == 'Windows':
                rule_name = f"CyberShield_Block_{ip.replace('.', '_')}"
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                                f'name={rule_name}', 'dir=in', 'action=block', f'remoteip={ip}'],
                               check=True, capture_output=True)
                result['success'] = True
                result['message'] = f"Blocked via Windows Firewall ({rule_name})"
            elif system == 'Linux':
                subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True, capture_output=True)
                result['success'] = True
                result['message'] = "Blocked via iptables"
            elif system == 'Darwin':
                subprocess.run(['sudo', 'pfctl', '-t', 'blocklist', '-T', 'add', ip], check=True, capture_output=True)
                result['success'] = True
                result['message'] = "Blocked via pf"

            if result['success']:
                with get_db_connection() as conn:
                    conn.execute('''
                        INSERT INTO blocked_ips (ip_address, reason, severity, blocked_at, blocked_until, blocked_by)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (ip, alert.get('description','Automated response') if alert else 'Automated',
                          alert.get('severity','high') if alert else 'high',
                          datetime.now().isoformat(),
                          (datetime.now().timestamp() + 86400),  # 24h block
                          'response_agent'))
                    conn.commit()
                self.blocked_ips[ip] = datetime.now().timestamp() + 86400
        except Exception as e:
            result['error'] = str(e)
            result['message'] = f"Failed: {e}"
        return result

    def unblock_ip(self, ip: str) -> bool:
        """Remove IP block from firewall."""
        system = platform.system()
        try:
            if system == 'Windows':
                rule_name = f"CyberShield_Block_{ip.replace('.', '_')}"
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}'],
                               check=True, capture_output=True)
            elif system == 'Linux':
                subprocess.run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], check=True, capture_output=True)
            elif system == 'Darwin':
                subprocess.run(['sudo', 'pfctl', '-t', 'blocklist', '-T', 'delete', ip], check=True, capture_output=True)
            # Update DB
            with get_db_connection() as conn:
                conn.execute('UPDATE blocked_ips SET is_active = 0, unblocked_at = ? WHERE ip_address = ?',
                             (datetime.now().isoformat(), ip))
                conn.commit()
            self.blocked_ips.pop(ip, None)
            return True
        except Exception as e:
            self.logger.error(f"Unblock failed for {ip}: {e}")
            return False

    def kill_suspicious_processes(self, alert: Dict) -> Dict:
        """Terminate processes with high CPU usage or known suspicious names."""
        result = {'action': 'kill_process', 'timestamp': datetime.now().isoformat(), 'success': False, 'killed': []}
        try:
            import psutil
            attack_type = alert.get('attack_type', '').lower()
            if 'resource_consumption' in attack_type or alert.get('tool') == 'resource_tool':
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                    try:
                        if proc.info['cpu_percent'] > 80:
                            p = psutil.Process(proc.info['pid'])
                            p.terminate()
                            p.wait(timeout=3)
                            result['killed'].append({'pid': proc.info['pid'], 'name': proc.info['name']})
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            result['success'] = len(result['killed']) > 0
            result['message'] = f"Killed {len(result['killed'])} processes"
            # Record in DB
            if result['killed']:
                with get_db_connection() as conn:
                    for k in result['killed']:
                        conn.execute('''
                            INSERT INTO blocked_processes (process_name, process_pid, reason, severity, action_taken, blocked_at)
                            VALUES (?, ?, ?, ?, ?, ?)
                        ''', (k['name'], k['pid'], alert.get('description','Resource consumption'),
                              alert.get('severity','high'), 'terminated', datetime.now().isoformat()))
                    conn.commit()
        except Exception as e:
            result['error'] = str(e)
            result['message'] = f"Failed: {e}"
        return result

    def _handle_bruteforce(self, alert: Dict) -> Dict:
        result = {'action': 'bruteforce_response', 'timestamp': datetime.now().isoformat(), 'success': False}
        ip = alert.get('source_ip')
        port = alert.get('target_port')
        if ip:
            block = self.block_ip(ip, alert)
            if port == 22:
                self._rate_limit_ssh(ip)
            elif port == 21:
                self._rate_limit_ftp(ip)
            result['success'] = block.get('success', False)
            result['message'] = f"Applied brute force countermeasures for {ip}"
        return result

    def _handle_dos(self, alert: Dict) -> Dict:
        result = {'action': 'dos_response', 'timestamp': datetime.now().isoformat(), 'success': False}
        ip = alert.get('source_ip')
        port = alert.get('target_port')
        if ip:
            self.block_ip(ip, alert)
            self._apply_rate_limit(ip, port)
            result['success'] = True
            result['message'] = f"Applied DoS countermeasures for {ip}"
        return result

    def _handle_scan(self, alert: Dict) -> Dict:
        result = {'action': 'scan_response', 'timestamp': datetime.now().isoformat(), 'success': False}
        ip = alert.get('source_ip')
        if ip:
            self.block_ip(ip, alert)
            # Also block for 1 hour in DB
            with get_db_connection() as conn:
                conn.execute('''
                    INSERT INTO blocked_ips (ip_address, reason, severity, blocked_at, blocked_until)
                    VALUES (?, ?, ?, ?, ?)
                ''', (ip, 'Port scanning detected', alert.get('severity','medium'),
                      datetime.now().isoformat(), datetime.now().timestamp() + 3600))
                conn.commit()
            result['success'] = True
            result['message'] = f"Blocked scanner {ip}"
        return result

    def _rate_limit_ssh(self, ip: str):
        if platform.system() == 'Linux':
            subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-p', 'tcp', '--dport', '22',
                            '-m', 'limit', '--limit', '1/minute', '--limit-burst', '3', '-j', 'ACCEPT'],
                           check=False)

    def _rate_limit_ftp(self, ip: str):
        if platform.system() == 'Linux':
            subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-p', 'tcp', '--dport', '21',
                            '-m', 'limit', '--limit', '2/minute', '--limit-burst', '5', '-j', 'ACCEPT'],
                           check=False)

    def _apply_rate_limit(self, ip: str, port: int):
        if platform.system() == 'Linux' and port:
            subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-p', 'tcp', '--dport', str(port),
                            '-m', 'limit', '--limit', '10/second', '--limit-burst', '20', '-j', 'ACCEPT'],
                           check=False)

    def _generate_response_id(self, alert: Dict) -> str:
        base = f"RESP_{alert['alert_id']}_{datetime.now().timestamp()}"
        return f"RSP-{hashlib.md5(base.encode()).hexdigest()[:8].upper()}"

    def _store_response(self, response: Dict):
        with get_db_connection() as conn:
            conn.execute('''
                INSERT INTO responses (response_id, alert_id, timestamp, action, status, details, success)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                response['response_id'],
                response['alert_id'],
                response['timestamp'],
                json.dumps([a.get('action') for a in response['actions'] if a]),
                'completed',
                json.dumps(response['actions']),
                1 if response['success'] else 0
            ))
            conn.commit()

    def _send_followup_alert(self, original_alert: Dict, response: Dict):
        """Generate an alert about the automated response."""
        followup = {
            'alert_id': f"RESP-{original_alert['alert_id']}",
            'timestamp': datetime.now().isoformat(),
            'severity': 'medium',
            'alert_type': 'automated_response',
            'source_ip': original_alert.get('source_ip', 'unknown'),
            'attack_type': 'response_executed',
            'description': f"Automated response executed for alert {original_alert['alert_id']}",
            'confidence': 1.0,
            'risk_score': 30,
            'recommendations': ['Review response actions', 'Check if further action needed'],
            'response_details': response
        }
        # Use alert agent to generate and queue this alert
        if self.alert_agent:
            alert_obj = self.alert_agent.generate_alert(followup)
            if alert_obj:
                self.alert_agent.queue_alert(alert_obj)

    def get_blocked_ips(self) -> List[Dict]:
        with get_db_connection() as conn:
            rows = conn.execute('SELECT * FROM blocked_ips WHERE is_active = 1 ORDER BY blocked_at DESC').fetchall()
            return [dict(r) for r in rows]

    def get_response_history(self, alert_id: str = None) -> List[Dict]:
        with get_db_connection() as conn:
            if alert_id:
                rows = conn.execute('SELECT * FROM responses WHERE alert_id = ? ORDER BY created_at DESC', (alert_id,)).fetchall()
            else:
                rows = conn.execute('SELECT * FROM responses ORDER BY created_at DESC LIMIT 100').fetchall()
            return [dict(r) for r in rows]  