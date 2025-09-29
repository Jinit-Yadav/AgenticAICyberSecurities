import os
import sys
import pandas as pd
import numpy as np
import json
from datetime import datetime
from dataclasses import dataclass
import glob

# Fix import paths
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(current_dir))
sys.path.append(project_root)

try:
    from src.logger import logging
    from src.exception import CustomException
except ImportError:
    from logger import logging
    from exception import CustomException

@dataclass
class AttackLogsConfig:
    """
    Configuration for real attack tool logs
    """
    # Your friend's attack logs directories
    nmap_logs_dir: str = 'C:/Users/yadav/Downloads/wetransfer_nmap-sv-json_2025-09-25_1525'
    attacks_log_dir: str = 'C:/Users/yadav/Downloads/Attacks log'
    
    # Output paths
    raw_attack_logs_path: str = os.path.join('artifacts', 'raw_attack_logs.csv')
    processed_attack_data_path: str = os.path.join('artifacts', 'processed_attack_data.csv')
    attack_catalog_path: str = os.path.join('artifacts', 'attack_catalog.json')
    
    def __post_init__(self):
        # Create artifacts directory if it doesn't exist
        os.makedirs('artifacts', exist_ok=True)

class AttackLogParser:
    """
    Parser for various security tool JSON logs with improved parsing
    """
    
    def __init__(self):
        self.tool_patterns = {
            'nmap': self._parse_nmap_logs,
            'gobuster': self._parse_gobuster_logs,
            'hping3': self._parse_hping3_logs,
            'hydra': self._parse_hydra_logs,
            'nikto': self._parse_nikto_logs,
            'smb': self._parse_smb_logs,
            'ftp_bruteforce': self._parse_ftp_bruteforce_logs
        }
    
    def parse_attack_logs(self, directory_path):
        """
        Parse all attack logs from a directory
        """
        all_attack_logs = []
        
        if not os.path.exists(directory_path):
            logging.warning(f"Directory not found: {directory_path}")
            return pd.DataFrame()
        
        # Process all JSON files in the directory
        json_files = glob.glob(os.path.join(directory_path, "*.json"))
        
        print(f"🔍 Found {len(json_files)} JSON files in {directory_path}")
        
        for json_file in json_files:
            tool_name = self._identify_tool(json_file)
            file_size = os.path.getsize(json_file)
            print(f"🔧 Parsing {tool_name} logs: {os.path.basename(json_file)} ({file_size:,} bytes)")
            
            try:
                tool_logs = self._parse_single_file(json_file, tool_name)
                if not tool_logs.empty:
                    all_attack_logs.append(tool_logs)
                    print(f"✅ Parsed {len(tool_logs):,} records from {tool_name}")
                else:
                    print(f"⚠️  No records parsed from {json_file}")
            except Exception as e:
                print(f"❌ Failed to parse {json_file}: {e}")
        
        if all_attack_logs:
            combined_df = pd.concat(all_attack_logs, ignore_index=True)
            print(f"🎯 Combined {len(combined_df):,} records from {len(all_attack_logs)} files")
            return combined_df
        
        print(f"❌ No data parsed from directory: {directory_path}")
        return pd.DataFrame()
    
    def _identify_tool(self, file_path):
        """
        Identify the security tool from filename
        """
        filename = os.path.basename(file_path).lower()
        
        if 'nmap' in filename:
            return 'nmap'
        elif 'gobuster' in filename:
            return 'gobuster'
        elif 'hping' in filename:
            return 'hping3'
        elif 'hydra' in filename:
            return 'hydra'
        elif 'nikto' in filename:
            return 'nikto'
        elif 'smb' in filename:
            return 'smb'
        elif 'ftp' in filename or 'bruteforce' in filename:
            return 'ftp_bruteforce'
        else:
            return 'unknown'
    
    def _parse_single_file(self, file_path, tool_name):
        """
        Parse a single JSON log file - handles NDJSON format with better error handling
        """
        try:
            print(f"📖 Reading NDJSON file: {file_path}")
            logs = []
            line_count = 0
            parsed_count = 0
            error_count = 0
            
            with open(file_path, 'r', encoding='utf-8') as file:
                for line_num, line in enumerate(file, 1):
                    line = line.strip()
                    if not line:  # Skip empty lines
                        continue
                    
                    line_count += 1
                    
                    try:
                        data = json.loads(line)
                        
                        # DEBUG: Show first few records to understand structure
                        if line_count <= 3:
                            print(f"   🔍 Sample line {line_count}: {list(data.keys()) if isinstance(data, dict) else type(data)}")
                        
                        # Try to parse with tool-specific parser
                        parsed_logs = pd.DataFrame()
                        if tool_name in self.tool_patterns:
                            parsed_logs = self.tool_patterns[tool_name](data, file_path)
                        
                        # If tool-specific parser didn't work, try generic
                        if parsed_logs.empty:
                            parsed_logs = self._parse_generic_json(data, file_path, tool_name)
                        
                        if not parsed_logs.empty:
                            logs.append(parsed_logs)
                            parsed_count += len(parsed_logs)
                            
                    except json.JSONDecodeError as e:
                        error_count += 1
                        if error_count <= 3:  # Only show first few errors
                            print(f"   ⚠️  Line {line_num}: JSON decode error - {e}")
                        continue
                    except Exception as e:
                        error_count += 1
                        if error_count <= 3:
                            print(f"   ⚠️  Line {line_num}: Unexpected error - {e}")
                        continue
                    
                    # Show progress for large files
                    if line_count % 10000 == 0:
                        print(f"   📊 Processed {line_count:,} lines, parsed {parsed_count:,} records, errors: {error_count}")
            
            print(f"   ✅ Finished: {line_count:,} total lines, {parsed_count:,} parsed records, {error_count} errors")
            
            if logs:
                return pd.concat(logs, ignore_index=True)
            else:
                return pd.DataFrame()
                
        except Exception as e:
            print(f"❌ Error parsing {file_path}: {e}")
            return pd.DataFrame()

    def _parse_nmap_logs(self, data, file_path):
        """
        Parse Nmap scan logs from Suricata EVE format
        """
        logs = []
        filename = os.path.basename(file_path).lower()
        
        # Extract from Suricata EVE format
        if 'event_type' in data or 'src_ip' in data:
            log_entry = {
                'timestamp': data.get('timestamp', datetime.now().isoformat()),
                'tool': 'nmap',
                'scan_type': self._get_nmap_scan_type(filename),
                'source_ip': data.get('src_ip', 'unknown'),
                'target_ip': data.get('dest_ip', 'unknown'),
                'source_port': data.get('src_port', 'unknown'),
                'target_port': data.get('dest_port', 'unknown'),
                'protocol': data.get('proto', 'unknown'),
                'event_type': data.get('event_type', 'unknown'),
                'flow_id': data.get('flow_id', 'unknown'),
                'attack_category': 'reconnaissance',
                'severity': 'medium',
                'is_threat': 1
            }
            
            # Add Nmap-specific data if available
            if 'nmap' in data:
                nmap_data = data.get('nmap', {})
                log_entry.update({
                    'nmap_command': nmap_data.get('command', 'unknown'),
                    'nmap_scan_type': nmap_data.get('scan_type', 'unknown')
                })
            
            logs.append(log_entry)
        
        return pd.DataFrame(logs)

    def _parse_gobuster_logs(self, data, file_path):
        """
        Parse Gobuster directory brute-forcing logs from Suricata EVE format
        """
        logs = []
        
        # Method 1: Check for HTTP data structure
        if 'http' in data:
            http_data = data.get('http', {})
            log_entry = {
                'timestamp': data.get('timestamp', datetime.now().isoformat()),
                'tool': 'gobuster',
                'source_ip': data.get('src_ip', 'unknown'),
                'target_ip': data.get('dest_ip', 'unknown'),
                'target_url': http_data.get('hostname', 'unknown'),
                'http_method': http_data.get('http_method', 'unknown'),
                'status_code': http_data.get('status', 'unknown'),
                'uri': http_data.get('url', 'unknown'),
                'user_agent': http_data.get('http_user_agent', 'unknown'),
                'attack_category': 'directory_bruteforce',
                'severity': 'medium',
                'is_threat': 1
            }
            logs.append(log_entry)
        
        # Method 2: Check for directory scanning patterns
        elif any(keyword in str(data).lower() for keyword in ['dir', 'directory', 'gobuster', 'brute']):
            log_entry = {
                'timestamp': data.get('timestamp', datetime.now().isoformat()),
                'tool': 'gobuster',
                'source_ip': data.get('src_ip', data.get('source_ip', 'unknown')),
                'target_ip': data.get('dest_ip', data.get('destination_ip', 'unknown')),
                'protocol': data.get('proto', 'http'),
                'event_type': data.get('event_type', 'directory_scan'),
                'attack_category': 'directory_bruteforce',
                'severity': 'medium',
                'is_threat': 1
            }
            logs.append(log_entry)
        
        return pd.DataFrame(logs)

    def _parse_hping3_logs(self, data, file_path):
        """
        Parse Hping3 network testing logs from Suricata EVE format
        """
        logs = []
        filename = os.path.basename(file_path).lower()
        
        scan_type = 'udp_flood' if 'udp' in filename else 'syn_flood'
        
        # Check for network traffic patterns
        if 'src_ip' in data or 'proto' in data:
            log_entry = {
                'timestamp': data.get('timestamp', datetime.now().isoformat()),
                'tool': 'hping3',
                'scan_type': scan_type,
                'source_ip': data.get('src_ip', 'unknown'),
                'target_ip': data.get('dest_ip', 'unknown'),
                'protocol': data.get('proto', 'unknown'),
                'event_type': data.get('event_type', 'unknown'),
                'packet_info': data.get('pkt_src', 'unknown'),
                'attack_category': 'dos_testing',
                'severity': 'high',
                'is_threat': 1
            }
            logs.append(log_entry)
        
        return pd.DataFrame(logs)

    def _parse_hydra_logs(self, data, file_path):
        """
        Parse Hydra brute-force attack logs with improved detection
        """
        logs = []
        filename = os.path.basename(file_path).lower()
        
        service = 'ssh' if 'ssh' in filename else 'ftp'
        
        # Method 1: Check for FTP data structure
        if 'ftp' in data:
            ftp_data = data.get('ftp', {})
            log_entry = {
                'timestamp': data.get('timestamp', datetime.now().isoformat()),
                'tool': 'hydra',
                'service': service,
                'source_ip': data.get('src_ip', 'unknown'),
                'target_ip': data.get('dest_ip', 'unknown'),
                'username': ftp_data.get('command_data', 'unknown') if ftp_data.get('command') == 'USER' else 'unknown',
                'password': ftp_data.get('command_data', 'unknown') if ftp_data.get('command') == 'PASS' else 'unknown',
                'command': ftp_data.get('command', 'unknown'),
                'status': ftp_data.get('reply_received', 'unknown'),
                'attack_category': 'bruteforce',
                'severity': 'high',
                'is_threat': 1
            }
            logs.append(log_entry)
            return pd.DataFrame(logs)
        
        # Method 2: Check for SSH connection attempts
        elif 'ssh' in data:
            ssh_data = data.get('ssh', {})
            log_entry = {
                'timestamp': data.get('timestamp', datetime.now().isoformat()),
                'tool': 'hydra',
                'service': service,
                'source_ip': data.get('src_ip', 'unknown'),
                'target_ip': data.get('dest_ip', 'unknown'),
                'protocol': 'ssh',
                'event_type': data.get('event_type', 'unknown'),
                'attack_category': 'bruteforce',
                'severity': 'high',
                'is_threat': 1
            }
            logs.append(log_entry)
            return pd.DataFrame(logs)
        
        # Method 3: Check for any authentication attempts in generic fields
        elif any(keyword in str(data).lower() for keyword in ['user', 'pass', 'login', 'auth', 'brute']):
            log_entry = {
                'timestamp': data.get('timestamp', datetime.now().isoformat()),
                'tool': 'hydra',
                'service': service,
                'source_ip': data.get('src_ip', data.get('source_ip', 'unknown')),
                'target_ip': data.get('dest_ip', data.get('destination_ip', 'unknown')),
                'protocol': data.get('proto', 'unknown'),
                'event_type': data.get('event_type', 'bruteforce_attempt'),
                'attack_category': 'bruteforce',
                'severity': 'high',
                'is_threat': 1
            }
            logs.append(log_entry)
            return pd.DataFrame(logs)
        
        return pd.DataFrame()

    def _parse_nikto_logs(self, data, file_path):
        """
        Parse Nikto web vulnerability scanner logs with improved detection
        """
        logs = []
        
        # Method 1: Check for HTTP data structure
        if 'http' in data:
            http_data = data.get('http', {})
            log_entry = {
                'timestamp': data.get('timestamp', datetime.now().isoformat()),
                'tool': 'nikto',
                'source_ip': data.get('src_ip', 'unknown'),
                'target_ip': data.get('dest_ip', 'unknown'),
                'target_url': http_data.get('hostname', 'unknown'),
                'uri': http_data.get('url', 'unknown'),
                'user_agent': http_data.get('http_user_agent', 'unknown'),
                'attack_category': 'web_scanning',
                'severity': 'medium',
                'is_threat': 1
            }
            logs.append(log_entry)
            return pd.DataFrame(logs)
        
        # Method 2: Check for web scanning patterns in generic data
        elif any(keyword in str(data).lower() for keyword in ['http', 'https', 'www.', 'url', 'web', 'nikto']):
            log_entry = {
                'timestamp': data.get('timestamp', datetime.now().isoformat()),
                'tool': 'nikto',
                'source_ip': data.get('src_ip', data.get('source_ip', 'unknown')),
                'target_ip': data.get('dest_ip', data.get('destination_ip', 'unknown')),
                'protocol': data.get('proto', 'http'),
                'event_type': data.get('event_type', 'web_scan'),
                'attack_category': 'web_scanning',
                'severity': 'medium',
                'is_threat': 1
            }
            logs.append(log_entry)
            return pd.DataFrame(logs)
        
        return pd.DataFrame()

    def _parse_smb_logs(self, data, file_path):
        """
        Parse SMB scanning and file access logs from Suricata EVE format
        """
        logs = []
        filename = os.path.basename(file_path).lower()
        
        attack_type = 'file_access' if 'fileaccess' in filename else 'scan'
        
        # Check for SMB or network scanning patterns
        if 'smb' in data or 'src_ip' in data:
            log_entry = {
                'timestamp': data.get('timestamp', datetime.now().isoformat()),
                'tool': 'smb',
                'scan_type': attack_type,
                'source_ip': data.get('src_ip', 'unknown'),
                'target_ip': data.get('dest_ip', 'unknown'),
                'protocol': data.get('proto', 'unknown'),
                'event_type': data.get('event_type', 'unknown'),
                'attack_category': 'network_scanning',
                'severity': 'medium',
                'is_threat': 1
            }
            
            # Add SMB-specific data if available
            if 'smb' in data:
                smb_data = data.get('smb', {})
                log_entry.update({
                    'smb_command': smb_data.get('command', 'unknown'),
                    'smb_file': smb_data.get('file', 'unknown')
                })
            
            logs.append(log_entry)
        
        return pd.DataFrame(logs)

    def _parse_ftp_bruteforce_logs(self, data, file_path):
        """
        Parse FTP brute-force attack logs from Suricata EVE format
        """
        logs = []
        
        if 'ftp' in data:
            ftp_data = data.get('ftp', {})
            log_entry = {
                'timestamp': data.get('timestamp', datetime.now().isoformat()),
                'tool': 'ftp_bruteforce',
                'service': 'ftp',
                'source_ip': data.get('src_ip', 'unknown'),
                'target_ip': data.get('dest_ip', 'unknown'),
                'username': ftp_data.get('command_data', 'unknown') if ftp_data.get('command') == 'USER' else 'unknown',
                'password': ftp_data.get('command_data', 'unknown') if ftp_data.get('command') == 'PASS' else 'unknown',
                'command': ftp_data.get('command', 'unknown'),
                'status': 'success' if ftp_data.get('reply_received') == 'yes' else 'failed',
                'attack_category': 'bruteforce',
                'severity': 'high',
                'is_threat': 1
            }
            logs.append(log_entry)
        
        return pd.DataFrame(logs)

    def _parse_generic_json(self, data, file_path, tool_name):
        """
        Parse generic JSON logs with more comprehensive field extraction
        """
        logs = []
        
        # Skip if data is not a dictionary
        if not isinstance(data, dict):
            return pd.DataFrame()
        
        # Create a basic log entry from available fields
        log_entry = {
            'timestamp': data.get('timestamp', data.get('time', data.get('@timestamp', datetime.now().isoformat()))),
            'tool': tool_name,
            'source_ip': data.get('src_ip', data.get('source_ip', data.get('srcip', 'unknown'))),
            'target_ip': data.get('dest_ip', data.get('destination_ip', data.get('dstip', 'unknown'))),
            'protocol': data.get('proto', data.get('protocol', 'unknown')),
            'event_type': data.get('event_type', data.get('alert_type', 'unknown')),
            'attack_category': self._infer_attack_category(data, tool_name),
            'severity': data.get('severity', data.get('priority', 'low')),
            'is_threat': 1,
            'file_source': os.path.basename(file_path)
        }
        
        # Add any additional fields (limit to avoid too many columns)
        field_count = 0
        for key, value in data.items():
            if key not in log_entry and isinstance(value, (str, int, float, bool)) and field_count < 10:
                clean_key = key.replace('.', '_').replace('-', '_')
                log_entry[f'extra_{clean_key}'] = str(value)[:200]  # Limit length
                field_count += 1
        
        logs.append(log_entry)
        return pd.DataFrame(logs)

    def _infer_attack_category(self, data, tool_name):
        """
        Infer attack category from data and tool name
        """
        # Tool-based inference
        tool_categories = {
            'nmap': 'reconnaissance',
            'gobuster': 'directory_bruteforce', 
            'hping3': 'dos_testing',
            'hydra': 'bruteforce',
            'nikto': 'web_scanning',
            'smb': 'network_scanning',
            'ftp_bruteforce': 'bruteforce'
        }
        
        category = tool_categories.get(tool_name, 'unknown')
        
        # Data-based inference
        data_str = str(data).lower()
        if 'scan' in data_str:
            category = 'reconnaissance'
        elif 'brute' in data_str or 'password' in data_str:
            category = 'bruteforce'
        elif 'dos' in data_str or 'flood' in data_str:
            category = 'dos_testing'
        elif 'http' in data_str or 'web' in data_str:
            category = 'web_scanning'
        
        return category

    def _get_nmap_scan_type(self, filename):
        """
        Determine Nmap scan type from filename
        """
        if '-O' in filename:
            return 'os_detection'
        elif '-sA' in filename:
            return 'ack_scan'
        elif '-sC' in filename:
            return 'script_scan'
        elif '-sS' in filename:
            return 'syn_scan'
        elif '-sT' in filename:
            return 'tcp_connect_scan'
        elif '-sU' in filename:
            return 'udp_scan'
        elif '-sV' in filename:
            return 'version_detection'
        else:
            return 'standard_scan'

    def debug_file_structure(self, file_path, sample_lines=5):
        """
        Debug method to understand the actual JSON structure
        """
        print(f"\n🔍 DEBUGGING FILE STRUCTURE: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                for i, line in enumerate(file):
                    if i >= sample_lines:
                        break
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            print(f"   Line {i+1}: {type(data)} - Keys: {list(data.keys()) if isinstance(data, dict) else 'Not a dict'}")
                            # Show first level of data structure
                            if isinstance(data, dict):
                                for key, value in list(data.items())[:5]:  # Show first 5 items
                                    print(f"     {key}: {type(value)} - {str(value)[:100]}...")
                        except json.JSONDecodeError as e:
                            print(f"   Line {i+1}: JSON Error - {e}")
        except Exception as e:
            print(f"   Error reading file: {e}")

class RealAttackDataProcessor:
    """
    Process and enrich real attack data
    """
    
    def __init__(self):
        self.attack_categories = {
            'reconnaissance': ['nmap', 'gobuster', 'nikto'],
            'bruteforce': ['hydra', 'ftp_bruteforce'],
            'dos_testing': ['hping3'],
            'network_scanning': ['smb']
        }
    
    def enrich_attack_data(self, df):
        """
        Add additional features and metadata to attack data
        """
        if df.empty:
            return df
        
        enriched_df = df.copy()
        
        # Add timestamp features
        enriched_df['timestamp'] = pd.to_datetime(enriched_df['timestamp'], errors='coerce')
        enriched_df['hour'] = enriched_df['timestamp'].dt.hour
        enriched_df['day_of_week'] = enriched_df['timestamp'].dt.dayofweek
        
        # Add attack complexity score
        enriched_df['complexity_score'] = enriched_df.apply(self._calculate_complexity_score, axis=1)
        
        # Add threat level based on tool and category
        enriched_df['threat_level'] = enriched_df.apply(self._calculate_threat_level, axis=1)
        
        # Add unique identifier for each attack session
        enriched_df['attack_session_id'] = enriched_df['tool'] + '_' + enriched_df['timestamp'].dt.strftime('%Y%m%d%H%M')
        
        return enriched_df
    
    def _calculate_complexity_score(self, row):
        """
        Calculate attack complexity score (1-10)
        """
        score = 1
        
        # Tool-based complexity
        tool_scores = {
            'nmap': 3, 'gobuster': 4, 'hping3': 6, 
            'hydra': 8, 'nikto': 5, 'ftp_bruteforce': 7
        }
        
        score += tool_scores.get(row.get('tool', 'unknown'), 1)
        
        # Severity-based complexity
        severity_scores = {'low': 1, 'medium': 2, 'high': 3}
        score += severity_scores.get(row.get('severity', 'low'), 1)
        
        return min(score, 10)
    
    def _calculate_threat_level(self, row):
        """
        Calculate overall threat level (low, medium, high, critical)
        """
        tool = row.get('tool', '')
        severity = row.get('severity', 'low')
        
        if tool in ['hydra', 'ftp_bruteforce'] and severity == 'high':
            return 'critical'
        elif tool in ['hping3'] and severity == 'high':
            return 'high'
        elif tool in ['nmap', 'gobuster', 'nikto']:
            return 'medium'
        else:
            return 'low'

class RealAttackDetectionAgent:
    """
    Detection Agent specialized for real attack tool logs
    """
    
    def __init__(self):
        self.config = AttackLogsConfig()
        self.parser = AttackLogParser()
        self.processor = RealAttackDataProcessor()
    
    def load_all_attack_logs(self):
        """
        Load and combine all real attack logs
        """
        print("🛡️ Loading REAL attack tool logs...")
        
        all_attack_data = []
        
        # Load Nmap and related logs
        print(f"📁 Checking Nmap logs directory: {self.config.nmap_logs_dir}")
        nmap_logs = self.parser.parse_attack_logs(self.config.nmap_logs_dir)
        if not nmap_logs.empty:
            all_attack_data.append(nmap_logs)
            print(f"✅ Loaded {len(nmap_logs):,} Nmap attack records")
        else:
            print("❌ No Nmap logs found or parsed")
        
        # Load other attack logs
        print(f"📁 Checking attacks logs directory: {self.config.attacks_log_dir}")
        attack_logs = self.parser.parse_attack_logs(self.config.attacks_log_dir)
        if not attack_logs.empty:
            all_attack_data.append(attack_logs)
            print(f"✅ Loaded {len(attack_logs):,} general attack records")
        else:
            print("❌ No attack logs found or parsed")
        
        if all_attack_data:
            combined_data = pd.concat(all_attack_data, ignore_index=True)
            
            # Save raw attack logs
            combined_data.to_csv(self.config.raw_attack_logs_path, index=False)
            
            print(f"🎯 Combined {len(combined_data):,} REAL attack records")
            return combined_data
        else:
            print("❌ No attack logs found in any directory!")
            return pd.DataFrame()
    
    def process_attack_data(self, attack_df):
        """
        Process and enrich the attack data
        """
        print("🔧 Processing and enriching attack data...")
        
        try:
            # Enrich with additional features
            processed_df = self.processor.enrich_attack_data(attack_df)
            
            # Add missing essential columns with default values
            essential_columns = ['source_ip', 'target_ip', 'tool', 'attack_category', 'severity']
            for col in essential_columns:
                if col not in processed_df.columns:
                    processed_df[col] = 'unknown'
            
            # Ensure all records are marked as threats
            processed_df['is_threat'] = 1
            
            # Save processed data
            processed_df.to_csv(self.config.processed_attack_data_path, index=False)
            
            print(f"✅ Processed {len(processed_df):,} attack records")
            return processed_df
            
        except Exception as e:
            print(f"❌ Attack data processing failed: {e}")
            raise Exception(f"Attack data processing failed: {e}")
    
    def generate_attack_catalog(self, attack_df):
        """
        Generate comprehensive catalog of attack techniques
        """
        try:
            if attack_df.empty:
                print("⚠️  No attack data available for catalog generation")
                return {}
            
            catalog = {
                'summary': {
                    'total_attacks': len(attack_df),
                    'unique_tools': attack_df['tool'].nunique(),
                    'time_range': {
                        'start': str(attack_df['timestamp'].min()),
                        'end': str(attack_df['timestamp'].max())
                    }
                },
                'tools_breakdown': attack_df['tool'].value_counts().to_dict(),
                'attack_categories': attack_df['attack_category'].value_counts().to_dict(),
                'severity_distribution': attack_df['severity'].value_counts().to_dict(),
                'top_targets': attack_df['target_ip'].value_counts().head(10).to_dict(),
                'threat_levels': attack_df['threat_level'].value_counts().to_dict() if 'threat_level' in attack_df.columns else {}
            }
            
            # Save catalog
            with open(self.config.attack_catalog_path, 'w') as f:
                json.dump(catalog, f, indent=2, default=str)
            
            print(f"📊 Attack catalog saved: {self.config.attack_catalog_path}")
            return catalog
            
        except Exception as e:
            print(f"Attack catalog generation failed: {e}")
            return {}
    
    def display_attack_analysis(self, attack_df, catalog):
        """
        Display comprehensive attack analysis
        """
        print("\n" + "="*80)
        print("🚨 REAL ATTACK TOOL ANALYSIS REPORT")
        print("="*80)
        
        if attack_df.empty:
            print("❌ No attack data available")
            return
        
        print(f"📊 TOTAL ATTACK RECORDS: {len(attack_df):,}")
        print(f"🛠️  UNIQUE ATTACK TOOLS: {attack_df['tool'].nunique()}")
        
        print(f"\n🔧 ATTACK TOOLS BREAKDOWN:")
        tool_counts = attack_df['tool'].value_counts()
        for tool, count in tool_counts.items():
            percentage = (count / len(attack_df) * 100)
            print(f"   • {tool}: {count:,} records ({percentage:.1f}%)")
        
        if 'attack_category' in attack_df.columns:
            print(f"\n🎯 ATTACK CATEGORIES:")
            category_counts = attack_df['attack_category'].value_counts()
            for category, count in category_counts.items():
                percentage = (count / len(attack_df) * 100)
                print(f"   • {category}: {count:,} attacks ({percentage:.1f}%)")
        
        if 'severity' in attack_df.columns:
            print(f"\n⚠️  SEVERITY DISTRIBUTION:")
            severity_counts = attack_df['severity'].value_counts()
            for severity, count in severity_counts.items():
                percentage = (count / len(attack_df) * 100)
                print(f"   • {severity}: {count:,} attacks ({percentage:.1f}%)")
        
        print(f"\n💾 Data saved to:")
        print(f"   • Raw attack logs: {self.config.raw_attack_logs_path}")
        print(f"   • Processed data: {self.config.processed_attack_data_path}")
        print(f"   • Attack catalog: {self.config.attack_catalog_path}")
        print("="*80)
    
    def initiate_real_attack_analysis(self):
        """
        Main method to analyze real attack tool logs
        """
        print("🚀 Starting Real Attack Tool Analysis")
        
        try:
            # Step 1: Load all attack logs
            print(f"📁 Checking for attack logs...")
            print(f"   - Nmap logs: {self.config.nmap_logs_dir}")
            print(f"   - Attack logs: {self.config.attacks_log_dir}")
            
            attack_data = self.load_all_attack_logs()
            
            if attack_data.empty:
                error_msg = "No attack data found in specified directories."
                print(f"❌ {error_msg}")
                return None, None, None
            
            # Step 2: Process and enrich data
            processed_data = self.process_attack_data(attack_data)
            
            # Step 3: Generate attack catalog
            catalog = self.generate_attack_catalog(processed_data)
            
            # Step 4: Display analysis
            self.display_attack_analysis(processed_data, catalog)
            
            print("✅ Real attack analysis completed successfully")
            
            return (
                self.config.processed_attack_data_path,
                processed_data,
                catalog
            )
            
        except Exception as e:
            error_msg = f"Real attack analysis failed: {str(e)}"
            print(f"❌ {error_msg}")
            return None, None, None

class HybridDetectionAgent(RealAttackDetectionAgent):
    """
    Agent that combines UNSW-NB15 with real attack logs - FIXED VERSION
    """
    
    def __init__(self):
        super().__init__()
        self.unsw_data_path = 'notebook/data/UNSW_NB15_training-set.csv'
    
    def initiate_hybrid_analysis(self):
        """
        Main method to analyze hybrid dataset (UNSW-NB15 + Real Attacks)
        """
        print("🚀 Starting Hybrid Analysis (UNSW-NB15 + Real Attacks)")
        
        try:
            # Step 1: Load hybrid data
            hybrid_data = self.load_hybrid_data()
            
            if hybrid_data.empty:
                error_msg = "No hybrid data found."
                print(f"❌ {error_msg}")
                return None, None, None
            
            # Step 2: Process and enrich data
            print("🔧 Processing and enriching hybrid data...")
            processed_data = self.process_attack_data(hybrid_data)
            
            # Step 3: Generate attack catalog
            catalog = self.generate_attack_catalog(processed_data)
            
            # Step 4: Display analysis
            self.display_hybrid_analysis(processed_data, catalog)
            
            print("✅ Hybrid analysis completed successfully")
            
            return (
                self.config.processed_attack_data_path,
                processed_data,
                catalog
            )
            
        except Exception as e:
            error_msg = f"Hybrid analysis failed: {str(e)}"
            print(f"❌ {error_msg}")
            import traceback
            traceback.print_exc()
            return None, None, None
    
    def display_hybrid_analysis(self, hybrid_df, catalog):
        """
        Display comprehensive hybrid analysis
        """
        print("\n" + "="*80)
        print("🚨 HYBRID DATASET ANALYSIS REPORT (UNSW-NB15 + Real Attacks)")
        print("="*80)
        
        if hybrid_df.empty:
            print("❌ No hybrid data available")
            return
        
        # Calculate dataset composition
        unsw_count = len(hybrid_df[hybrid_df['tool'] == 'unsw_dataset'])
        real_attack_count = len(hybrid_df[hybrid_df['tool'] != 'unsw_dataset'])
        
        print(f"📊 DATASET COMPOSITION:")
        print(f"   • UNSW-NB15 Records: {unsw_count:,} ({unsw_count/len(hybrid_df)*100:.1f}%)")
        print(f"   • Real Attack Records: {real_attack_count:,} ({real_attack_count/len(hybrid_df)*100:.1f}%)")
        print(f"   • TOTAL: {len(hybrid_df):,} records")
        
        # Threat distribution
        total_threats = hybrid_df['is_threat'].sum()
        total_normal = len(hybrid_df) - total_threats
        
        print(f"\n🎯 THREAT DISTRIBUTION:")
        print(f"   • Threats: {total_threats:,} ({total_threats/len(hybrid_df)*100:.1f}%)")
        print(f"   • Normal: {total_normal:,} ({total_normal/len(hybrid_df)*100:.1f}%)")
        
        # Tool breakdown
        print(f"\n🔧 TOOLS BREAKDOWN:")
        tool_counts = hybrid_df['tool'].value_counts()
        for tool, count in tool_counts.head(10).items():  # Show top 10
            percentage = (count / len(hybrid_df) * 100)
            print(f"   • {tool}: {count:,} records ({percentage:.1f}%)")
        
        if 'attack_category' in hybrid_df.columns:
            print(f"\n🎯 ATTACK CATEGORIES:")
            category_counts = hybrid_df['attack_category'].value_counts()
            for category, count in category_counts.items():
                percentage = (count / len(hybrid_df) * 100)
                print(f"   • {category}: {count:,} records ({percentage:.1f}%)")
        
        print(f"\n💾 Data saved to:")
        print(f"   • Processed data: {self.config.processed_attack_data_path}")
        print(f"   • Attack catalog: {self.config.attack_catalog_path}")
        print("="*80)

    def load_hybrid_data(self):
        """
        Load both UNSW-NB15 and real attack logs - PROPERLY SEPARATED
        """
        print("🔄 Loading HYBRID dataset (UNSW-NB15 + Real Attacks)...")
        
        all_datasets = []
        
        # 1. Load UNSW-NB15 dataset FIRST (to preserve labels)
        print(f"📁 Loading UNSW-NB15: {self.unsw_data_path}")
        unsw_data = self._load_unsw_dataset()
        if not unsw_data.empty:
            all_datasets.append(unsw_data)
            print(f"✅ Loaded {len(unsw_data):,} UNSW-NB15 records")
            print(f"   - Threats: {unsw_data['is_threat'].sum():,}")
            print(f"   - Normal: {len(unsw_data) - unsw_data['is_threat'].sum():,}")
        else:
            print("❌ No UNSW-NB15 data found!")
            return pd.DataFrame()
        
        # 2. Load real attack logs SECOND
        attack_data = self.load_all_attack_logs()
        if not attack_data.empty:
            # Ensure real attacks are marked as threats
            attack_data['is_threat'] = 1
            all_datasets.append(attack_data)
            print(f"✅ Loaded {len(attack_data):,} real attack records")
        
        if all_datasets:
            combined_data = pd.concat(all_datasets, ignore_index=True)
            
            # Verify threat distribution
            total_threats = combined_data['is_threat'].sum()
            total_normal = len(combined_data) - total_threats
            
            print(f"🎯 Combined {len(combined_data):,} TOTAL records")
            print(f"   - Total Threats: {total_threats:,} ({total_threats/len(combined_data)*100:.1f}%)")
            print(f"   - Total Normal: {total_normal:,} ({total_normal/len(combined_data)*100:.1f}%)")
            
            return combined_data
        else:
            print("❌ No data found!")
            return pd.DataFrame()
    
    def _load_unsw_dataset(self):
        """
        Load and prepare UNSW-NB15 dataset - PRESERVE ORIGINAL LABELS
        """
        try:
            if not os.path.exists(self.unsw_data_path):
                print(f"❌ UNSW-NB15 not found at: {self.unsw_data_path}")
                print(f"🔍 Current working directory: {os.getcwd()}")
                print(f"🔍 Files in notebook/data/: {os.listdir('notebook/data') if os.path.exists('notebook/data') else 'Directory not found'}")
                return pd.DataFrame()
            
            # Load UNSW-NB15
            df = pd.read_csv(self.unsw_data_path)
            print(f"📊 UNSW-NB15 loaded: {len(df):,} records, {len(df.columns)} features")
            
            # Check original label distribution
            if 'label' in df.columns:
                original_threats = df['label'].sum()
                original_normal = len(df) - original_threats
                print(f"📋 UNSW Original labels - Threats: {original_threats:,}, Normal: {original_normal:,}")
            
            # Map UNSW columns to our schema - PRESERVE LABELS
            df = self._map_unsw_to_our_schema(df)
            
            return df
            
        except Exception as e:
            print(f"❌ Failed to load UNSW-NB15: {e}")
            import traceback
            traceback.print_exc()
            return pd.DataFrame()
    
    def _map_unsw_to_our_schema(self, df):
        """
        Map UNSW-NB15 columns to our unified schema - PRESERVE ORIGINAL LABELS
        """
        mapped_df = df.copy()
        
        print("🔧 Mapping UNSW-NB15 to unified schema...")
        
        # PRESERVE ORIGINAL LABELS - this is crucial!
        if 'label' in mapped_df.columns:
            mapped_df['is_threat'] = mapped_df['label'].astype(int)
            print(f"✅ Preserved original threat labels: {mapped_df['is_threat'].sum():,} threats, {len(mapped_df) - mapped_df['is_threat'].sum():,} normal")
        else:
            print("⚠️  No 'label' column found in UNSW data - all will be marked as threats")
            mapped_df['is_threat'] = 1
        
        # Rename other columns to match our schema
        column_mapping = {
            'srcip': 'source_ip',
            'dstip': 'target_ip', 
            'proto': 'protocol',
            'service': 'service',
            'state': 'state',
            'attack_cat': 'threat_type'
        }
        
        # Apply mapping for existing columns
        for old_col, new_col in column_mapping.items():
            if old_col in mapped_df.columns:
                mapped_df[new_col] = mapped_df[old_col]
            else:
                print(f"⚠️  Column {old_col} not found in UNSW data")
        
        # Add tool identifier
        mapped_df['tool'] = 'unsw_dataset'
        
        # Map UNSW attack categories to our categories
        if 'threat_type' in mapped_df.columns:
            mapped_df['attack_category'] = mapped_df['threat_type'].apply(self._map_unsw_attack_category)
        else:
            # For normal traffic, set category to 'normal'
            mapped_df['attack_category'] = mapped_df['is_threat'].apply(
                lambda x: 'normal' if x == 0 else 'unknown'
            )
        
        # Set severity based on attack type
        mapped_df['severity'] = mapped_df.apply(self._set_unsw_severity, axis=1)
        
        # Add synthetic timestamp if not present
        if 'timestamp' not in mapped_df.columns:
            mapped_df['timestamp'] = datetime.now().isoformat()
        
        print(f"✅ UNSW mapping complete: {mapped_df['is_threat'].sum():,} threats, {len(mapped_df) - mapped_df['is_threat'].sum():,} normal")
        
        return mapped_df
    
    def _map_unsw_attack_category(self, threat_type):
        """
        Map UNSW-NB15 attack categories to our categories
        """
        if pd.isna(threat_type) or threat_type == '':
            return 'normal'
        
        threat_str = str(threat_type).lower()
        
        category_mapping = {
            'normal': 'normal',
            'exploits': 'exploitation',
            'reconnaissance': 'reconnaissance', 
            'dos': 'dos_testing',
            'fuzzers': 'fuzzing',
            'shellcode': 'exploitation',
            'analysis': 'reconnaissance',
            'backdoors': 'backdoor',
            'generic': 'generic_attack',
            'worms': 'malware'
        }
        
        return category_mapping.get(threat_str, 'unknown')
    
    def _set_unsw_severity(self, row):
        """
        Set severity for UNSW-NB15 records
        """
        if row.get('is_threat', 0) == 0:
            return 'low'  # Normal traffic
        
        threat_type = str(row.get('threat_type', 'unknown')).lower()
        
        if threat_type in ['reconnaissance', 'analysis', 'fuzzers']:
            return 'medium'
        elif threat_type in ['exploits', 'dos', 'generic']:
            return 'high'
        elif threat_type in ['shellcode', 'backdoors', 'worms']:
            return 'critical'
        else:
            return 'medium'

    def debug_data_sources(self):
        """Debug method to check data sources"""
        print("\n🔍 DEBUGGING DATA SOURCES:")
        
        # Check UNSW file
        if os.path.exists(self.unsw_data_path):
            df = pd.read_csv(self.unsw_data_path)
            print(f"✅ UNSW file exists: {len(df):,} records")
            if 'label' in df.columns:
                print(f"   - Labels: {df['label'].sum():,} threats, {len(df) - df['label'].sum():,} normal")
            else:
                print("   - ❌ NO 'label' COLUMN FOUND")
        else:
            print(f"❌ UNSW file not found: {self.unsw_data_path}")
        
        # Check attack logs
        attack_data = self.load_all_attack_logs()
        print(f"✅ Attack logs: {len(attack_data):,} records")

if __name__ == "__main__":
    try:
        print("🚀 Starting Cyber Threat Detection System")
        print("="*60)
        print("Choose analysis mode:")
        print("1. Real Attack Analysis (Friend's logs only)")
        print("2. Hybrid Analysis (UNSW-NB15 + Friend's logs)")
        
        choice = input("\nEnter choice (1 or 2): ").strip()
        
        if choice == "1":
            print("\n🎯 Selected: Real Attack Analysis")
            agent = RealAttackDetectionAgent()
            agent.debug_data_sources()
            processed_path, data, catalog = agent.initiate_real_attack_analysis()
        elif choice == "2":
            print("\n🎯 Selected: Hybrid Analysis")
            agent = HybridDetectionAgent()
            agent.debug_data_sources()
            processed_path, data, catalog = agent.initiate_hybrid_analysis()
        else:
            print("❌ Invalid choice. Using Hybrid Analysis by default.")
            agent = HybridDetectionAgent()
            agent.debug_data_sources()
            processed_path, data, catalog = agent.initiate_hybrid_analysis()
        
        if processed_path and data is not None:
            print(f"\n🎯 ANALYSIS COMPLETE:")
            print(f"✅ Processed data: {processed_path}")
            print(f"📊 Total records: {len(data):,}")
            print(f"📁 Attack catalog: {agent.config.attack_catalog_path}")
        else:
            print("\n❌ Analysis failed or no data found")
            
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()