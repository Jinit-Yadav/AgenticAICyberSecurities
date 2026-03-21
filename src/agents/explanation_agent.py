import os
import json
import pandas as pd
import numpy as np
import faiss
from sentence_transformers import SentenceTransformer
from openai import OpenAI
from typing import List, Dict, Optional, Tuple
import sys
import logging
from datetime import datetime
import concurrent.futures
import re
import time
import random
from functools import wraps
from queue import Queue
import threading
import hashlib
import pickle
import requests

# =============================================================================
# API KEY VALIDATION FUNCTION
# =============================================================================

def test_openrouter_connection():
    """Test if the OpenRouter API key is valid"""
    api_key = os.getenv('OPENROUTER_API_KEY')
    if not api_key:
        print("❌ No API key found in environment variables")
        return False
    
    print(f"🔑 Testing API Key: {api_key[:10]}...")
    
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }
    
    # Test with a lightweight models endpoint or simple chat completion
    test_payload = {
        "model": "openrouter/pony-alpha:free",
        "messages": [{"role": "user", "content": "Test"}],
        "max_tokens": 5
    }
    
    try:
        response = requests.post(
            'https://openrouter.ai/api/v1/chat/completions',
            headers=headers,
            json=test_payload,
            timeout=10
        )
        
        if response.status_code == 200:
            print("✅ API Key is VALID - Connection successful")
            return True
        elif response.status_code == 401:
            print("❌ API Key is INVALID - Unauthorized")
            return False
        elif response.status_code == 404:
            print("❌ Model not found - Check model ID")
            return False
        else:
            print(f"❌ API Key test failed: Status {response.status_code}")
            print(f"Response: {response.text[:200]}")
            return False
            
    except Exception as e:
        print(f"❌ API Connection failed: {e}")
        return False
    
# =============================================================================
# ENHANCED RESPONSE CACHE
# =============================================================================

class EnhancedResponseCache:
    """Enhanced cache with threat-specific keys - IMPROVED VERSION"""
    
    def __init__(self, cache_file="artifacts/api_cache.pkl", max_size=1000):
        self.cache_file = cache_file
        self.max_size = max_size
        self.cache = self._load_cache()
        self.access_count = {}
        
    def _load_cache(self):
        try:
            with open(self.cache_file, 'rb') as f:
                return pickle.load(f)
        except:
            return {}
    
    def _save_cache(self):
        with open(self.cache_file, 'wb') as f:
            pickle.dump(self.cache, f)
    
    def get_key(self, model_config, messages):
        """Generate UNIQUE cache key based on specific threat details"""
        # Extract the actual query content from messages
        user_content = ""
        for msg in messages:
            if msg.get('role') == 'user':
                user_content = msg.get('content', '')
                break
        
        # Extract SPECIFIC threat details from the content
        threat_tool = "unknown"
        src_ip = "unknown"
        attack_type = "unknown"
        
        # Parse for specific threat patterns in the user content
        # Method 1: Try JSON parsing
        json_match = re.search(r'\{[^}]+\}', user_content)
        if json_match:
            try:
                data = json.loads(json_match.group(0))
                threat_tool = data.get('tool', 'unknown').lower()
                src_ip = data.get('src_ip', 'unknown')
                attack_type = data.get('attack_type', 'unknown').lower()
            except:
                pass
        
        # Method 2: Regex extraction
        if threat_tool == "unknown":
            tool_match = re.search(r'"tool":\s*"([^"]+)"', user_content)
            if tool_match:
                threat_tool = tool_match.group(1).lower()
        
        if src_ip == "unknown":
            src_match = re.search(r'"src_ip":\s*"([^"]+)"', user_content)
            if src_match:
                src_ip = src_match.group(1)
        
        if attack_type == "unknown":
            attack_match = re.search(r'"attack_type":\s*"([^"]+)"', user_content)
            if attack_match:
                attack_type = attack_match.group(1).lower()
        
        # Create a HIGHLY SPECIFIC key based on expert, tool, IP, and attack type
        key_str = f"{model_config['name']}:{threat_tool}:{src_ip}:{attack_type}"
        print(f"🔑 Generated SPECIFIC cache key: {key_str}")
        return hashlib.md5(key_str.encode()).hexdigest()
    
    def get(self, model_config, messages):
        key = self.get_key(model_config, messages)
        if key in self.cache:
            self.access_count[key] = self.access_count.get(key, 0) + 1
            print(f"📦 Using cached response for {model_config['name']} - threat: {key.split(':')[1]}")
            return self.cache[key]
        return None
    
    def set(self, model_config, messages, response):
        if len(self.cache) >= self.max_size:
            # Remove least frequently used item
            lfu_key = min(self.access_count.items(), key=lambda x: x[1])[0]
            del self.cache[lfu_key]
            del self.access_count[lfu_key]
        
        key = self.get_key(model_config, messages)
        self.cache[key] = response
        self.access_count[key] = 1
        self._save_cache()

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
    print("✅ Loaded environment variables from .env file")
except ImportError:
    print("⚠️ python-dotenv not installed, using system environment variables")
    pass

# =============================================================================
# ENHANCED CONFIGURATION
# =============================================================================

class DebateConfig:
    # API Configuration
    API_KEY = os.getenv('OPENROUTER_API_KEY', '')
    BASE_URL = "https://openrouter.ai/api/v1"
    PRIMARY_MODEL = "openrouter/pony-alpha:free" 
    EMBEDDING_MODEL = "all-MiniLM-L6-v2"
    
    # File Paths
    INDEX_PATH = "artifacts/security_knowledge.index"
    METADATA_PATH = "artifacts/security_metadata.json"
    
    # Search Parameters
    TOP_K = 3
    SIMILARITY_THRESHOLD = 0.3
    
    # OPTIMIZED Rate Limiting
    REQUESTS_PER_MINUTE = 10
    REQUESTS_PER_DAY = 40
    
    # OPTIMIZED: 3 experts with parallel processing
    DEBATE_MODELS = [
    {
        "name": "Network Security Expert",
        "model": "openrouter/pony-alpha:free",  # Use this exact string
        "role": "Network Security Specialist", 
        "specialty": "Port scanning analysis, firewall configurations",
        "working": True
    },
    {
        "name": "Threat Intelligence Analyst",
        "model": "openrouter/pony-alpha:free",  # Same here
        "role": "Threat Intelligence Analyst",
        "specialty": "Threat assessment, attack patterns, risk analysis",
        "working": True
    },
    {
        "name": "Incident Response Expert",
        "model": "openrouter/pony-alpha:free",  # And here
        "role": "Incident Response Specialist",
        "specialty": "Containment strategies, forensic analysis, recovery",
        "working": True
    }
]

# =============================================================================
# RATE LIMITING AND RETRY MECHANISMS
# =============================================================================

def rate_limited_optimized(max_per_minute=10):
    """Optimized rate limiting for parallel calls"""
    min_interval = 60.0 / float(max_per_minute)
    last_called = threading.Lock()
    last_call_time = 0.0
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            nonlocal last_call_time
            with last_called:
                elapsed = time.time() - last_call_time
                left_to_wait = min_interval - elapsed
                
                if left_to_wait > 0:
                    actual_wait = max(left_to_wait * 0.7, 2.0)
                    print(f"⏳ Optimized rate limiting: waiting {actual_wait:.2f}s")
                    time.sleep(actual_wait)
                
                result = func(*args, **kwargs)
                last_call_time = time.time()
                return result
        return wrapper
    return decorator

def retry_with_backoff(max_retries=3, base_delay=2, max_delay=30):
    """Retry decorator with exponential backoff"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_retries:
                        print(f"❌ Max retries exceeded for {func.__name__}: {e}")
                        raise
                    
                    if "rate limit" in str(e).lower() or "429" in str(e):
                        delay = min(base_delay * (2 ** attempt) + random.random(), max_delay)
                        print(f"🔄 Rate limit hit, retry {attempt + 1}/{max_retries} in {delay:.2f}s")
                        time.sleep(delay)
                    else:
                        print(f"❌ Non-rate-limit error in {func.__name__}: {e}")
                        raise
            return None
        return wrapper
    return decorator

# =============================================================================
# USAGE TRACKER
# =============================================================================

class UsageTracker:
    def __init__(self, daily_limit=45):
        self.daily_limit = daily_limit
        self.requests_today = 0
        self.last_reset = datetime.now().date()
        self.last_request_time = 0
        self.rate_limited = False
        
    def can_make_request(self):
        """Check if we can make another request"""
        today = datetime.now().date()
        if today != self.last_reset:
            self.requests_today = 0
            self.last_reset = today
            self.rate_limited = False
        
        if self.rate_limited or self.requests_today >= self.daily_limit:
            print(f"🚨 API LIMIT REACHED: {self.requests_today}/{self.daily_limit}")
            return False
        
        # Check minimum time between requests
        time_since_last = time.time() - self.last_request_time
        min_interval = 60.0 / 8
        if time_since_last < min_interval:
            wait_time = min_interval - time_since_last
            print(f"⏳ Waiting {wait_time:.2f}s for rate limit")
            time.sleep(wait_time)
        
        return True
    
    def track_request(self):
        """Track that a request was made"""
        self.requests_today += 1
        self.last_request_time = time.time()
        print(f"📊 API Usage: {self.requests_today}/{self.daily_limit}")
    
    def mark_rate_limited(self):
        """Mark that we've been rate limited"""
        self.rate_limited = True
        print("🚨 MARKED AS RATE LIMITED - Using fallback mode")

# =============================================================================
# THREAT-SPECIFIC KNOWLEDGE BASE MANAGER
# =============================================================================

class ThreatKnowledgeBaseManager:
    """Manages threat-specific knowledge for RAG system"""
    
    def __init__(self):
        self.threat_knowledge = self._initialize_threat_knowledge()
    
    def _initialize_threat_knowledge(self):
        """Initialize comprehensive threat-specific knowledge base"""
        return {
            'nmap': {
                'title': 'Nmap Port Scanning',
                'description': 'Network Mapper (Nmap) is a network scanning tool used for network discovery and security auditing. It sends crafted packets and analyzes responses to map network topology and identify services.',
                'techniques': [
                    'TCP SYN Scan (-sS) - Half-open scanning',
                    'TCP Connect Scan (-sT) - Full TCP connection', 
                    'UDP Scan (-sU) - UDP service discovery',
                    'Version Detection (-sV) - Service version identification',
                    'OS Detection (-O) - Operating system fingerprinting'
                ],
                'detection_indicators': [
                    'Multiple SYN packets to different ports from single source',
                    'Short duration connections to multiple ports',
                    'Sequential port scanning patterns',
                    'Unusual TTL values in packets'
                ],
                'mitigation': [
                    'Configure firewall to block unsolicited inbound connections',
                    'Implement intrusion detection systems with port scan detection',
                    'Use port knocking techniques for service access',
                    'Monitor for scanning patterns in network traffic'
                ],
                'immediate_actions': [
                    'Block source IP at network perimeter',
                    'Analyze scanned ports for vulnerable services', 
                    'Review firewall logs for reconnaissance patterns',
                    'Check if internal systems were compromised'
                ],
                'risk_level': 'Medium-High',
                'category': 'Reconnaissance',
                'impact': 'Information disclosure, pre-attack reconnaissance'
            },
            'hydra': {
                'title': 'Hydra Brute Force Attacks',
                'description': 'Hydra is a parallelized login cracker that supports numerous protocols for brute-force attacks. It rapidly attempts multiple username/password combinations to gain unauthorized access.',
                'techniques': [
                    'SSH brute forcing - Targeting SSH services',
                    'FTP password attacks - FTP service credential cracking',
                    'HTTP form cracking - Web application login attacks', 
                    'RDP credential stuffing - Remote desktop attacks'
                ],
                'detection_indicators': [
                    'Multiple failed authentication attempts from single IP',
                    'Rapid sequential login attempts with different credentials',
                    'Same source IP with different usernames/passwords',
                    'Unusual protocol-specific authentication patterns'
                ],
                'mitigation': [
                    'Implement account lockout policies after failed attempts',
                    'Enable multi-factor authentication for critical services',
                    'Use strong password policies with complexity requirements',
                    'Monitor authentication logs for brute force patterns'
                ],
                'immediate_actions': [
                    'Immediately block source IP address',
                    'Review targeted accounts for compromise',
                    'Check for successful logins from suspicious IPs',
                    'Implement temporary rate limiting on authentication'
                ],
                'risk_level': 'High-Critical', 
                'category': 'Credential Attack',
                'impact': 'Unauthorized access, credential theft, system compromise'
            },
            'hping3': {
                'title': 'Hping3 Network Testing and Attacks',
                'description': 'Hping3 is a command-line oriented TCP/IP packet assembler/analyzer used for network testing and attacks. It can craft custom packets for SYN floods, UDP floods, and other network-based attacks.',
                'techniques': [
                    'SYN flood attacks - Exhausting connection resources',
                    'UDP flood attacks - Overwhelming UDP services',
                    'ICMP attacks - Network discovery and flooding',
                    'Port scanning - Service discovery',
                    'Firewall testing - Security control evasion'
                ],
                'detection_indicators': [
                    'High volume of SYN packets to specific ports',
                    'Spoofed source IP addresses in packets',
                    'Unusual packet fragmentation patterns',
                    'Protocol-specific flooding patterns'
                ],
                'mitigation': [
                    'Implement rate limiting on network interfaces',
                    'Configure DDoS protection mechanisms',
                    'Use traffic filtering and blackholing',
                    'Monitor network bandwidth for anomalies'
                ],
                'immediate_actions': [
                    'Block source IP at network boundary',
                    'Implement temporary rate limiting',
                    'Monitor for service degradation',
                    'Check for collateral damage to other services'
                ],
                'risk_level': 'High',
                'category': 'DoS/Network Attack',
                'impact': 'Service disruption, resource exhaustion, network congestion'
            },
            'sqlmap': {
                'title': 'SQLMap SQL Injection',
                'description': 'SQLMap is an open-source penetration testing tool that automates SQL injection detection and exploitation',
                'techniques': [
                    'Boolean-based blind SQLi',
                    'Time-based blind SQLi',
                    'Union query-based SQLi',
                    'Stacked queries SQLi'
                ],
                'detection_indicators': [
                    'Unusual SQL patterns in HTTP requests',
                    'Database error messages in responses',
                    'Suspicious parameter values',
                    'Unexpected database queries'
                ],
                'mitigation': [
                    'Implement input validation',
                    'Use parameterized queries',
                    'Deploy web application firewalls',
                    'Regular security patching'
                ],
                'risk_level': 'High-Critical',
                'category': 'Web Application Attack'
            },
            'metasploit': {
                'title': 'Metasploit Framework',
                'description': 'Metasploit is a penetration testing framework that provides information about security vulnerabilities and aids in penetration testing',
                'techniques': [
                    'Exploit delivery',
                    'Payload execution',
                    'Post-exploitation activities',
                    'Persistence mechanisms'
                ],
                'detection_indicators': [
                    'Known exploit patterns',
                    'Shellcode execution attempts',
                    'Persistence mechanism installation',
                    'Lateral movement patterns'
                ],
                'mitigation': [
                    'Regular vulnerability patching',
                    'Endpoint protection deployment',
                    'Network segmentation',
                    'Behavioral monitoring'
                ],
                'risk_level': 'Critical',
                'category': 'Exploitation Framework'
            }
        }
    
    def get_threat_knowledge(self, threat_type: str) -> Dict:
        """Get comprehensive knowledge about a specific threat"""
        threat_type_lower = threat_type.lower()
        
        # Handle variations and synonyms
        threat_mapping = {
            'port_scan': 'nmap',
            'portscan': 'nmap', 
            'scanning': 'nmap',
            'reconnaissance': 'nmap',
            'bruteforce': 'hydra',
            'brute_force': 'hydra',
            'password_attack': 'hydra',
            'credential_attack': 'hydra',
            'dos': 'hping3',
            'ddos': 'hping3',
            'syn_flood': 'hping3',
            'flood_attack': 'hping3',
            'denial_of_service': 'hping3'
        }
        
        actual_threat = threat_mapping.get(threat_type_lower, threat_type_lower)
        
        return self.threat_knowledge.get(actual_threat, {
            'title': f'Unknown Threat: {threat_type}',
            'description': f'No specific knowledge available for {threat_type} threat type',
            'techniques': ['Unknown attack techniques'],
            'detection_indicators': ['General suspicious activity patterns'],
            'mitigation': ['Standard security measures and monitoring'],
            'immediate_actions': ['Investigate and contain the threat'],
            'risk_level': 'Unknown',
            'category': 'Unknown',
            'impact': 'Potential security compromise'
        })

# =============================================================================
# CORE OPTIMIZED DEBATE AGENT - WITH FIXES
# =============================================================================

class OptimizedDebateAgent:
    """Core agent for handling API calls and state management - FIXED VERSION"""
    
    def __init__(self, config: DebateConfig = None):
        self.config = config or DebateConfig()
        self.llm_client = None
        self.embedding_model = None
        self.vector_index = None
        self.metadata = []
        self.debate_history = []
        self.fallback_mode = False
        self.usage_tracker = UsageTracker()
        self.response_cache = EnhancedResponseCache()
        self.threat_knowledge_base = ThreatKnowledgeBaseManager()
        
        self._initialize_components()
    
    def _initialize_components(self):
        """Initialize all required components"""
        try:
            # Initialize embedding model
            self.embedding_model = SentenceTransformer(self.config.EMBEDDING_MODEL)
            print(f"✅ Loaded embedding model: {self.config.EMBEDDING_MODEL}")
            
            # Test API connection before initializing LLM client
            api_valid = test_openrouter_connection()
            
            if self.config.API_KEY and api_valid:
                self.llm_client = OpenAI(
                    api_key=self.config.API_KEY,
                    base_url=self.config.BASE_URL
                )
                print("✅ LLM client initialized with OpenRouter")
                self.fallback_mode = False
            else:
                print("⚠️ No valid API key found, using fallback mode")
                self.fallback_mode = True
            
            # Load existing knowledge base if available
            self._load_knowledge_base()
            
        except Exception as e:
            print(f"❌ Component initialization failed: {e}")
            self.fallback_mode = True
    
    def _load_knowledge_base(self):
        """Load existing knowledge base from disk"""
        try:
            if os.path.exists(self.config.INDEX_PATH):
                self.vector_index = faiss.read_index(self.config.INDEX_PATH)
                print("✅ Loaded existing vector index")
            
            if os.path.exists(self.config.METADATA_PATH):
                with open(self.config.METADATA_PATH, 'r', encoding='utf-8') as f:
                    self.metadata = json.load(f)
                print(f"✅ Loaded {len(self.metadata)} metadata entries")
                
        except Exception as e:
            print(f"⚠️ Could not load knowledge base: {e}")
    
    @retry_with_backoff(max_retries=3)
    @rate_limited_optimized(max_per_minute=10)
    def _safe_api_call(self, model_config: Dict, messages: List[Dict], max_tokens: int = 500):
        """Make safe API call with retry and rate limiting - FIXED VERSION"""
        if self.fallback_mode or not self.llm_client:
            raise Exception("Fallback mode - no API calls")
        
        if not self.usage_tracker.can_make_request():
            raise Exception("Rate limit exceeded")
        
        # Check cache first
        cached_response = self.response_cache.get(model_config, messages)
        if cached_response:
            return cached_response
        
        try:
            response = self.llm_client.chat.completions.create(
                model=model_config['model'],
                messages=messages,
                max_tokens=max_tokens,
                temperature=0.7
            )
            
            # FIXED: Enhanced safety checks for response
            if not response or not hasattr(response, 'choices'):
                raise ValueError("Invalid response format - no choices attribute")
            
            if not response.choices or len(response.choices) == 0:
                raise ValueError("Empty response from API - no choices returned")
            
            self.usage_tracker.track_request()
            self.response_cache.set(model_config, messages, response)
            
            return response
            
        except Exception as e:
            if "rate limit" in str(e).lower():
                self.usage_tracker.mark_rate_limited()
            print(f"❌ API Call Error in _safe_api_call: {type(e).__name__}: {e}")
            raise e

# =============================================================================
# ENHANCED MULTI-LLM DEBATE AGENT WITH RAG INTEGRATION - FIXED
# =============================================================================

class OptimizedDebateGenerator:
    """Generates debates using RAG system for threat-specific explanations - FIXED VERSION"""
    
    def __init__(self, agent: OptimizedDebateAgent):
        self.agent = agent
        self.config = agent.config
        self.multi_expert_used = False
    
    def generate_debate_and_solution(self, query: str, context: List[Tuple[Dict, float]]) -> Dict:
        """Generate multi-expert debate using RAG system - FIXED to be threat-specific"""
        try:
            print("🎯 Starting THREAT-SPECIFIC RAG-based multi-expert debate generation...")
            
            # EXTRACT THREAT-SPECIFIC INFORMATION FROM QUERY
            threat_info = self._extract_threat_info_from_query(query)
            print(f"🔍 Extracted threat info: {threat_info}")
            
            if self.agent.fallback_mode or self.agent.llm_client is None:
                print("🔄 Using RAG-enhanced fallback solution generation")
                return self._generate_rag_enhanced_fallback_solution(query, context, threat_info)
            
            # Step 1: Get expert analyses from working models (PARALLEL) with threat-specific context
            expert_analyses = self._get_expert_analyses(query, context, threat_info)
            
            # Step 2: Generate comprehensive solution using RAG context and threat info
            final_solution = self._generate_comprehensive_solution(query, context, expert_analyses, threat_info)
            
            # Multi-expert tracking
            multi_expert_used = len(expert_analyses) >= 2
            expert_count = len(expert_analyses)

            print(f"🔍 RAG-based analysis: {expert_count} experts consulted, multi-expert: {multi_expert_used}")

            # Create comprehensive result
            result = {
                'timestamp': datetime.now().isoformat(),
                'query': query,
                'expert_analyses': expert_analyses,
                'consensus_analysis': final_solution['analysis'],
                'recommended_solution': final_solution['solution'],
                'implementation_steps': final_solution['implementation'],
                'monitoring_recommendations': final_solution['monitoring'],
                'risk_assessment': final_solution['risk_assessment'],
                'sources_used': [ctx[0]['title'] for ctx in context],
                'confidence_score': final_solution['confidence'],
                'models_used': [model['name'] for model in self.config.DEBATE_MODELS if model.get('working', True)],
                'ai_generated': True,
                'fallback_used': False,
                'multi_expert_analysis_used': multi_expert_used,
                'expert_count': expert_count,
                'rag_used': len(context) > 0,
                'threat_specific_info': threat_info
            }
            
            self.agent.debate_history.append(result)
            print(f"🤖 Generated THREAT-SPECIFIC RAG-based multi-expert debate and solution for {threat_info['tool']}")
            return result
            
        except Exception as e:
            print(f"❌ Critical error in RAG debate generation: {e}")
            return self._create_error_response(query, str(e))
    
    def _extract_threat_info_from_query(self, query: str) -> Dict:
        """Extract specific threat information from the query - FIXED VERSION"""
        threat_info = {
            'tool': 'unknown',
            'src_ip': 'unknown', 
            'dest_ip': 'unknown',
            'dest_port': 'unknown',
            'proto': 'unknown',
            'attack_type': 'unknown',
            'severity': 'unknown'
        }
        
        try:
            # FIRST: Look for actual attack types in the query text
            actual_attack_types = [
                'port_scan', 'portscan', 'scanning', 'reconnaissance',
                'bruteforce', 'brute_force', 'password_attack', 'credential_attack', 
                'dos', 'ddos', 'syn_flood', 'flood_attack', 'denial_of_service',
                'sql_injection', 'sqli', 'web_attack',
                'exploitation', 'malware', 'backdoor'
            ]
            
            query_lower = query.lower()
            for attack_type in actual_attack_types:
                if attack_type in query_lower:
                    threat_info['attack_type'] = attack_type
                    print(f"✅ Found specific attack type: {attack_type}")
                    break
            
            # SECOND: Try to extract from JSON-like pattern
            json_match = re.search(r'\{[^}]+\}', query)
            if json_match:
                try:
                    data = json.loads(json_match.group(0))
                    
                    # OVERWRITE with actual values from detection
                    if data.get('attack_type') and data['attack_type'].lower() != 'potential security threat':
                        threat_info['attack_type'] = data['attack_type'].lower()
                    
                    if data.get('tool'):
                        threat_info['tool'] = data['tool'].lower()
                    
                    if data.get('src_ip') and data['src_ip'] not in ['unknown', 'missing']:
                        threat_info['src_ip'] = data['src_ip']
                    
                    if data.get('dest_ip') and data['dest_ip'] not in ['unknown', 'missing']:
                        threat_info['dest_ip'] = data['dest_ip']
                    
                    if data.get('dest_port') and str(data['dest_port']) not in ['unknown', 'missing']:
                        threat_info['dest_port'] = str(data['dest_port'])
                    
                    if data.get('proto'):
                        threat_info['proto'] = data['proto'].lower()
                    
                    if data.get('severity'):
                        threat_info['severity'] = data['severity'].lower()
                        
                    print(f"✅ Extracted from JSON: tool={threat_info['tool']}, attack_type={threat_info['attack_type']}")
                    
                except json.JSONDecodeError:
                    pass
            
            # THIRD: Regex extraction as fallback
            if threat_info['tool'] == "unknown":
                tool_match = re.search(r'"tool":\s*"([^"]+)"', query) or re.search(r'- Tool:\s*([^\n]+)', query)
                if tool_match:
                    threat_info['tool'] = tool_match.group(1).lower().strip()
            
            if threat_info['src_ip'] == "unknown":
                src_match = re.search(r'"src_ip":\s*"([^"]+)"', query) or re.search(r'- Source:\s*([^\n]*?)(\d+\.\d+\.\d+\.\d+)', query)
                if src_match:
                    threat_info['src_ip'] = src_match.group(1) if '"src_ip"' in query else src_match.group(2)
            
            if threat_info['dest_ip'] == "unknown":
                dest_match = re.search(r'"dest_ip":\s*"([^"]+)"', query)
                if dest_match:
                    threat_info['dest_ip'] = dest_match.group(1)
            
            if threat_info['dest_port'] == "unknown":
                port_match = re.search(r'"dest_port":\s*(\d+)', query) or re.search(r'Target:.*?:(\d+)', query)
                if port_match:
                    threat_info['dest_port'] = port_match.group(1)
            
            if threat_info['proto'] == "unknown":
                proto_match = re.search(r'"proto":\s*"([^"]+)"', query) or re.search(r'- Protocol:\s*([^\n]+)', query)
                if proto_match:
                    threat_info['proto'] = proto_match.group(1).lower().strip()
            
            if threat_info['attack_type'] == "unknown":
                attack_match = re.search(r'"attack_type":\s*"([^"]+)"', query) or re.search(r'- Attack Type:\s*([^\n]+)', query)
                if attack_match:
                    extracted_type = attack_match.group(1).lower().strip()
                    # Only use if it's not generic
                    if 'potential security threat' not in extracted_type:
                        threat_info['attack_type'] = extracted_type
            
            if threat_info['severity'] == "unknown":
                severity_match = re.search(r'"severity":\s*"([^"]+)"', query) or re.search(r'- Severity:\s*([^\n]+)', query)
                if severity_match:
                    threat_info['severity'] = severity_match.group(1).lower().strip()
            
            # FINAL: If we still have generic attack type, try to infer from tool
            if threat_info['attack_type'] == 'unknown' and threat_info['tool'] != 'unknown':
                tool_to_attack = {
                    'nmap': 'port_scan',
                    'hydra': 'bruteforce', 
                    'hping3': 'dos',
                    'sqlmap': 'sql_injection',
                    'metasploit': 'exploitation'
                }
                if threat_info['tool'] in tool_to_attack:
                    threat_info['attack_type'] = tool_to_attack[threat_info['tool']]
                    print(f"✅ Inferred attack type from tool: {threat_info['attack_type']}")
                
        except Exception as e:
            print(f"⚠️ Error extracting threat info: {e}")
        
        print(f"🔍 Final threat info: {threat_info}")
        return threat_info
    
    def _get_expert_analyses(self, query: str, context: List[Tuple[Dict, float]], threat_info: Dict) -> List[Dict]:
        """Get analyses from all expert models with threat-specific context"""
        expert_analyses = []
        working_models = [model for model in self.config.DEBATE_MODELS if model.get('working', True)]
        
        print(f"🧠 Consulting {len(working_models)} experts for {threat_info['tool']} {threat_info['attack_type']} attack...")
        
        # Use ThreadPoolExecutor for parallel API calls
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            future_to_model = {
                executor.submit(self._get_single_expert_analysis, model_config, query, context, threat_info): model_config 
                for model_config in working_models
            }
            
            for future in concurrent.futures.as_completed(future_to_model):
                model_config = future_to_model[future]
                try:
                    analysis = future.result(timeout=30)
                    expert_analysis = {
                        'model_name': model_config['name'],
                        'model_role': model_config['role'], 
                        'specialty': model_config['specialty'],
                        'analysis': analysis.get('analysis', ''),
                        'confidence': analysis.get('confidence', 0.7),
                        'key_points': analysis.get('key_points', []),
                        'risk_level': analysis.get('risk_level', 'Medium'),
                        'recommendations': analysis.get('recommendations', []),
                        'threat_specific': True,
                        'threat_tool': threat_info['tool'],
                        'threat_type': threat_info['attack_type']
                    }
                    expert_analyses.append(expert_analysis)
                    print(f"✅ {model_config['name']} analysis completed for {threat_info['tool']}")
                except Exception as e:
                    print(f"❌ Expert {model_config['name']} failed: {e}")
                    expert_analyses.append(self._create_rag_enhanced_expert_fallback(model_config, query, context, threat_info))
        
        self.multi_expert_used = len(expert_analyses) >= 2
        print(f"🔍 THREAT-SPECIFIC MULTI-EXPERT: {len(expert_analyses)} experts completed for {threat_info['tool']}")
        
        return expert_analyses
    
    def _get_single_expert_analysis(self, model_config: Dict, query: str, context: List[Tuple[Dict, float]], threat_info: Dict) -> Dict:
        """Get analysis from a specific expert model with threat-specific context - FIXED"""
        try:
            formatted_context = self._format_rag_context_for_llm(context)
            
            # HIGHLY SPECIFIC system prompt for each threat type
            system_prompt = self._create_threat_specific_system_prompt(model_config, threat_info)
            
            user_content = f"""Analyze this SPECIFIC security incident using the provided security knowledge:

INCIDENT DETAILS (RAW):
{query}

SPECIFIC THREAT CONTEXT:
- Attack Tool: {threat_info['tool']}
- Attack Type: {threat_info['attack_type']} 
- Source IP: {threat_info['src_ip']}
- Target: {threat_info['dest_ip']}:{threat_info['dest_port']}
- Protocol: {threat_info['proto']}
- Severity: {threat_info['severity']}

SECURITY KNOWLEDGE CONTEXT:
{formatted_context}

Provide your EXPERT analysis SPECIFICALLY for this {threat_info['tool']} {threat_info['attack_type']} attack."""
            
            response = self.agent._safe_api_call(
                model_config,
                [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content}
                ],
                max_tokens=500
            )
            
            # FIXED: Enhanced safety checks
            if response and hasattr(response, 'choices') and response.choices and len(response.choices) > 0:
                analysis_text = response.choices[0].message.content.strip()
                # Clean up any truncation markers
                analysis_text = re.sub(r'<s>\[(OUT|BOT|INST)\]', '', analysis_text).strip()
                print(f"📝 {model_config['name']} response for {threat_info['tool']}: {analysis_text[:150]}...")
                return self._parse_expert_analysis_with_rag(analysis_text, context, threat_info)
            else:
                raise ValueError(f"Invalid response format from {model_config['name']}")
                
        except Exception as e:
            print(f"❌ Expert analysis with RAG failed for {model_config['name']}: {e}")
            return self._create_rag_enhanced_expert_fallback(model_config, query, context, threat_info)
    
    def _create_threat_specific_system_prompt(self, model_config: Dict, threat_info: Dict) -> str:
        """Create highly specific system prompt based on threat type and expert role"""
        base_prompt = f"You are {model_config['name']}, a {model_config['role']} specializing in {model_config['specialty']}."
        
        # Add threat-specific guidance
        threat_guidance = ""
        tool = threat_info['tool']
        attack_type = threat_info['attack_type']
        
        # PORT SCANNING - nmap
        if tool == 'nmap' or 'scan' in attack_type:
            threat_guidance = """
FOCUS ON PORT SCANNING:
- Port scanning techniques and patterns used by nmap
- Network reconnaissance implications and risks
- Firewall and IDS evasion methods commonly employed
- Information disclosure risks from port scanning
- Recommended network hardening against reconnaissance
- Detection of stealth scanning techniques
"""
        # BRUTE FORCE - hydra
        elif tool == 'hydra' or 'brute' in attack_type:
            threat_guidance = """
FOCUS ON BRUTE FORCE ATTACKS:  
- Brute force attack methodologies used by Hydra
- Credential stuffing patterns and detection
- Authentication security weaknesses exploited
- Account lockout strategies and effectiveness
- Multi-factor authentication importance
- Password policy recommendations
- Service-specific attack patterns (SSH, FTP, HTTP, etc.)
"""
        # DOS ATTACKS - hping3
        elif tool == 'hping3' or 'dos' in attack_type or 'flood' in attack_type:
            threat_guidance = """
FOCUS ON DENIAL OF SERVICE ATTACKS:
- DoS/DDoS attack vectors used by hping3
- Network resource exhaustion techniques
- SYN flood mitigation strategies
- Traffic filtering and rate limiting approaches  
- Service availability protection mechanisms
- Detection of flood attack patterns
- ISP coordination for attack mitigation
"""
        # SQL INJECTION - sqlmap
        elif tool == 'sqlmap' or 'sql' in attack_type:
            threat_guidance = """
FOCUS ON SQL INJECTION ATTACKS:
- SQL injection techniques and payloads
- Database security vulnerabilities
- Web application firewall effectiveness
- Input validation and sanitization
- Parameterized query implementation
- Database error information leakage
"""
        # EXPLOITATION - metasploit
        elif tool == 'metasploit' or 'exploit' in attack_type:
            threat_guidance = """
FOCUS ON EXPLOITATION FRAMEWORKS:
- Metasploit framework capabilities
- Payload delivery and execution methods
- Post-exploitation activities
- Persistence mechanism detection
- Vulnerability management importance
- Patch management strategies
"""
        else:
            threat_guidance = """
FOCUS ON GENERAL SECURITY:
- Attack pattern analysis specific to this tool
- Security control recommendations
- Risk assessment and mitigation strategies
- Incident response procedures
- Threat intelligence integration
"""
        
        return base_prompt + threat_guidance + """

Provide SPECIFIC, ACTIONABLE analysis for this exact threat type.

Include:
- Technical assessment specific to this attack tool and technique
- Risk level (Low/Medium/High/Critical) with justification
- 3-4 key observations about this specific attack
- 3-4 specific, actionable recommendations
- Confidence score (0.1-1.0) based on available information

Be highly specific to the attack tool and techniques used."""
    
    def _create_rag_enhanced_expert_fallback(self, model_config: Dict, query: str, context: List[Tuple[Dict, float]], threat_info: Dict) -> Dict:
        """Create threat-specific fallback analysis"""
        # Get detailed threat knowledge
        threat_knowledge = self.agent.threat_knowledge_base.get_threat_knowledge(threat_info['tool'])
        
        # Create highly specific analysis based on expert role and threat type
        if "Network" in model_config['role']:
            if threat_info['tool'] == 'nmap':
                analysis = f"NETWORK SECURITY ANALYSIS: nmap port scanning detected from {threat_info['src_ip']}. This reconnaissance activity maps network services and identifies vulnerabilities. Targeting {threat_info['dest_ip']}:{threat_info['dest_port']} via {threat_info['proto']}."
                key_points = [
                    "Port scanning reconnaissance phase",
                    "Network topology mapping attempt", 
                    "Service enumeration for vulnerability assessment",
                    "Pre-attack information gathering"
                ]
                recommendations = [
                    f"Block {threat_info['src_ip']} at network perimeter",
                    "Implement port scan detection in IDS/IPS",
                    "Review firewall rules for unnecessary open ports",
                    "Monitor for follow-up exploitation attempts"
                ]
                risk_level = "High"
                confidence = 0.85
                
            elif threat_info['tool'] == 'hydra':
                analysis = f"NETWORK SECURITY ANALYSIS: hydra brute force attack from {threat_info['src_ip']} targeting {threat_info['dest_ip']}:{threat_info['dest_port']}. Rapid credential guessing attempts detected."
                key_points = [
                    "Authentication service targeting",
                    "Credential stuffing patterns",
                    "Service-specific attack vectors",
                    "Account lockout circumvention attempts"
                ]
                recommendations = [
                    f"Immediately block {threat_info['src_ip']}",
                    "Implement account lockout policies",
                    "Enable multi-factor authentication",
                    "Monitor authentication logs for patterns"
                ]
                risk_level = "Critical"
                confidence = 0.9
                
            elif threat_info['tool'] == 'hping3':
                analysis = f"NETWORK SECURITY ANALYSIS: hping3 DoS attack from {threat_info['src_ip']} targeting {threat_info['dest_ip']}:{threat_info['dest_port']}. Potential SYN flood or network resource exhaustion."
                key_points = [
                    "Network resource targeting",
                    "Packet crafting capabilities",
                    "Service disruption objectives",
                    "Traffic amplification potential"
                ]
                recommendations = [
                    f"Block {threat_info['src_ip']} at network boundary",
                    "Implement rate limiting on affected services",
                    "Configure DDoS protection mechanisms",
                    "Monitor network bandwidth utilization"
                ]
                risk_level = "High"
                confidence = 0.87
                
            else:
                analysis = f"NETWORK SECURITY ANALYSIS: {threat_info['tool']} activity from {threat_info['src_ip']} targeting {threat_info['dest_ip']}:{threat_info['dest_port']}. {threat_knowledge['description']}"
                key_points = threat_knowledge['detection_indicators'][:3]
                recommendations = threat_knowledge['mitigation'][:3] + [f"Block {threat_info['src_ip']}"]
                risk_level = threat_knowledge['risk_level']
                confidence = 0.8
            
        elif "Threat" in model_config['role']:
            analysis = f"THREAT INTELLIGENCE ANALYSIS: {threat_knowledge['title']} detected from {threat_info['src_ip']}. Category: {threat_knowledge['category']}. Risk Level: {threat_knowledge['risk_level']}."
            
            if threat_info['tool'] == 'nmap':
                key_points = [
                    "Reconnaissance phase of cyber kill chain",
                    "Information gathering for future attacks",
                    "Common precursor to exploitation",
                    "Threat actor profiling opportunity"
                ]
                recommendations = [
                    "Add source IP to threat intelligence feeds",
                    "Correlate with known APT reconnaissance patterns",
                    "Monitor for follow-up exploitation attempts",
                    "Share IOC with industry partners"
                ]
                
            elif threat_info['tool'] == 'hydra':
                key_points = [
                    "Credential-based attack patterns",
                    "Common in ransomware precursor activities", 
                    "Lateral movement preparation",
                    "Persistent threat actor behavior"
                ]
                recommendations = [
                    "Update threat intelligence with credential attack IOCs",
                    "Correlate with credential dumping attempts",
                    "Monitor for successful authentication events",
                    "Check for compromised account usage"
                ]
                
            elif threat_info['tool'] == 'hping3':
                key_points = [
                    "Network layer attack methodology",
                    "DDoS precursor or distraction tactic",
                    "Service availability impact assessment",
                    "Attack sophistication indicators"
                ]
                recommendations = [
                    "Monitor for coordinated attack patterns",
                    "Check threat feeds for similar attack campaigns",
                    "Assess botnet participation possibilities",
                    "Update DDoS protection rules"
                ]
                
            else:
                key_points = [
                    f"Threat Category: {threat_knowledge['category']}",
                    f"Risk Assessment: {threat_knowledge['risk_level']}",
                    f"Source IP: {threat_info['src_ip']} - Requires monitoring",
                    f"Detection Indicators: {', '.join(threat_knowledge['detection_indicators'][:2])}"
                ]
                recommendations = [
                    "Update threat intelligence feeds with this IOC",
                    "Correlate with existing threat data",
                    f"Monitor for related activity from {threat_info['src_ip']}",
                    "Assess campaign-like behavior patterns"
                ]
            
            risk_level = "High" if "High" in threat_knowledge['risk_level'] else "Critical"
            confidence = 0.9
            
        else:  # Incident Response
            analysis = f"INCIDENT RESPONSE ANALYSIS: {threat_knowledge['title']} from {threat_info['src_ip']} requires immediate containment. Attack type: {threat_info['attack_type']}. Severity: {threat_info['severity']}."
            
            if threat_info['tool'] == 'nmap':
                key_points = [
                    f"Immediate containment required for {threat_info['src_ip']}",
                    "Preserve scanning activity logs for investigation",
                    "Check for successful service enumeration",
                    "Assess information disclosure impact"
                ]
                recommendations = [
                    f"Block {threat_info['src_ip']} at all network boundaries",
                    "Collect and preserve firewall and IDS logs",
                    "Scan targeted systems for vulnerabilities",
                    "Implement enhanced monitoring for targeted services"
                ]
                
            elif threat_info['tool'] == 'hydra':
                key_points = [
                    f"Critical: Immediate blocking of {threat_info['src_ip']}",
                    "Review targeted accounts for compromise",
                    "Check authentication logs for successful logins",
                    "Assess credential exposure impact"
                ]
                recommendations = [
                    f"Emergency block of {threat_info['src_ip']}",
                    "Force password reset for targeted accounts",
                    "Implement temporary rate limiting on authentication",
                    "Conduct forensic analysis of authentication systems"
                ]
                
            elif threat_info['tool'] == 'hping3':
                key_points = [
                    f"Immediate network containment for {threat_info['src_ip']}",
                    "Assess service availability impact",
                    "Check for collateral damage to other services",
                    "Monitor for attack escalation"
                ]
                recommendations = [
                    f"Block {threat_info['src_ip']} at ISP level if possible",
                    "Implement emergency rate limiting",
                    "Activate DDoS mitigation services",
                    "Monitor critical service availability"
                ]
                
            else:
                key_points = [
                    f"Immediate containment required for {threat_info['src_ip']}",
                    f"Risk Level: {threat_knowledge['risk_level']} - {threat_info['severity']} severity",
                    f"Target: {threat_info['dest_ip']}:{threat_info['dest_port']} needs protection"
                ] + threat_knowledge['detection_indicators'][:1]
                recommendations = threat_knowledge['mitigation'][:3] + ["Document incident for forensic analysis"]
            
            risk_level = "Critical" if "Critical" in threat_knowledge['risk_level'] else "High"
            confidence = 0.8
        
        return {
            'model_name': model_config['name'],
            'model_role': model_config['role'],
            'specialty': model_config['specialty'],
            'analysis': analysis,
            'confidence': confidence,
            'key_points': key_points,
            'risk_level': risk_level,
            'recommendations': recommendations,
            'threat_specific': True,
            'threat_tool': threat_info['tool'],
            'threat_type': threat_info['attack_type']
        }
    
    def _parse_expert_analysis_with_rag(self, analysis_text: str, context: List[Tuple[Dict, float]], threat_info: Dict) -> Dict:
        """Parse expert analysis with threat-specific context awareness"""
        result = {
            'analysis': analysis_text,
            'confidence': 0.7,
            'key_points': [],
            'risk_level': 'Medium',
            'recommendations': [],
            'threat_specific': True,
            'threat_tool': threat_info['tool'],
            'threat_type': threat_info['attack_type']
        }
        
        # Enhanced parsing with threat context
        lines = analysis_text.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Detect risk level
            if 'risk' in line.lower() and 'level' in line.lower():
                risk_match = re.search(r'\b(Critical|High|Medium|Low)\b', line, re.IGNORECASE)
                if risk_match:
                    result['risk_level'] = risk_match.group(0).capitalize()
            
            # Extract confidence
            if 'confidence' in line.lower():
                conf_match = re.search(r'(\d+\.?\d*)', line)
                if conf_match:
                    try:
                        conf_value = float(conf_match.group(1))
                        if conf_value > 1.0:
                            conf_value = conf_value / 100.0
                        result['confidence'] = min(max(conf_value, 0.1), 1.0)
                    except ValueError:
                        pass
            
            # Extract key points and recommendations
            if line.startswith(('-', '•', '*')) or (line and line[0].isdigit() and '. ' in line):
                clean_line = re.sub(r'^[-•*\d+\.\s]+', '', line).strip()
                if clean_line:
                    is_recommendation = any(word in clean_line.lower() for word in 
                                          ['implement', 'enable', 'block', 'monitor', 'update', 
                                           'configure', 'review', 'install', 'deploy', 'recommend'])
                    
                    if is_recommendation and len(result['recommendations']) < 4:
                        result['recommendations'].append(clean_line)
                    elif len(result['key_points']) < 4:
                        result['key_points'].append(clean_line)
        
        # Ensure we have threat-specific content
        if not result['key_points']:
            threat_knowledge = self.agent.threat_knowledge_base.get_threat_knowledge(threat_info['tool'])
            result['key_points'] = [
                f"{threat_info['tool']} {threat_info['attack_type']} detected from {threat_info['src_ip']}",
                f"Targeting {threat_info['dest_ip']}:{threat_info['dest_port']} via {threat_info['proto']}",
                f"Attack category: {threat_knowledge['category']}",
                f"Risk level: {threat_knowledge['risk_level']}"
            ]
        
        if not result['recommendations']:
            threat_knowledge = self.agent.threat_knowledge_base.get_threat_knowledge(threat_info['tool'])
            result['recommendations'] = threat_knowledge['mitigation'][:3] + [f"Block {threat_info['src_ip']}"]
        
        return result
    
    def _generate_comprehensive_solution(self, query: str, context: List[Tuple[Dict, float]], expert_analyses: List[Dict], threat_info: Dict) -> Dict:
        """Generate comprehensive solution using threat-specific context"""
        try:
            print(f"🔧 Generating THREAT-SPECIFIC comprehensive solution for {threat_info['tool']}...")
            
            # Prepare synthesis context
            synthesis_context = self._prepare_synthesis_context(expert_analyses, context, threat_info)
            
            solution_prompt = self._create_threat_specific_solution_prompt(query, synthesis_context, threat_info)
            
            response = self.agent._safe_api_call(
                {'model': self.config.PRIMARY_MODEL, 'name': 'Solution Architect'},
                [
                    {"role": "system", "content": f"You are a cybersecurity solution architect. Create a comprehensive security solution SPECIFICALLY for this {threat_info['tool']} {threat_info['attack_type']} attack from {threat_info['src_ip']}."},
                    {"role": "user", "content": solution_prompt}
                ],
                max_tokens=500
            )
            
            # FIXED: Enhanced safety checks
            if response and hasattr(response, 'choices') and response.choices and len(response.choices) > 0:
                solution_text = response.choices[0].message.content.strip()
                # Clean up any truncation markers
                solution_text = re.sub(r'<s>\[(OUT|BOT|INST)\]', '', solution_text).strip()
                return self._parse_comprehensive_solution(solution_text, expert_analyses, threat_info)
            else:
                raise ValueError("Empty solution response")
                
        except Exception as e:
            print(f"❌ Threat-specific solution generation failed: {e}")
            return self._create_rag_fallback_solution(expert_analyses, query, threat_info)
    
    def _prepare_synthesis_context(self, expert_analyses: List[Dict], context: List[Tuple[Dict, float]], threat_info: Dict) -> str:
        """Prepare context for solution synthesis with threat info"""
        synthesis = f"THREAT-SPECIFIC EXPERT ANALYSES FOR {threat_info['tool'].upper()} {threat_info['attack_type'].upper()} ATTACK:\n\n"
        
        for i, analysis in enumerate(expert_analyses, 1):
            synthesis += f"--- Expert {i}: {analysis['model_name']} ---\n"
            synthesis += f"Specialty: {analysis['specialty']}\n"
            synthesis += f"Risk: {analysis['risk_level']} | Confidence: {analysis['confidence']:.2f}\n"
            synthesis += f"Analysis: {analysis['analysis'][:200]}...\n"
            synthesis += f"Key Points: {', '.join(analysis['key_points'][:2])}\n\n"
        
        synthesis += f"ATTACK SPECIFICS:\n"
        synthesis += f"- Tool: {threat_info['tool']}\n"
        synthesis += f"- Type: {threat_info['attack_type']}\n"
        synthesis += f"- Source: {threat_info['src_ip']}\n"
        synthesis += f"- Target: {threat_info['dest_ip']}:{threat_info['dest_port']}\n"
        synthesis += f"- Protocol: {threat_info['proto']}\n"
        synthesis += f"- Severity: {threat_info['severity']}\n"
        
        return synthesis
    
    def _create_threat_specific_solution_prompt(self, query: str, synthesis_context: str, threat_info: Dict) -> str:
        """Create prompt for threat-specific solution generation"""
        return f"""Create a COMPREHENSIVE security solution SPECIFICALLY for this {threat_info['tool']} {threat_info['attack_type']} attack.

ATTACK DETAILS:
{query}

{synthesis_context}

Provide a UNIFIED security solution SPECIFIC to this {threat_info['tool']} {threat_info['attack_type']} attack with:
1. Overall analysis and risk assessment for this specific threat
2. Recommended solution approach tailored to {threat_info['tool']} {threat_info['attack_type']}
3. Implementation steps specific to this attack vector
4. Monitoring recommendations for similar {threat_info['tool']} activity
5. Overall confidence score

Be SPECIFIC to this {threat_info['tool']} {threat_info['attack_type']} attack from {threat_info['src_ip']}."""

    def _parse_comprehensive_solution(self, solution_text: str, expert_analyses: List[Dict], threat_info: Dict) -> Dict:
        """Parse the comprehensive solution response with threat context"""
        threat_knowledge = self.agent.threat_knowledge_base.get_threat_knowledge(threat_info['tool'])
        
        # Parse the solution text for specific sections
        sections = {
            'analysis': solution_text,
            'solution': f"Implement {threat_knowledge['category']}-specific security controls",
            'implementation': [
                f"1. Immediate containment of {threat_info['src_ip']}",
                f"2. {threat_info['tool']}-specific forensic investigation",
                f"3. {threat_knowledge['category']} security control implementation",
                "4. Validation and continuous monitoring"
            ],
            'monitoring': [
                f"Real-time monitoring for {threat_info['tool']} patterns",
                f"Network traffic analysis from {threat_info['src_ip']}",
                f"Threat intelligence integration for {threat_knowledge['category']}",
                f"Service-specific monitoring for {threat_info['dest_port']}"
            ],
            'risk_assessment': 'High',
            'confidence': 0.7
        }
        
        # Try to extract more specific information from solution text
        lines = solution_text.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Detect sections
            if 'implementation' in line.lower() or 'steps' in line.lower():
                current_section = 'implementation'
            elif 'monitor' in line.lower() or 'detection' in line.lower():
                current_section = 'monitoring'
            elif 'risk' in line.lower() and 'assessment' in line.lower():
                current_section = 'risk'
            elif 'solution' in line.lower() or 'recommend' in line.lower():
                current_section = 'solution'
            elif line.startswith(('1.', '2.', '3.', '4.', '-', '•')):
                # This is a list item
                clean_line = re.sub(r'^[•\d\.\-\s]+', '', line).strip()
                if current_section == 'implementation' and len(sections['implementation']) < 6:
                    sections['implementation'].append(clean_line)
                elif current_section == 'monitoring' and len(sections['monitoring']) < 6:
                    sections['monitoring'].append(clean_line)
        
        # Calculate overall confidence from experts
        confidences = [analysis['confidence'] for analysis in expert_analyses]
        if confidences:
            sections['confidence'] = sum(confidences) / len(confidences)
        
        # Determine overall risk level
        risk_levels = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
        expert_risks = [risk_levels.get(analysis.get('risk_level', 'Medium'), 2) for analysis in expert_analyses]
        if expert_risks:
            max_risk = max(expert_risks)
            sections['risk_assessment'] = [k for k, v in risk_levels.items() if v == max_risk][0]
        
        return sections
    
    def _create_rag_fallback_solution(self, expert_analyses: List[Dict], query: str, threat_info: Dict) -> Dict:
        """Create threat-specific fallback solution"""
        threat_knowledge = self.agent.threat_knowledge_base.get_threat_knowledge(threat_info['tool'])
        
        # Calculate metrics
        confidences = [analysis['confidence'] for analysis in expert_analyses if analysis.get('confidence')]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.7
        
        risk_levels = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
        expert_risks = [risk_levels.get(analysis.get('risk_level', 'Medium'), 2) for analysis in expert_analyses]
        max_risk = max(expert_risks) if expert_risks else 2
        overall_risk = [k for k, v in risk_levels.items() if v == max_risk][0]
        
        # Threat-specific solution templates
        if threat_info['tool'] == 'nmap':
            solution = "Implement comprehensive network reconnaissance detection and prevention controls including port scan detection, service obfuscation, and enhanced logging."
            implementation = [
                f"1. Immediate network perimeter blocking of {threat_info['src_ip']}",
                "2. Deploy port scan detection rules in IDS/IPS",
                "3. Review and harden exposed services",
                "4. Implement network segmentation and service hiding"
            ]
            monitoring = [
                "Continuous port scan pattern monitoring",
                "Network reconnaissance detection alerts",
                "Service access pattern analysis",
                "Threat intelligence integration for scanning IPs"
            ]
            
        elif threat_info['tool'] == 'hydra':
            solution = "Deploy multi-layered authentication protection including account lockout, MFA, and credential monitoring."
            implementation = [
                f"1. Emergency blocking of {threat_info['src_ip']}",
                "2. Implement account lockout policies",
                "3. Enable multi-factor authentication",
                "4. Conduct credential compromise assessment"
            ]
            monitoring = [
                "Real-time authentication failure monitoring",
                "Brute force pattern detection",
                "Successful login correlation",
                "Credential stuffing attack alerts"
            ]
            
        elif threat_info['tool'] == 'hping3':
            solution = "Activate DDoS protection and network resilience measures including rate limiting and traffic filtering."
            implementation = [
                f"1. Immediate network-level blocking of {threat_info['src_ip']}",
                "2. Implement traffic rate limiting",
                "3. Configure DDoS protection services",
                "4. Establish service redundancy"
            ]
            monitoring = [
                "Network traffic volume monitoring",
                "DDoS attack pattern detection",
                "Service availability tracking",
                "Bandwidth utilization alerts"
            ]
            
        else:
            solution = f"Implement {threat_knowledge['category']}-specific security framework for {threat_info['tool']} attacks."
            implementation = [
                f"1. Immediate containment of {threat_info['src_ip']}",
                f"2. {threat_info['attack_type']}-specific investigation",
                f"3. Security control implementation for {threat_knowledge['category']}",
                "4. Continuous monitoring and validation"
            ]
            monitoring = [
                f"Real-time monitoring for {threat_info['tool']} patterns",
                f"Network traffic analysis from {threat_info['src_ip']}",
                f"Threat intelligence integration for {threat_knowledge['category']}",
                "Behavioral anomaly detection"
            ]
        
        return {
            'analysis': f"Threat-specific analysis: {threat_knowledge['title']} detected from {threat_info['src_ip']}. {threat_knowledge['description']}",
            'solution': solution,
            'implementation': implementation,
            'monitoring': monitoring,
            'risk_assessment': overall_risk,
            'confidence': avg_confidence
        }
    
    def _generate_rag_enhanced_fallback_solution(self, query: str, context: List[Tuple[Dict, float]], threat_info: Dict) -> Dict:
        """Generate threat-specific fallback solution when API is unavailable"""
        threat_knowledge = self.agent.threat_knowledge_base.get_threat_knowledge(threat_info['tool'])
        
        # Threat-specific fallback content
        if threat_info['tool'] == 'nmap':
            expert_analysis = {
                'model_name': 'RAG-Enhanced Network Security',
                'model_role': 'Network Security Analyst',
                'specialty': 'Port scanning detection and prevention',
                'analysis': f'Network reconnaissance detected: nmap port scanning from {threat_info["src_ip"]} targeting {threat_info["dest_ip"]}:{threat_info["dest_port"]}. This is typically reconnaissance for vulnerability assessment.',
                'confidence': 0.85,
                'key_points': [
                    "Port scanning reconnaissance activity",
                    "Network service enumeration attempt",
                    "Pre-attack information gathering phase",
                    "Potential vulnerability scanning precursor"
                ],
                'risk_level': 'High',
                'recommendations': [
                    f"Block {threat_info['src_ip']} at network perimeter",
                    "Implement port scan detection mechanisms",
                    "Review exposed services for vulnerabilities",
                    "Monitor for follow-up exploitation attempts"
                ],
                'threat_specific': True
            }
            consensus = "nmap port scanning incident requires immediate network-level containment and enhanced monitoring for follow-up attacks."
            
        elif threat_info['tool'] == 'hydra':
            expert_analysis = {
                'model_name': 'RAG-Enhanced Authentication Security',
                'model_role': 'Authentication Security Specialist',
                'specialty': 'Brute force attack detection and prevention',
                'analysis': f'Credential attack detected: hydra brute force from {threat_info["src_ip"]} targeting {threat_info["dest_ip"]}:{threat_info["dest_port"]}. Rapid password guessing attempts against authentication service.',
                'confidence': 0.9,
                'key_points': [
                    "Authentication service targeting",
                    "Credential stuffing attack patterns",
                    "Account compromise risk",
                    "Lateral movement preparation"
                ],
                'risk_level': 'Critical',
                'recommendations': [
                    f"Immediately block {threat_info['src_ip']}",
                    "Implement account lockout policies",
                    "Enable multi-factor authentication",
                    "Review authentication logs for compromises"
                ],
                'threat_specific': True
            }
            consensus = "hydra brute force attack requires immediate containment, credential protection, and authentication hardening."
            
        elif threat_info['tool'] == 'hping3':
            expert_analysis = {
                'model_name': 'RAG-Enhanced Network Protection',
                'model_role': 'DDoS Protection Specialist',
                'specialty': 'Flood attack mitigation',
                'analysis': f'Denial of Service attack detected: hping3 network flooding from {threat_info["src_ip"]} targeting {threat_info["dest_ip"]}:{threat_info["dest_port"]}. Potential service disruption attempt.',
                'confidence': 0.87,
                'key_points': [
                    "Network resource exhaustion attempt",
                    "Service availability impact",
                    "Traffic flooding patterns",
                    "DDoS attack characteristics"
                ],
                'risk_level': 'High',
                'recommendations': [
                    f"Block {threat_info['src_ip']} at network boundary",
                    "Implement traffic rate limiting",
                    "Activate DDoS protection services",
                    "Monitor service availability metrics"
                ],
                'threat_specific': True
            }
            consensus = "hping3 DoS attack requires immediate network containment and service protection measures."
            
        else:
            expert_analysis = {
                'model_name': 'RAG-Enhanced Security Engine',
                'model_role': 'Security Analyst',
                'specialty': 'Comprehensive security analysis',
                'analysis': f'Threat-specific analysis: {threat_knowledge["description"]} from {threat_info["src_ip"]} targeting {threat_info["dest_ip"]}:{threat_info["dest_port"]}',
                'confidence': 0.8,
                'key_points': [
                    f"Tool: {threat_info['tool']}",
                    f"Source: {threat_info['src_ip']}",
                    f"Target: {threat_info['dest_ip']}:{threat_info['dest_port']}",
                    f"Type: {threat_info['attack_type']}",
                    f"Category: {threat_knowledge['category']}"
                ],
                'risk_level': 'High' if 'High' in threat_knowledge['risk_level'] else 'Medium',
                'recommendations': threat_knowledge['mitigation'][:3] + [f"Block {threat_info['src_ip']}"],
                'threat_specific': True
            }
            consensus = f"{threat_knowledge['title']} incident from {threat_info['src_ip']} requires immediate response and specific security controls."
        
        return {
            'timestamp': datetime.now().isoformat(),
            'query': query,
            'expert_analyses': [expert_analysis],
            'consensus_analysis': consensus,
            'recommended_solution': f"Implement {threat_knowledge['category']}-specific security framework for {threat_info['tool']}.",
            'implementation_steps': [
                f"1. Immediate {threat_info['tool']} containment from {threat_info['src_ip']}",
                f"2. Block {threat_info['src_ip']} at network perimeter",
                f"3. Conduct {threat_info['attack_type']} forensic analysis",
                f"4. Implement {threat_knowledge['category']} security controls"
            ],
            'monitoring_recommendations': [
                f"24/7 monitoring for {threat_info['tool']} patterns",
                f"Monitor traffic from {threat_info['src_ip']}",
                f"Endpoint protection for {threat_knowledge['category']}",
                f"Service-specific monitoring for port {threat_info['dest_port']}"
            ],
            'risk_assessment': 'High',
            'sources_used': [ctx[0]['title'] for ctx in context] if context else [],
            'confidence_score': 0.75,
            'models_used': ['RAG-Enhanced Security Engine'],
            'ai_generated': False,
            'fallback_used': True,
            'multi_expert_analysis_used': False,
            'expert_count': 1,
            'rag_used': len(context) > 0,
            'threat_specific_info': threat_info
        }
    
    def _create_error_response(self, query: str, error_msg: str) -> Dict:
        threat_info = self._extract_threat_info_from_query(query)
        error_result = self._generate_rag_enhanced_fallback_solution(query, [], threat_info)
        error_result['error'] = error_msg
        return error_result

    def _format_rag_context_for_llm(self, context: List[Tuple[Dict, float]]) -> str:
        """Format RAG context for LLM consumption"""
        if not context:
            return "No specific security knowledge available for this threat type."
        
        formatted_parts = ["RELEVANT SECURITY KNOWLEDGE:"]
        for i, (metadata, score) in enumerate(context, 1):
            context_text = f"\n--- Source {i} (Relevance: {score:.2f}) ---\n"
            context_text += f"Title: {metadata.get('title', 'N/A')}\n"
            content_preview = metadata.get('content', 'N/A')[:200] + "..." if len(metadata.get('content', '')) > 200 else metadata.get('content', 'N/A')
            context_text += f"Content: {content_preview}\n"
            formatted_parts.append(context_text)
        
        return "\n".join(formatted_parts)

# =============================================================================
# ENHANCED KNOWLEDGE BASE MANAGER
# =============================================================================

class KnowledgeBaseManager:
    """Manages the knowledge base for explanations"""
    
    def __init__(self, agent: OptimizedDebateAgent):
        self.agent = agent
        self.config = agent.config
    
    def add_explanation_documents(self, documents: List[Dict]):
        """Add explanation documents to the knowledge base"""
        try:
            print(f"📝 Adding {len(documents)} documents to knowledge base...")
            texts_to_embed = []
            new_metadata = []
            
            for doc in documents:
                embedding_text = self._prepare_embedding_text(doc)
                texts_to_embed.append(embedding_text)
                
                metadata = {
                    'id': len(self.agent.metadata) + len(new_metadata),
                    'title': doc.get('title', 'Untitled'),
                    'content': doc.get('content', ''),
                    'category': doc.get('category', 'general'),
                    'tags': doc.get('tags', []),
                    'source': doc.get('source', 'manual'),
                    'timestamp': datetime.now().isoformat()
                }
                new_metadata.append(metadata)
            
            embeddings = self.agent.embedding_model.encode(texts_to_embed)
            embedding_matrix = np.array(embeddings).astype('float32')
            
            if self.agent.vector_index is None:
                dimension = embedding_matrix.shape[1]
                self.agent.vector_index = faiss.IndexFlatL2(dimension)
                print(f"📊 Created new FAISS index with dimension {dimension}")
            
            self.agent.vector_index.add(embedding_matrix)
            self.agent.metadata.extend(new_metadata)
            
            self._save_knowledge_base()
            
            print(f"✅ Added {len(documents)} explanation documents to knowledge base")
            return True
            
        except Exception as e:
            print(f"❌ Error adding documents: {e}")
            return False
    
    def _prepare_embedding_text(self, document: Dict) -> str:
        title = document.get('title', '')
        content = document.get('content', '')
        category = document.get('category', '')
        tags = ' '.join(document.get('tags', []))
        return f"{title} {content} {category} {tags}".strip()
    
    def _save_knowledge_base(self):
        try:
            if self.agent.vector_index is not None:
                faiss.write_index(self.agent.vector_index, self.config.INDEX_PATH)
            
            with open(self.config.METADATA_PATH, 'w', encoding='utf-8') as f:
                json.dump(self.agent.metadata, f, indent=2, ensure_ascii=False)
            
            print("💾 Knowledge base saved successfully")
        except Exception as e:
            print(f"❌ Error saving knowledge base: {e}")

# =============================================================================
# ENHANCED RETRIEVAL SYSTEM WITH THREAT-SPECIFIC QUERIES
# =============================================================================

class ExplanationRetriever:
    def __init__(self, agent: OptimizedDebateAgent):
        self.agent = agent
        self.config = agent.config
    
    def retrieve_relevant_explanations(self, query: str, top_k: int = None) -> List[Tuple[Dict, float]]:
        """Retrieve relevant explanations with threat-specific queries"""
        if (self.agent.vector_index is None or 
            len(self.agent.metadata) == 0 or not query.strip()):
            print("⚠️ No knowledge base available for retrieval")
            return []
        
        try:
            # Enhance query with threat-specific terms
            enhanced_query = self._enhance_query_with_threat_context(query)
            
            query_embedding = self.agent.embedding_model.encode([enhanced_query])
            query_vector = np.array(query_embedding).reshape(1, -1).astype('float32')
            
            if top_k is None:
                top_k = self.config.TOP_K
            
            actual_top_k = min(int(top_k), len(self.agent.metadata))
            if actual_top_k == 0:
                return []
            
            distances, indices = self.agent.vector_index.search(query_vector, actual_top_k)
            
            results = []
            for i, (idx, distance) in enumerate(zip(indices[0], distances[0])):
                if 0 <= idx < len(self.agent.metadata):
                    similarity_score = 1 / (1 + distance)
                    if similarity_score >= self.config.SIMILARITY_THRESHOLD:
                        results.append((self.agent.metadata[idx], similarity_score))
            
            results.sort(key=lambda x: x[1], reverse=True)
            
            print(f"🔍 Retrieved {len(results)} relevant explanations for query: {enhanced_query}")
            return results
            
        except Exception as e:
            print(f"❌ Error during retrieval: {e}")
            return []
    
    def _enhance_query_with_threat_context(self, query: str) -> str:
        """Enhance query with threat-specific context for better retrieval"""
        enhanced_query = query
        
        # Add threat-specific context
        threat_keywords = {
            'nmap': 'port scanning network reconnaissance security audit',
            'hydra': 'brute force password attack authentication credential',
            'hping3': 'network testing packet crafting dos attack syn flood', 
            'sqlmap': 'sql injection database web application security',
            'metasploit': 'exploitation framework penetration testing payload'
        }
        
        for threat, keywords in threat_keywords.items():
            if threat in query.lower():
                enhanced_query += " " + keywords
                break
        
        return enhanced_query

# =============================================================================
# MAIN ENHANCED AGENT - WITH FIXES
# =============================================================================

class AdvancedOptimizedDebateAgent:
    """Complete Optimized Multi-Expert Debate Agent with RAG - FIXED VERSION"""
    
    def __init__(self, config: DebateConfig = None):
        self.config = config or DebateConfig()
        self.core_agent = OptimizedDebateAgent(self.config)
        self.knowledge_manager = KnowledgeBaseManager(self.core_agent)
        self.retriever = ExplanationRetriever(self.core_agent)
        self.debate_generator = OptimizedDebateGenerator(self.core_agent)
        
        print("🚀 Advanced Optimized Debate Agent with RAG initialized")
        self._initialize_enhanced_knowledge()
    
    def _initialize_enhanced_knowledge(self):
        """Initialize with enhanced security knowledge"""
        try:
            security_docs = create_comprehensive_security_knowledge_base()
            success = self.knowledge_manager.add_explanation_documents(security_docs)
            if success:
                print("✅ Comprehensive security knowledge base initialized")
            else:
                print("❌ Failed to initialize security knowledge base")
        except Exception as e:
            print(f"❌ Could not initialize security knowledge: {e}")
    
    def add_knowledge(self, documents: List[Dict]) -> bool:
        return self.knowledge_manager.add_explanation_documents(documents)
    
    def analyze_and_solve(self, query: str, top_k: int = None) -> Dict:
        print(f"🔍 Analyzing query with RAG: {query[:100]}...")
        context = self.retriever.retrieve_relevant_explanations(query, top_k)
        result = self.debate_generator.generate_debate_and_solution(query, context)
        return result
    
    def get_agent_stats(self) -> Dict:
        return {
            'knowledge_base_size': len(self.core_agent.metadata),
            'debate_history_count': len(self.core_agent.debate_history),
            'index_loaded': self.core_agent.vector_index is not None,
            'fallback_mode': self.core_agent.fallback_mode,
            'llm_available': self.core_agent.llm_client is not None and not self.core_agent.fallback_mode,
            'api_key_valid': getattr(self.core_agent, 'api_key_valid', False),
            'debate_models': len([m for m in self.config.DEBATE_MODELS if m.get('working', True)]),
            'primary_model': self.config.PRIMARY_MODEL,
            'api_usage_today': self.core_agent.usage_tracker.requests_today,
            'api_daily_limit': self.core_agent.usage_tracker.daily_limit,
            'rag_enabled': True
        }

# =============================================================================
# ENHANCED SECURITY KNOWLEDGE BASE
# =============================================================================

def create_comprehensive_security_knowledge_base():
    """Create comprehensive security knowledge base for RAG system"""
    security_documents = [
        {
            'title': 'Nmap Port Scanning Techniques',
            'content': 'Nmap (Network Mapper) is a security scanner used to discover hosts and services on a computer network. It uses raw IP packets to determine available hosts, services, operating systems, packet filters/firewalls, and other characteristics. Common techniques include TCP SYN scanning, TCP connect scanning, UDP scanning, version detection, and OS detection.',
            'category': 'reconnaissance',
            'tags': ['nmap', 'port scanning', 'network reconnaissance', 'security audit']
        },
        {
            'title': 'Hydra Brute Force Attacks',
            'content': 'Hydra is a parallelized login cracker that supports numerous protocols to attack. It is very fast and flexible, and new modules are easy to add. Hydra works by using different approaches of generating passwords, including dictionary attacks, brute force attacks, and hybrid attacks. It supports protocols like SSH, FTP, HTTP, HTTPS, SMB, and many others.',
            'category': 'bruteforce',
            'tags': ['hydra', 'brute force', 'password attack', 'authentication']
        },
        {
            'title': 'Hping3 Network Testing and Attacks',
            'content': 'Hping3 is a network tool able to send custom TCP/IP packets and to display target replies. It can be used for network testing, manual path MTU discovery, advanced traceroute, remote OS fingerprinting, firewall testing, and as a network security tool. It is often used for SYN flood attacks, UDP flood attacks, and other network-based attacks.',
            'category': 'network_attack',
            'tags': ['hping3', 'network testing', 'packet crafting', 'dos attack']
        },
        {
            'title': 'SQL Injection Attacks and Prevention',
            'content': 'SQL injection is a code injection technique that might destroy your database. It is one of the most common web hacking techniques. SQL injection is the placement of malicious code in SQL statements, via web page input. Prevention methods include using prepared statements with parameterized queries, input validation, and web application firewalls.',
            'category': 'web_attack',
            'tags': ['sql injection', 'web security', 'database attack', 'owasp']
        },
        {
            'title': 'Metasploit Framework for Penetration Testing',
            'content': 'The Metasploit Framework is an open-source penetration testing platform that provides information about security vulnerabilities and aids in penetration testing and IDS signature development. It includes tools for developing and executing exploit code against a remote target machine, performing security vulnerability assessments, and managing security testing processes.',
            'category': 'exploitation',
            'tags': ['metasploit', 'penetration testing', 'exploitation', 'security framework']
        },
        {
            'title': 'Network Security Fundamentals',
            'content': 'Network security involves protecting network infrastructure from unauthorized access, misuse, or attacks. Key components include firewalls, intrusion detection systems (IDS), intrusion prevention systems (IPS), and access control mechanisms. Defense in depth strategy employs multiple layers of security controls throughout the network.',
            'category': 'security',
            'tags': ['network security', 'firewall', 'ids', 'ips', 'access control']
        },
        {
            'title': 'Incident Response Framework',
            'content': 'The incident response process includes preparation, detection, containment, eradication, recovery, and lessons learned phases for effective security incident management. A well-defined incident response plan helps organizations respond quickly and effectively to security incidents, minimizing damage and recovery time.',
            'category': 'incident_response',
            'tags': ['incident response', 'containment', 'eradication', 'recovery']
        }
    ]
    return security_documents

# =============================================================================
# ENHANCED SECURITY DEBATE AGENT
# =============================================================================

class SecurityDebateAgent:
    def __init__(self, base_agent: AdvancedOptimizedDebateAgent):
        self.agent = base_agent
        
    def analyze_security_incident(self, detection_data: Dict) -> Dict:
        print("🛡️ Analyzing security incident with RAG-based multi-expert system...")
        
        # DEBUG: Print what we're receiving
        print(f"🔍 DEBUG - Detection data received:")
        print(f"   Tool: {detection_data.get('tool', 'MISSING')}")
        print(f"   Source IP: {detection_data.get('source_ip', detection_data.get('src_ip', 'MISSING'))}")
        print(f"   Attack Type: {detection_data.get('attack_type', 'MISSING')}")
        
        query = self._build_security_query(detection_data)
        result = self.agent.analyze_and_solve(query, top_k=3)
        return self._enhance_security_result(result, detection_data)
    
    def _build_security_query(self, detection_data: Dict) -> str:
        """Build query with ACTUAL threat data that can be parsed"""
        
        # Extract data with fallbacks for different field names
        tool = detection_data.get('tool', 'unknown')
        src_ip = detection_data.get('src_ip', detection_data.get('source_ip', 'unknown'))
        dest_ip = detection_data.get('dest_ip', detection_data.get('target_ip', 'unknown'))
        dest_port = detection_data.get('dest_port', detection_data.get('target_port', 'unknown'))
        proto = detection_data.get('proto', detection_data.get('protocol', 'unknown'))
        attack_type = detection_data.get('attack_type', 'unknown')
        severity = detection_data.get('severity', 'unknown')
        confidence = detection_data.get('confidence', detection_data.get('final_confidence', 0))
        risk_score = detection_data.get('risk_score', 0)
        
        # CRITICAL FIX: Ensure we have SPECIFIC attack types, not generic ones
        if attack_type.lower() in ['potential security threat', 'unknown', '']:
            # Infer from tool if possible
            tool_to_attack = {
                'nmap': 'port_scan',
                'hydra': 'bruteforce',
                'hping3': 'dos', 
                'sqlmap': 'sql_injection',
                'metasploit': 'exploitation'
            }
            if tool in tool_to_attack:
                attack_type = tool_to_attack[tool]
                print(f"✅ Inferred specific attack type from tool: {attack_type}")
        
        # Create a JSON-like structure that the threat extractor can parse
        query_data = {
            'tool': tool,
            'src_ip': src_ip,
            'dest_ip': dest_ip, 
            'dest_port': dest_port,
            'proto': proto,
            'attack_type': attack_type,  # Now this should be specific
            'severity': severity,
            'confidence': confidence,
            'risk_score': risk_score,
            'description': detection_data.get('description', '')
        }
        
        # Convert to string that mimics JSON format for parsing
        query_lines = [
            "SECURITY INCIDENT FOR EXPERT ANALYSIS:",
            f'{{"tool": "{tool}", "src_ip": "{src_ip}", "dest_ip": "{dest_ip}", "dest_port": {dest_port}, "proto": "{proto}", "attack_type": "{attack_type}", "severity": "{severity}"}}',
            "",
            "INCIDENT DETAILS:",
            f"- Attack Type: {attack_type}",
            f"- Confidence: {confidence}%",
            f"- Risk Score: {risk_score}",
            f"- Source: {src_ip} → {dest_ip}:{dest_port}",
            f"- Protocol: {proto}",
            f"- Tool: {tool}",
            f"- Severity: {severity}",
            "",
            "Multiple cybersecurity experts should analyze this incident using security knowledge base and provide comprehensive solutions."
        ]
        
        return "\n".join(query_lines)
    
    def _enhance_security_result(self, result: Dict, detection_data: Dict) -> Dict:
        """Enhance the result with security-specific formatting"""
        enhanced_result = result.copy()
        
        # Get the actual threat info from the detection data
        tool = detection_data.get('tool', 'unknown')
        src_ip = detection_data.get('src_ip', detection_data.get('source_ip', 'unknown'))
        dest_ip = detection_data.get('dest_ip', detection_data.get('target_ip', 'unknown'))
        dest_port = detection_data.get('dest_port', detection_data.get('target_port', 'unknown'))
        
        if 'consensus_analysis' in result:
            header = f"🔒 **RAG-ENHANCED MULTI-EXPERT CYBERSECURITY SOLUTION** 🔒\n\n"
            header += f"**Incident Summary:**\n"
            header += f"- **Type:** {detection_data.get('attack_type', 'Unknown')}\n"
            header += f"- **Tool:** {tool}\n"
            header += f"- **Source:** {src_ip} → **Target:** {dest_ip}:{dest_port}\n"
            header += f"- **Protocol:** {detection_data.get('proto', detection_data.get('protocol', 'Unknown'))}\n"
            header += f"- **Severity:** {detection_data.get('severity', 'Unknown')}\n"
            header += f"- **Confidence:** {detection_data.get('confidence', detection_data.get('final_confidence', 0))}%\n"
            header += f"- **Risk Score:** {detection_data.get('risk_score', 0)}\n\n"
            
            if result.get('rag_used', False):
                header += "> 📚 *RAG-Enhanced Security Knowledge Base Used*\n\n"
            elif result.get('fallback_used'):
                header += "> ⚠️ *Enhanced Security Analysis Engine*\n\n"
            else:
                expert_count = result.get('expert_count', 0)
                multi_expert_used = result.get('multi_expert_analysis_used', False)
                
                if multi_expert_used:
                    header += f"> 🤖 *AI-Powered Multi-Expert Analysis ({expert_count} experts)*\n\n"
                else:
                    header += f"> ⚡ *AI Security Analysis*\n\n"
            
            header += "---\n\n"
            
            enhanced_result['formatted_output'] = header + self._format_comprehensive_result(result)
        
        return enhanced_result
    
    def _format_comprehensive_result(self, result: Dict) -> str:
        """Format the comprehensive result for display"""
        output = ""
        
        # Expert Analyses
        if 'expert_analyses' in result and result['expert_analyses']:
            output += "## 🎯 EXPERT ANALYSES\n\n"
            for analysis in result['expert_analyses']:
                output += f"**{analysis['model_name']}** ({analysis['model_role']})\n"
                output += f"*Specialty: {analysis['specialty']}*\n"
                output += f"*Risk Level: {analysis.get('risk_level', 'Medium')} | Confidence: {analysis['confidence']:.2f}*\n"
                if analysis.get('analysis'):
                    # Show first 150 chars of analysis
                    analysis_preview = analysis['analysis']
                    if len(analysis_preview) > 150:
                        analysis_preview = analysis_preview[:150] + "..."
                    output += f"*Analysis:* {analysis_preview}\n"
                if analysis.get('key_points'):
                    output += f"*Key Insights:* {', '.join(analysis['key_points'][:3])}\n"
                output += "\n"
        
        # Consensus Analysis
        if 'consensus_analysis' in result:
            output += "## 🤝 UNIFIED ANALYSIS\n\n"
            output += f"{result['consensus_analysis']}\n\n"
        
        # Risk Assessment
        if 'risk_assessment' in result:
            output += f"## ⚠️ RISK ASSESSMENT: {result['risk_assessment'].upper()}\n\n"
        
        # Recommended Solution
        if 'recommended_solution' in result:
            output += "## 🛡️ RECOMMENDED SOLUTION\n\n"
            output += f"{result['recommended_solution']}\n\n"
        
        # Implementation Steps
        if 'implementation_steps' in result:
            output += "## 📋 IMPLEMENTATION ROADMAP\n\n"
            for step in result['implementation_steps']:
                output += f"• {step}\n"
            output += "\n"
        
        # Monitoring Recommendations
        if 'monitoring_recommendations' in result and result['monitoring_recommendations']:
            output += "## 📊 MONITORING & VALIDATION\n\n"
            for monitor in result['monitoring_recommendations']:
                output += f"• {monitor}\n"
            output += "\n"
        
        # Confidence Score
        output += f"**Overall Confidence: {result.get('confidence_score', 0.7):.2f}**\n\n"
        
        # RAG and multi-expert usage indicator
        expert_count = result.get('expert_count', 0)
        multi_expert_used = result.get('multi_expert_analysis_used', False)
        rag_used = result.get('rag_used', False)
        
        if rag_used and multi_expert_used:
            output += f"*✅ RAG-Enhanced Multi-Expert AI Analysis Applied ({expert_count} experts)*\n"
        elif rag_used:
            output += f"*📚 RAG-Enhanced Security Analysis Completed*\n"
        elif multi_expert_used:
            output += f"*🤖 Multi-Expert AI Analysis Successfully Applied ({expert_count} experts)*\n"
        elif result.get('fallback_used', False):
            output += "*🔄 Enhanced Security Analysis Engine Used*\n"
        else:
            output += f"*⚡ AI Security Analysis Completed*\n"
        
        return output

# =============================================================================
# SIMPLIFIED INTERFACE - WITH FIXES
# =============================================================================

class SimpleOptimizedDebateAgent:
    def __init__(self):
        print("🚀 Initializing SimpleOptimizedDebateAgent with RAG...")
        self.advanced_agent = AdvancedOptimizedDebateAgent()
        self.security_agent = SecurityDebateAgent(self.advanced_agent)
        
        stats = self.get_status()
        print(f"📊 RAG Agent Status: {stats}")
    
    def analyze_detection(self, detection_results: Dict) -> Dict:
        try:
            print(f"🔍 Analyzing detection with RAG: {detection_results.get('attack_type', 'Unknown')}")
            
            # CRITICAL FIX: Ensure we have specific attack types, not generic ones
            if detection_results.get('attack_type', '').lower() in ['potential security threat', 'unknown']:
                # Infer from tool
                tool_to_attack = {
                    'nmap': 'port_scan',
                    'hydra': 'bruteforce',
                    'hping3': 'dos',
                    'sqlmap': 'sql_injection', 
                    'metasploit': 'exploitation'
                }
                tool = detection_results.get('tool', '').lower()
                if tool in tool_to_attack:
                    detection_results['attack_type'] = tool_to_attack[tool]
                    print(f"✅ Inferred specific attack type: {detection_results['attack_type']}")
            
            result = self.security_agent.analyze_security_incident(detection_results)
            
            multi_expert_used = result.get('multi_expert_analysis_used', False)
            expert_count = result.get('expert_count', 0)
            rag_used = result.get('rag_used', False)
            
            print(f"✅ RAG Analysis completed: Multi-expert: {multi_expert_used} ({expert_count} experts), RAG: {rag_used}")
            return result
        except Exception as e:
            print(f"❌ Error in RAG analyze_detection: {e}")
            return self._create_error_response(str(e))
    
    def _create_error_response(self, error_msg: str) -> Dict:
        return {
            'error': error_msg,
            'formatted_output': f"🔒 RAG Security analysis temporarily unavailable: {error_msg}",
            'multi_expert_analysis_used': False,
            'expert_count': 0,
            'rag_used': False
        }
    
    def get_status(self) -> Dict:
        stats = self.advanced_agent.get_agent_stats()
        return {
            'ai_enabled': not stats['fallback_mode'] and stats['llm_available'],
            'knowledge_base_size': stats['knowledge_base_size'],
            'debates_completed': stats['debate_history_count'],
            'fallback_mode': stats['fallback_mode'],
            'api_key_present': bool(os.getenv('OPENROUTER_API_KEY')),
            'api_key_valid': stats.get('api_key_valid', False),
            'debate_models': stats.get('debate_models', 0),
            'primary_model': stats.get('primary_model', 'Unknown'),
            'api_usage_today': stats.get('api_usage_today', 0),
            'api_daily_limit': stats.get('api_daily_limit', 45),
            'rag_enabled': stats.get('rag_enabled', True)
        }

# =============================================================================
# INITIALIZATION FUNCTION - WITH API TESTING
# =============================================================================

def initialize_optimized_debate_agent():
    try:
        print("🚀 INITIALIZING RAG-ENHANCED DEBATE AGENT...")
        
        # Test API connection first
        api_valid = test_openrouter_connection()
        
        agent = SimpleOptimizedDebateAgent()
        status = agent.get_status()
        
        print("=" * 60)
        print("🤖 CYBERSHIELD RAG-ENHANCED DEBATE AGENT STATUS")
        print("=" * 60)
        print(f"🔧 AI Analysis: {'✅ ENABLED' if status['ai_enabled'] else '🔄 FALLBACK MODE'}")
        print(f"📚 Knowledge Base: {status['knowledge_base_size']} security documents")
        print(f"📊 Analyses Completed: {status['debates_completed']}")
        print(f"🤖 Expert Models: {status['debate_models']} specialists")
        print(f"🔑 API Key Present: {'✅ Yes' if status['api_key_present'] else '❌ No'}")
        print(f"🔑 API Key Valid: {'✅ Yes' if api_valid else '❌ No'}")
        print(f"🎯 Primary Model: {status['primary_model']}")
        print(f"📈 API Usage Today: {status['api_usage_today']}/{status['api_daily_limit']}")
        print(f"📚 RAG System: {'✅ ENABLED' if status['rag_enabled'] else '❌ DISABLED'}")
        
        if not status['ai_enabled']:
            print("\n💡 TROUBLESHOOTING REQUIRED:")
            if not status['api_key_present']:
                print("❌ No API key found. Set OPENROUTER_API_KEY in your .env file")
            elif not api_valid:
                print("❌ API key invalid. Check your OpenRouter API key at: https://openrouter.ai/keys")
            else:
                print("❌ Unknown initialization issue")
        
        print("=" * 60)
        print("🛡️  RAG-ENHANCED FEATURES ACTIVE:")
        print("   • 3 Expert Models (Network, Threat Intel, Incident Response)")
        print("   • RAG System with Threat-Specific Knowledge Base")
        print("   • Parallel Processing")
        print("   • Threat-Specific Caching")
        print("   • 10 requests/minute maximum")
        print("   • 40 requests/day maximum")
        print("=" * 60)
        
        return agent, status['ai_enabled']
    except Exception as e:
        print(f"❌ RAG-Enhanced Debate Agent: FAILED TO INITIALIZE - {e}")
        import traceback
        traceback.print_exc()
        return None, False

# =============================================================================
# TEST FUNCTION
# =============================================================================

def test_threat_extraction():
    """Test threat extraction with actual log data"""
    test_cases = [
        {
            'tool': 'nmap',
            'src_ip': '192.168.1.100',
            'dest_ip': '192.168.1.1',
            'dest_port': 22,
            'proto': 'TCP',
            'attack_type': 'port_scan',
            'severity': 'high'
        },
        {
            'tool': 'hydra', 
            'src_ip': '10.0.0.50',
            'dest_ip': '10.0.0.1',
            'dest_port': 22,
            'proto': 'TCP',
            'attack_type': 'bruteforce',
            'severity': 'critical'
        },
        {
            'tool': 'hping3',
            'src_ip': '172.16.0.25',
            'dest_ip': '172.16.0.1', 
            'dest_port': 80,
            'proto': 'TCP',
            'attack_type': 'dos',
            'severity': 'high'
        }
    ]
    
    agent = SecurityDebateAgent(None)  # We just need the query building method
    
    for i, test_case in enumerate(test_cases):
        print(f"\n🧪 Test Case {i+1}: {test_case['tool']}")
        query = agent._build_security_query(test_case)
        print(f"📝 Generated Query:\n{query[:300]}...")
        
        # Test extraction
        generator = OptimizedDebateGenerator(None)
        threat_info = generator._extract_threat_info_from_query(query)
        print(f"🔍 Extracted: {threat_info}")

if __name__ == "__main__":
    print("🔧 This file contains the RAG-ENHANCED Multi-LLM Debate Agent.")
    print("💡 Run 'python application.py' to start the Flask web application.")
    
    # Test initialization
    agent, enabled = initialize_optimized_debate_agent()
    if agent:
        print(f"✅ RAG Agent initialized successfully. AI Enabled: {enabled}")
    
    # Test threat-specific processing
    test_threat_extraction()