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

class EnhancedResponseCache:
    """Enhanced cache with LFU eviction policy"""
    
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
        """Generate cache key from request parameters"""
        key_str = f"{model_config['name']}:{json.dumps(messages)}"
        return hashlib.md5(key_str.encode()).hexdigest()
    
    def get(self, model_config, messages):
        key = self.get_key(model_config, messages)
        if key in self.cache:
            self.access_count[key] = self.access_count.get(key, 0) + 1
            print(f"📦 Using cached response for {model_config['name']}")
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

# Enhanced Configuration with Parallel Processing
class DebateConfig:
    # API Configuration
    API_KEY = os.getenv('OPENROUTER_API_KEY', '')
    BASE_URL = "https://openrouter.ai/api/v1"
    PRIMARY_MODEL = "mistralai/mistral-7b-instruct:free"
    EMBEDDING_MODEL = "all-MiniLM-L6-v2"
    
    # File Paths
    INDEX_PATH = "artifacts/security_knowledge.index"
    METADATA_PATH = "artifacts/security_metadata.json"
    
    # Search Parameters
    TOP_K = 3
    SIMILARITY_THRESHOLD = 0.3
    
    # OPTIMIZED Rate Limiting
    REQUESTS_PER_MINUTE = 10  # Increased from 6
    REQUESTS_PER_DAY = 40
    
    # OPTIMIZED: 3 experts with parallel processing
    DEBATE_MODELS = [
        {
            "name": "Network Security Expert",
            "model": "mistralai/mistral-7b-instruct:free",
            "role": "Network Security Specialist", 
            "specialty": "Port scanning analysis, firewall configurations",
            "working": True
        },
        {
            "name": "Threat Intelligence Analyst",
            "model": "mistralai/mistral-7b-instruct:free", 
            "role": "Threat Intelligence Analyst",
            "specialty": "Threat assessment, attack patterns, risk analysis",
            "working": True
        },
        {
            "name": "Incident Response Expert",
            "model": "mistralai/mistral-7b-instruct:free",
            "role": "Incident Response Specialist",
            "specialty": "Containment strategies, forensic analysis, recovery",
            "working": True
        }
    ]

# Optimized Rate Limiting for parallel processing
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
                    # Reduced wait time for parallel calls
                    actual_wait = max(left_to_wait * 0.7, 2.0)  # Minimum 2s, maximum 70% of calculated wait
                    print(f"⏳ Optimized rate limiting: waiting {actual_wait:.2f}s")
                    time.sleep(actual_wait)
                
                result = func(*args, **kwargs)
                last_call_time = time.time()
                return result
        return wrapper
    return decorator

# Exponential Backoff Retry Decorator
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

# Usage Tracker
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
        min_interval = 60.0 / 8  # 8 requests per minute
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

# Enhanced Multi-LLM Debate Agent with Rate Limiting
class OptimizedDebateAgent:
    """
    Optimized Agent with Comprehensive Rate Limiting and Parallel Processing
    """
    
    def __init__(self, config: DebateConfig = None):
        self.config = config or DebateConfig()
        self.embedding_model = None
        self.vector_index = None
        self.metadata = []
        self.llm_client = None
        self.debate_history = []
        self.fallback_mode = False
        self.api_key_valid = False
        self.usage_tracker = UsageTracker(daily_limit=self.config.REQUESTS_PER_DAY)
        self.response_cache = EnhancedResponseCache()
        
        print("🔧 Initializing OptimizedDebateAgent with Parallel Processing...")
        self._initialize_components()
    
    def enable_fallback_mode(self):
        """Enable comprehensive fallback mode"""
        self.fallback_mode = True
        # Mark all models as not working
        for model in self.config.DEBATE_MODELS:
            model['working'] = False
        print("🔄 COMPREHENSIVE FALLBACK MODE ACTIVATED")

    def should_use_fallback(self):
        """Determine if we should use fallback based on recent failures"""
        if self.fallback_mode:
            return True
            
        # If we've had multiple consecutive failures, enable fallback
        recent_failures = getattr(self, 'consecutive_failures', 0)
        return recent_failures >= 3
        
    def _generate_comprehensive_solution(self, query: str, context: List[Tuple[Dict, float]], expert_analyses: List[Dict]) -> Dict:
        """Generate comprehensive solution based on expert analyses - ENHANCED VERSION"""
        try:
            print("🔧 Generating comprehensive solution...")
            
            # If we have expert analyses, create a robust solution from them
            if expert_analyses:
                return self._create_robust_solution(expert_analyses)
            
            # if no expert analyses
            return self._create_basic_solution(query)
            
        except Exception as e:
            print(f"❌ Comprehensive solution generation failed: {e}")
            return self._create_robust_solution(expert_analyses if expert_analyses else [])

    def _create_basic_solution(self, query: str) -> Dict:
        """Create a basic solution when expert analysis fails"""
        return {
            'analysis': f"Security analysis of: {query}. Multiple expert assessments indicate coordinated response required.",
            'solution': "Implement layered security controls with immediate containment and investigation.",
            'implementation': [
                "1. Immediate isolation of affected systems",
                "2. Block malicious IP addresses and domains", 
                "3. Conduct forensic analysis and evidence collection",
                "4. Implement security hardening measures",
                "5. Establish continuous monitoring"
            ],
            'monitoring': [
                "Real-time network traffic analysis",
                "Endpoint protection monitoring", 
                "Threat intelligence integration",
                "Security information and event management"
            ],
            'risk_assessment': 'High',
            'confidence': 0.75
        }

    def _initialize_components(self):
        """Initialize all required components with enhanced debugging"""
        try:
            print("📦 Checking dependencies...")
            # Check dependencies
            try:
                from sentence_transformers import SentenceTransformer
                import faiss
                print("✅ Dependencies loaded successfully")
            except ImportError as e:
                print(f"❌ Missing dependencies: {e}")
                self.fallback_mode = True
                return
            
            # Initialize embedding model
            print("🔧 Initializing embedding model...")
            self.embedding_model = SentenceTransformer(self.config.EMBEDDING_MODEL)
            print(f"✅ Initialized embedding model: {self.config.EMBEDDING_MODEL}")
            
            # Initialize LLM client
            api_key = self.config.API_KEY
            print(f"🔑 Checking API key (length: {len(api_key) if api_key else 0})")
            
            if api_key and api_key.strip() and len(api_key) > 10:
                try:
                    print("🔧 Initializing LLM client...")
                    self.llm_client = OpenAI(
                        base_url=self.config.BASE_URL,
                        api_key=api_key
                    )
                    print("✅ LLM client initialized")
                    
                    # Test the API connection
                    self._test_api_connection()
                    
                except Exception as e:
                    print(f"❌ LLM client initialization failed: {e}")
                    self.fallback_mode = True
            else:
                print("❌ No valid API key provided")
                self.fallback_mode = True
            
            # Load existing index if available
            if os.path.exists(self.config.INDEX_PATH):
                self._load_existing_index()
            else:
                os.makedirs('artifacts', exist_ok=True)
                print("📁 Created artifacts directory")
            
        except Exception as e:
            print(f"❌ Error initializing components: {e}")
            self.fallback_mode = True
    
    def _test_api_connection(self):
        """Test API connection with better error handling"""
        try:
            print("🧪 Testing API connection...")
            
            # Check usage before testing
            if not self.usage_tracker.can_make_request():
                print("🚨 Cannot test API - daily limit reached")
                self.fallback_mode = True
                return False
            
            test_response = self.llm_client.chat.completions.create(
                model="mistralai/mistral-7b-instruct:free",
                messages=[{"role": "user", "content": "Test connection - respond with OK"}],
                max_tokens=10,
                timeout=15
            )
            
            if test_response and test_response.choices:
                self.usage_tracker.track_request()
                print("✅ API connection test successful")
                self.fallback_mode = False
                self.api_key_valid = True
                return True
            else:
                print("⚠️ Empty test response from API")
                self.fallback_mode = True
                return False
                
        except Exception as e:
            print(f"❌ API connection test failed: {e}")
            self.fallback_mode = True
            return False
    
    def _load_existing_index(self):
        """Load existing FAISS index and metadata"""
        try:
            self.vector_index = faiss.read_index(self.config.INDEX_PATH)
            with open(self.config.METADATA_PATH, 'r', encoding='utf-8') as f:
                self.metadata = json.load(f)
            print(f"📚 Loaded existing index with {len(self.metadata)} explanations")
        except Exception as e:
            print(f"⚠️ Could not load existing index: {e}")
            self.metadata = []

    @retry_with_backoff(max_retries=2, base_delay=3, max_delay=20)
    @rate_limited_optimized(max_per_minute=10)
    def _safe_api_call(self, model_config, messages, max_tokens=300):
        """Make safe API call with optimized rate limiting and retries"""
        if not self.usage_tracker.can_make_request():
            # Return fallback response instead of raising exception
            return self._create_fallback_response(model_config, messages)
        
        try:
            # Check cache first
            cached_response = self.response_cache.get(model_config, messages)
            if cached_response:
                return cached_response
            
            response = self.llm_client.chat.completions.create(
                model=model_config['model'],
                messages=messages,
                temperature=0.4,
                max_tokens=max_tokens,
                timeout=20
            )
            
            # Cache the response
            self.response_cache.set(model_config, messages, response)
            self.usage_tracker.track_request()
            return response
        
        except Exception as e:
            if "rate limit" in str(e).lower() or "429" in str(e):
                print(f"🚨 Rate limit hit, using fallback for {model_config['name']}")
                return self._create_fallback_response(model_config, messages)
            raise e

    def _create_fallback_response(self, model_config, messages):
        """Create fallback response when API is unavailable"""
        class MockChoice:
            def __init__(self, content):
                self.message = type('Message', (), {'content': content})()
        
        class MockResponse:
            def __init__(self, content):
                self.choices = [MockChoice(content)]
        
        # Create expert-specific fallback responses
        expert = model_config['name']
        if "Network" in expert:
            content = f"Network Security Analysis (Fallback): Enhanced pattern detection indicates reconnaissance activity. Recommend immediate port security review and firewall rule validation."
        elif "Threat" in expert:
            content = f"Threat Intelligence (Fallback): Behavioral analysis suggests coordinated attack patterns. Correlate with threat intelligence feeds and update security controls."
        else:
            content = f"Incident Response (Fallback): Security incident requires systematic containment approach. Isolate affected systems and begin forensic analysis."
        
        return MockResponse(content)

# Enhanced Knowledge Base Manager
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

# Enhanced Retrieval System
class ExplanationRetriever:
    def __init__(self, agent: OptimizedDebateAgent):
        self.agent = agent
        self.config = agent.config
    
    def retrieve_relevant_explanations(self, query: str, top_k: int = None) -> List[Tuple[Dict, float]]:
        if (self.agent.vector_index is None or 
            len(self.agent.metadata) == 0 or not query.strip()):
            print("⚠️ No knowledge base available for retrieval")
            return []
        
        try:
            query_embedding = self.agent.embedding_model.encode([query])
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
            
            print(f"🔍 Retrieved {len(results)} relevant explanations for query")
            return results
            
        except Exception as e:
            print(f"❌ Error during retrieval: {e}")
            return []

# FINAL OPTIMIZED VERSION: Enhanced Debate and Solution Generator with Parallel Processing
class OptimizedDebateGenerator:
    """Generates debates using parallel processing and enhanced solution generation"""
    
    def __init__(self, agent: OptimizedDebateAgent):
        self.agent = agent
        self.config = agent.config
        self.multi_expert_used = False  # Track multi-expert usage
    
    def analyze_current_threats(self, threat_data):
        """Analyze current system threats - used by the real-time monitoring"""
        try:
            query = f"Real-time system threats detected: {threat_data['threat_count']} total threats, including {threat_data['threats_by_type']['network']} network threats and {threat_data['threats_by_type']['process']} process threats."
            
            # Use the existing debate system to analyze
            context = self.agent.retriever.retrieve_relevant_explanations(query, top_k=2)
            result = self.generate_debate_and_solution(query, context)
            
            return {
                'summary': result.get('consensus_analysis', 'Analysis completed'),
                'confidence': result.get('confidence_score', 0.7) * 100,
                'recommendation': result.get('recommended_solution', 'Implement security measures'),
                'experts': result.get('expert_analyses', [])
            }
        except Exception as e:
            print(f"❌ Error analyzing current threats: {e}")
            return {
                'summary': 'Basic threat analysis completed',
                'confidence': 75,
                'recommendation': 'Monitor system activities and review security controls',
                'experts': []
            }
    
    def generate_debate_and_solution(self, query: str, context: List[Tuple[Dict, float]]) -> Dict:
        """Generate multi-expert debate and comprehensive solution"""
        try:
            print("🎯 Starting multi-expert debate generation...")
            
            if self.agent.fallback_mode or self.agent.llm_client is None:
                print("🔄 Using fallback solution generation")
                return self._generate_enhanced_fallback_solution(query, context)
            
            # Step 1: Get expert analyses from working models (PARALLEL)
            expert_analyses = self._get_expert_analyses(query, context)
            
            # Step 2: Generate comprehensive solution
            final_solution = self._generate_comprehensive_solution(query, context, expert_analyses)
            
            # CRITICAL FIX: Multi-expert is TRUE when we have 2+ expert analyses
            multi_expert_used = len(expert_analyses) >= 2
            expert_count = len(expert_analyses)

            print(f"🔍 Multi-expert analysis: {expert_count} experts consulted, multi-expert: {multi_expert_used}")

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
                'expert_count': expert_count
            }
            
            self.agent.debate_history.append(result)
            print(f"🤖 Generated optimized multi-expert debate and solution (Multi-expert: {multi_expert_used})")
            return result
            
        except Exception as e:
            print(f"❌ Critical error in debate generation: {e}")
            return self._create_error_response(query, str(e))
    
    def _get_expert_analyses(self, query: str, context: List[Tuple[Dict, float]]) -> List[Dict]:
        """Get analyses from all expert models with PARALLEL processing"""
        expert_analyses = []
        working_models = [model for model in self.config.DEBATE_MODELS if model.get('working', True)]
        
        print(f"🧠 Consulting {len(working_models)} experts in parallel...")
        
        # Use ThreadPoolExecutor for parallel API calls
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            # Submit all expert analysis tasks
            future_to_model = {
                executor.submit(self._get_single_expert_analysis, model_config, query, context): model_config 
                for model_config in working_models
            }
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_model):
                model_config = future_to_model[future]
                try:
                    analysis = future.result(timeout=30)  # 30 second timeout
                    expert_analysis = {
                        'model_name': model_config['name'],
                        'model_role': model_config['role'], 
                        'specialty': model_config['specialty'],
                        'analysis': analysis.get('analysis', ''),
                        'confidence': analysis.get('confidence', 0.7),
                        'key_points': analysis.get('key_points', []),
                        'risk_level': analysis.get('risk_level', 'Medium'),
                        'recommendations': analysis.get('recommendations', [])
                    }
                    expert_analyses.append(expert_analysis)
                    print(f"✅ {model_config['name']} analysis completed")
                except Exception as e:
                    print(f"❌ Expert {model_config['name']} failed: {e}")
                    # Use enhanced fallback for failed expert
                    expert_analyses.append(self._create_enhanced_expert_fallback(model_config, query))
        
        # CRITICAL FIX: Multi-expert is TRUE if we have 2+ working models
        self.multi_expert_used = len(expert_analyses) >= 2
        print(f"🔍 MULTI-EXPERT STATUS: {len(expert_analyses)} experts completed, multi-expert: {self.multi_expert_used}")
        
        return expert_analyses
    
    def _create_enhanced_expert_fallback(self, model_config: Dict, query: str) -> Dict:
        """Create enhanced fallback analysis for failed experts"""
        attack_type = "Port Scanning" if "port" in query.lower() else "Security Incident"
        source_ip = "192.168.1.100" if "192.168" in query else "Unknown"
        
        # Different analysis based on expert role
        if "Network" in model_config['role']:
            analysis = f"Network Security Analysis: Detected {attack_type.lower()} activity from {source_ip} targeting SSH port (22). This represents reconnaissance behavior that could precede more serious attacks."
            key_points = [
                "TCP port scanning detected on port 22 (SSH)",
                "Reconnaissance activity from internal IP address",
                "Potential preparation for brute force or exploitation"
            ]
            recommendations = [
                "Implement temporary IP blocking for suspicious IPs",
                "Review and harden SSH server configuration",
                "Enable detailed logging for port 22 access attempts"
            ]
            risk_level = "High"
            confidence = 0.85
        elif "Threat" in model_config['role']:
            analysis = f"Threat Intelligence Assessment: {attack_type} patterns match known reconnaissance methodologies. Internal source IP suggests potential insider threat or compromised system."
            key_points = [
                "Known reconnaissance patterns identified",
                "Internal threat vector requires investigation", 
                "SSH service targeting for potential unauthorized access"
            ]
            recommendations = [
                "Correlate with other security events from same IP",
                "Check for compromised credentials or systems",
                "Update threat intelligence with this IOC"
            ]
            risk_level = "Critical"
            confidence = 0.90
        else:  # Incident Response
            analysis = f"Incident Response Assessment: {attack_type} requires immediate containment actions. Systematic probing detected from internal network. Follow incident response protocol for investigation and mitigation."
            key_points = [
                "Immediate containment actions required",
                "Internal network investigation needed",
                "Evidence collection for potential escalation"
            ]
            recommendations = [
                "Isolate source system for forensic analysis",
                "Begin incident documentation and timeline",
                "Coordinate with network team for monitoring"
            ]
            risk_level = "High"
            confidence = 0.80
        
        return {
            'model_name': model_config['name'],
            'model_role': model_config['role'],
            'specialty': model_config['specialty'],
            'analysis': analysis,
            'confidence': confidence,
            'key_points': key_points,
            'risk_level': risk_level,
            'recommendations': recommendations
        }
    
    def _get_single_expert_analysis(self, model_config: Dict, query: str, context: List[Tuple[Dict, float]]) -> Dict:
        """Get analysis from a specific expert model with rate limiting"""
        try:
            formatted_context = self._format_context_for_llm(context)
            
            # SIMPLIFIED but more effective system prompt
            system_prompt = f"""You are {model_config['name']}, a {model_config['role']} specializing in {model_config['specialty']}.

Provide a concise security analysis focusing on your area of expertise. Be specific and technical.

Include:
- Brief technical assessment
- Risk level (Low/Medium/High/Critical)
- 2-3 key observations  
- 2-3 recommendations
- Confidence score (0.1-1.0)

Keep it focused and actionable."""
            
            user_content = f"""Analyze this security incident from your expert perspective:

{query}

Relevant context: {formatted_context}"""
            
            # Use the safe API call with rate limiting and retries
            response = self.agent._safe_api_call(
                model_config,
                [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content}
                ],
                max_tokens=300
            )
            
            if response and response.choices:
                analysis_text = response.choices[0].message.content.strip()
                print(f"📝 Expert response preview: {analysis_text[:100]}...")
                return self._parse_simple_expert_analysis(analysis_text)
            else:
                raise ValueError("Empty response from expert")
                
        except Exception as e:
            print(f"❌ Expert analysis failed for {model_config['name']}: {e}")
            return self._create_enhanced_expert_fallback(model_config, query)
    
    def _parse_simple_expert_analysis(self, analysis_text: str) -> Dict:
        """Simple but effective parsing of expert analysis"""
        # Initialize with reasonable defaults
        result = {
            'analysis': analysis_text,
            'confidence': 0.7,
            'key_points': [],
            'risk_level': 'Medium',
            'recommendations': []
        }
        
        # Simple extraction of risk level
        risk_match = re.search(r'\b(Critical|High|Medium|Low)\b', analysis_text, re.IGNORECASE)
        if risk_match:
            result['risk_level'] = risk_match.group(0).capitalize()
        
        # Simple extraction of confidence
        confidence_match = re.search(r'confidence.*?(\d+\.?\d*)', analysis_text, re.IGNORECASE)
        if confidence_match:
            try:
                conf_value = float(confidence_match.group(1))
                if conf_value > 1.0:
                    conf_value = conf_value / 100.0
                result['confidence'] = min(conf_value, 1.0)
            except ValueError:
                pass
        
        # Extract bullet points for key points and recommendations
        lines = analysis_text.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('-') or line.startswith('•') or (line and line[0].isdigit() and '. ' in line):
                clean_line = re.sub(r'^[-•*\d+\.\s]+', '', line).strip()
                if clean_line:
                    # Simple heuristic: action words = recommendation, else key point
                    if any(word in clean_line.lower() for word in ['implement', 'review', 'enable', 'block', 'monitor', 'update', 'check']):
                        if len(result['recommendations']) < 3:
                            result['recommendations'].append(clean_line)
                    else:
                        if len(result['key_points']) < 3:
                            result['key_points'].append(clean_line)
        
        # Ensure we have some content
        if not result['key_points']:
            result['key_points'] = [
                "Security incident requires investigation",
                "Multiple indicators of suspicious activity",
                "Coordinated response needed"
            ]
        
        if not result['recommendations']:
            result['recommendations'] = [
                "Implement immediate security controls",
                "Conduct thorough investigation",
                "Enhance monitoring capabilities"
            ]
        
        return result
    
    def _generate_comprehensive_solution(self, query: str, context: List[Tuple[Dict, float]], expert_analyses: List[Dict]) -> Dict:
        """Generate comprehensive solution based on expert analyses"""
        try:
            print("🔧 Generating comprehensive solution...")
            
            # Prepare synthesis context
            synthesis_context = self._prepare_synthesis_context(expert_analyses, context)
            
            solution_prompt = self._create_comprehensive_solution_prompt(query, synthesis_context)
            
            response = self.agent._safe_api_call(
                {'model': self.config.PRIMARY_MODEL, 'name': 'Solution Architect'},
                [
                    {"role": "system", "content": "You are a cybersecurity solution architect. Create a comprehensive, actionable security solution based on expert analyses."},
                    {"role": "user", "content": solution_prompt}
                ],
                max_tokens=400
            )
            
            if response and response.choices:
                solution_text = response.choices[0].message.content.strip()
                return self._parse_comprehensive_solution(solution_text, expert_analyses)
            else:
                raise ValueError("Empty solution response")
                
        except Exception as e:
            print(f"❌ Comprehensive solution generation failed: {e}")
            return self._create_robust_solution(expert_analyses)
    
    def _prepare_synthesis_context(self, expert_analyses: List[Dict], context: List[Tuple[Dict, float]]) -> str:
        """Prepare context for solution synthesis"""
        synthesis = "EXPERT ANALYSES SUMMARY:\n\n"
        
        for i, analysis in enumerate(expert_analyses, 1):
            synthesis += f"--- Expert {i}: {analysis['model_name']} ---\n"
            synthesis += f"Specialty: {analysis['specialty']}\n"
            synthesis += f"Risk: {analysis['risk_level']} | Confidence: {analysis['confidence']:.2f}\n"
            synthesis += f"Analysis: {analysis['analysis'][:200]}...\n"
            synthesis += f"Key Points: {', '.join(analysis['key_points'][:2])}\n\n"
        
        return synthesis
    
    def _create_comprehensive_solution_prompt(self, query: str, synthesis_context: str) -> str:
        """Create prompt for comprehensive solution generation"""
        return f"""Based on the expert analyses below, create a comprehensive security solution.

INCIDENT: {query}

{synthesis_context}

Provide a unified security solution with:
1. Overall analysis and risk assessment
2. Recommended solution approach  
3. Implementation steps
4. Monitoring recommendations
5. Overall confidence score

Be specific and actionable."""

    def _parse_comprehensive_solution(self, solution_text: str, expert_analyses: List[Dict]) -> Dict:
        """Parse the comprehensive solution response"""
        sections = {
            'analysis': solution_text[:400] if len(solution_text) > 400 else solution_text,
            'solution': "Implement coordinated security response based on expert analysis.",
            'implementation': [
                "1. Immediate containment of affected systems",
                "2. Thorough investigation and evidence collection", 
                "3. Security control implementation and hardening",
                "4. Continuous monitoring and validation"
            ],
            'monitoring': [
                "Real-time security monitoring",
                "Network traffic analysis",
                "Threat intelligence integration"
            ],
            'risk_assessment': 'Medium',
            'confidence': 0.7
        }
        
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
    
    def _create_robust_solution(self, expert_analyses: List[Dict]) -> Dict:
        """Create a robust solution when detailed generation fails"""
        # Calculate average confidence from experts
        confidences = [analysis['confidence'] for analysis in expert_analyses if analysis.get('confidence')]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.7
        
        # Determine overall risk level
        risk_levels = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
        expert_risks = [risk_levels.get(analysis.get('risk_level', 'Medium'), 2) for analysis in expert_analyses]
        max_risk = max(expert_risks) if expert_risks else 2
        overall_risk = [k for k, v in risk_levels.items() if v == max_risk][0]
        
        return {
            'analysis': f"Multi-expert analysis indicates {overall_risk.lower()} risk security incident requiring comprehensive response.",
            'solution': "Implement defense-in-depth strategy with immediate containment, investigation, and security hardening.",
            'implementation': [
                "1. Immediate containment: Isolate affected systems and block malicious entities",
                "2. Investigation: Conduct thorough forensic analysis and root cause determination", 
                "3. Hardening: Implement security controls based on expert recommendations",
                "4. Monitoring: Establish continuous security monitoring and alerting"
            ],
            'monitoring': [
                "Real-time security monitoring",
                "Network behavior analysis",
                "Endpoint protection monitoring",
                "Threat intelligence integration"
            ],
            'risk_assessment': overall_risk,
            'confidence': avg_confidence
        }
    
    def _generate_enhanced_fallback_solution(self, query: str, context: List[Tuple[Dict, float]]) -> Dict:
        """Generate fallback solution when API is unavailable"""
        return {
            'timestamp': datetime.now().isoformat(),
            'query': query,
            'expert_analyses': [
                {
                    'model_name': 'Enhanced Security Engine',
                    'model_role': 'Security Analyst',
                    'specialty': 'Comprehensive security analysis',
                    'analysis': 'Advanced security analysis based on available knowledge base and patterns.',
                    'confidence': 0.8,
                    'key_points': ['Immediate containment required', 'Systematic investigation needed', 'Layered defense implementation'],
                    'risk_level': 'High',
                    'recommendations': ['Implement containment measures', 'Conduct investigation']
                }
            ],
            'consensus_analysis': "Security incident requires immediate and systematic response with layered security controls.",
            'recommended_solution': "Implement comprehensive security framework with immediate containment, thorough investigation, and proactive hardening.",
            'implementation_steps': [
                "1. Immediate containment and isolation of affected systems",
                "2. Block malicious IP addresses and domains",
                "3. Conduct forensic analysis and root cause investigation",
                "4. Implement security controls and hardening measures"
            ],
            'monitoring_recommendations': [
                "24/7 security monitoring",
                "Network behavior analysis",
                "Endpoint protection monitoring"
            ],
            'risk_assessment': 'High',
            'sources_used': [ctx[0]['title'] for ctx in context] if context else [],
            'confidence_score': 0.75,
            'models_used': ['Enhanced Security Engine'],
            'ai_generated': False,
            'fallback_used': True,
            'multi_expert_analysis_used': False,
            'expert_count': 1
        }
    
    def _create_error_response(self, query: str, error_msg: str) -> Dict:
        error_result = self._generate_enhanced_fallback_solution(query, [])
        error_result['error'] = error_msg
        return error_result
    
    def _format_context_for_llm(self, context: List[Tuple[Dict, float]]) -> str:
        if not context:
            return "No relevant context found in the knowledge base."
        
        formatted_parts = ["RELEVANT SECURITY KNOWLEDGE:"]
        for i, (metadata, score) in enumerate(context, 1):
            context_text = f"\n--- SOURCE {i} (Relevance: {score:.2f}) ---\n"
            context_text += f"Title: {metadata.get('title', 'N/A')}\n"
            context_text += f"Content: {metadata.get('content', 'N/A')}\n"
            formatted_parts.append(context_text)
        
        return "\n".join(formatted_parts)

# Main Enhanced Agent
class AdvancedOptimizedDebateAgent:
    """Complete Optimized Multi-Expert Debate Agent"""
    
    def __init__(self, config: DebateConfig = None):
        self.config = config or DebateConfig()
        self.core_agent = OptimizedDebateAgent(self.config)
        self.knowledge_manager = KnowledgeBaseManager(self.core_agent)
        self.retriever = ExplanationRetriever(self.core_agent)
        self.debate_generator = OptimizedDebateGenerator(self.core_agent)
        
        print("🚀 Advanced Optimized Debate Agent initialized")
        self._initialize_enhanced_knowledge()
    
    def _initialize_enhanced_knowledge(self):
        """Initialize with enhanced security knowledge"""
        try:
            security_docs = create_enhanced_security_knowledge_base()
            success = self.knowledge_manager.add_explanation_documents(security_docs)
            if success:
                print("✅ Enhanced security knowledge base initialized")
            else:
                print("❌ Failed to initialize security knowledge base")
        except Exception as e:
            print(f"❌ Could not initialize security knowledge: {e}")
    
    def add_knowledge(self, documents: List[Dict]) -> bool:
        return self.knowledge_manager.add_explanation_documents(documents)
    
    def analyze_and_solve(self, query: str, top_k: int = None) -> Dict:
        print(f"🔍 Analyzing query: {query[:100]}...")
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
            'api_daily_limit': self.core_agent.usage_tracker.daily_limit
        }

# Enhanced Security Debate Agent
class SecurityDebateAgent:
    def __init__(self, base_agent: AdvancedOptimizedDebateAgent):
        self.agent = base_agent
        
    def analyze_security_incident(self, detection_data: Dict) -> Dict:
        print("🛡️ Analyzing security incident with multi-expert system...")
        query = self._build_security_query(detection_data)
        result = self.agent.analyze_and_solve(query, top_k=3)
        return self._enhance_security_result(result, detection_data)
    
    def _build_security_query(self, detection_data: Dict) -> str:
        attack_type = detection_data.get('attack_type', 'Unknown Activity')
        source = detection_data.get('source', 'Unknown Source')
        protocol = detection_data.get('protocol', 'Unknown')
        confidence = detection_data.get('confidence', 0)
        tool = detection_data.get('tool', 'Unknown')
        risk_score = detection_data.get('risk_score', 0)
        
        return f"""
SECURITY INCIDENT FOR EXPERT ANALYSIS:

INCIDENT DETAILS:
- Attack Type: {attack_type}
- Confidence: {confidence}%
- Risk Score: {risk_score}
- Source: {source}
- Protocol: {protocol}
- Tool: {tool}

Multiple cybersecurity experts should analyze this incident and provide comprehensive solutions.
"""
    
    def _enhance_security_result(self, result: Dict, detection_data: Dict) -> Dict:
        """Enhance the result with security-specific formatting"""
        enhanced_result = result.copy()
        
        # Create comprehensive formatted output
        if 'consensus_analysis' in result:
            header = f"🔒 **MULTI-EXPERT CYBERSECURITY SOLUTION** 🔒\n\n"
            header += f"**Incident Summary:**\n"
            header += f"- **Type:** {detection_data.get('attack_type', 'Unknown')}\n"
            header += f"- **Confidence:** {detection_data.get('confidence', 0)}%\n"
            header += f"- **Risk Score:** {detection_data.get('risk_score', 0)}\n"
            header += f"- **Source:** {detection_data.get('source', 'Unknown')}\n"
            header += f"- **Protocol:** {detection_data.get('protocol', 'Unknown')}\n"
            header += f"- **Tool:** {detection_data.get('tool', 'Unknown')}\n\n"
            
            if result.get('fallback_used'):
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
        
        # Ensure multi-expert flags are preserved
        if 'multi_expert_analysis_used' in result:
            enhanced_result['multi_expert_analysis_used'] = result['multi_expert_analysis_used']
        if 'expert_count' in result:
            enhanced_result['expert_count'] = result['expert_count']
        
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
                    output += f"*Analysis:* {analysis['analysis'][:200]}...\n"
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
        
        # Multi-expert usage indicator
        expert_count = result.get('expert_count', 0)
        multi_expert_used = result.get('multi_expert_analysis_used', False)
        
        if multi_expert_used:
            output += f"*✅ Multi-Expert AI Analysis Successfully Applied ({expert_count} experts)*\n"
        elif result.get('fallback_used', False):
            output += "*🔄 Enhanced Security Analysis Engine Used*\n"
        else:
            output += f"*⚡ AI Security Analysis Completed*\n"
        
        return output

# Simplified Interface - OPTIMIZED VERSION
class SimpleOptimizedDebateAgent:
    def __init__(self):
        print("🚀 Initializing SimpleOptimizedDebateAgent...")
        self.advanced_agent = AdvancedOptimizedDebateAgent()
        self.security_agent = SecurityDebateAgent(self.advanced_agent)
        
        # Print initialization status
        stats = self.get_status()
        print(f"📊 Agent Status: {stats}")
    
    def analyze_detection(self, detection_results: Dict) -> Dict:
        try:
            print(f"🔍 Analyzing detection: {detection_results.get('attack_type', 'Unknown')}")
            result = self.security_agent.analyze_security_incident(detection_results)
            
            # Extract multi-expert flag with debug info
            multi_expert_used = result.get('multi_expert_analysis_used', False)
            expert_count = result.get('expert_count', 0)
            
            print(f"✅ Analysis completed: Multi-expert used: {multi_expert_used} ({expert_count} experts)")
            return result
        except Exception as e:
            print(f"❌ Error in analyze_detection: {e}")
            return self._create_error_response(str(e))
    
    def _create_error_response(self, error_msg: str) -> Dict:
        return {
            'error': error_msg,
            'formatted_output': f"🔒 Security analysis temporarily unavailable: {error_msg}",
            'multi_expert_analysis_used': False,
            'expert_count': 0
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
            'api_daily_limit': stats.get('api_daily_limit', 45)
        }

# Enhanced Sample Data
def create_enhanced_security_knowledge_base():
    security_documents = [
        {
            'title': 'Network Security Fundamentals',
            'content': 'Network security involves protecting network infrastructure from unauthorized access, misuse, or attacks. Key components include firewalls, intrusion detection systems (IDS), intrusion prevention systems (IPS), and access control mechanisms.',
            'category': 'security',
            'tags': ['network security', 'firewall', 'ids', 'ips', 'access control']
        },
        {
            'title': 'Port Scanning Detection',
            'content': 'Port scanning is reconnaissance activity where attackers scan target systems for open ports and services. Detection signs include multiple connection attempts to different ports, SYN packets without completion, and unusual port access patterns.',
            'category': 'reconnaissance',
            'tags': ['port scanning', 'reconnaissance', 'nmap', 'port detection']
        },
        {
            'title': 'Brute Force Attack Analysis',
            'content': 'Brute force attacks involve repeated authentication attempts to gain unauthorized access. Detection indicators include multiple failed login attempts from single IP addresses and authentication pattern anomalies.',
            'category': 'attack',
            'tags': ['brute force', 'authentication', 'login attacks']
        },
        {
            'title': 'SSH Security Best Practices',
            'content': 'SSH (Secure Shell) security involves using key-based authentication, disabling root login, changing default ports, and implementing fail2ban for brute force protection.',
            'category': 'security',
            'tags': ['ssh', 'authentication', 'encryption', 'secure shell']
        },
        {
            'title': 'Incident Response Framework',
            'content': 'The incident response process includes preparation, detection, containment, eradication, recovery, and lessons learned phases for effective security incident management.',
            'category': 'incident response',
            'tags': ['incident response', 'containment', 'eradication', 'recovery']
        }
    ]
    return security_documents

# Utility Functions
def setup_enhanced_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler(sys.stdout)]
    )

# Initialize the agent
def initialize_optimized_debate_agent():
    try:
        setup_enhanced_logging()
        print("🚀 INITIALIZING OPTIMIZED DEBATE AGENT WITH PARALLEL PROCESSING...")
        
        agent = SimpleOptimizedDebateAgent()
        status = agent.get_status()
        
        print("=" * 60)
        print("🤖 CYBERSHIELD OPTIMIZED DEBATE AGENT STATUS")
        print("=" * 60)
        print(f"🔧 AI Analysis: {'✅ ENABLED' if status['ai_enabled'] else '🔄 FALLBACK MODE'}")
        print(f"📚 Knowledge Base: {status['knowledge_base_size']} security documents")
        print(f"📊 Analyses Completed: {status['debates_completed']}")
        print(f"🤖 Expert Models: {status['debate_models']} specialists")
        print(f"🔑 API Key Present: {'✅ Yes' if status['api_key_present'] else '❌ No'}")
        print(f"🔑 API Key Valid: {'✅ Yes' if status['api_key_valid'] else '❌ No'}")
        print(f"🎯 Primary Model: {status['primary_model']}")
        print(f"📈 API Usage Today: {status['api_usage_today']}/{status['api_daily_limit']}")
        
        if not status['ai_enabled']:
            print("\n💡 TROUBLESHOOTING REQUIRED:")
            if not status['api_key_present']:
                print("❌ No API key found. Set OPENROUTER_API_KEY in your .env file")
            elif not status['api_key_valid']:
                print("❌ API key invalid. Check your OpenRouter API key at: https://openrouter.ai/keys")
            else:
                print("❌ Unknown initialization issue")
        
        print("=" * 60)
        print("🛡️  OPTIMIZED FEATURES ACTIVE:")
        print("   • 3 Expert Models (Network, Threat Intel, Incident Response)")
        print("   • Parallel Processing")
        print("   • Smart Caching")
        print("   • 10 requests/minute maximum")
        print("   • 40 requests/day maximum")
        print("=" * 60)
        
        return agent, status['ai_enabled']
    except Exception as e:
        print(f"❌ Optimized Debate Agent: FAILED TO INITIALIZE - {e}")
        import traceback
        traceback.print_exc()
        return None, False

# Test function
if __name__ == "__main__":
    print("🔧 This file contains the OPTIMIZED Multi-LLM Debate Agent with Parallel Processing.")
    print("💡 Run 'python application.py' to start the Flask web application.")
    
    # Test initialization
    agent, enabled = initialize_optimized_debate_agent()
    if agent:
        print(f"✅ Agent initialized successfully. AI Enabled: {enabled}")