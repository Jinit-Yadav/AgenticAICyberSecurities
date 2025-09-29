# ============================================================================
# EXPLANATION AGENT WITH RAG USING DEEPSEEK AND FAISS
# ============================================================================

# 1. IMPORTS
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

# 2. CONFIGURATION
class ExplanationConfig:
    """Configuration for Explanation Agent"""
    # OpenRouter Configuration
    BASE_URL = "https://openrouter.ai/api/v1"
    API_KEY = "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"  # Replace with your key
    MODEL_NAME = "deepseek/deepseek-chat-v3.1:free"
    
    # Embedding Model
    EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"
    
    # Vector Store
    INDEX_PATH = "explanation_index.faiss"
    METADATA_PATH = "explanation_metadata.json"
    
    # Retrieval Parameters
    TOP_K = 5
    SIMILARITY_THRESHOLD = 0.7

# 3. CORE EXPLANATION AGENT
class ExplanationAgent:
    """
    Advanced Explanation Agent with RAG capabilities
    Provides detailed explanations using retrieved context and DeepSeek
    """
    
    def __init__(self, config: ExplanationConfig = None):
        self.config = config or ExplanationConfig()
        self.embedding_model = None
        self.vector_index = None
        self.metadata = []
        self.llm_client = None
        self.explanation_history = []
        
        self._initialize_components()
    
    def _initialize_components(self):
        """Initialize all required components"""
        try:
            # Initialize embedding model
            self.embedding_model = SentenceTransformer(self.config.EMBEDDING_MODEL)
            logging.info(f"✅ Initialized embedding model: {self.config.EMBEDDING_MODEL}")
            
            # Initialize LLM client
            self.llm_client = OpenAI(
                base_url=self.config.BASE_URL,
                api_key=self.config.API_KEY
            )
            logging.info(f"✅ Initialized LLM client: {self.config.MODEL_NAME}")
            
            # Load existing index if available
            if os.path.exists(self.config.INDEX_PATH):
                self._load_existing_index()
            
        except Exception as e:
            logging.error(f"❌ Error initializing components: {e}")
            raise
    
    def _load_existing_index(self):
        """Load existing FAISS index and metadata"""
        try:
            self.vector_index = faiss.read_index(self.config.INDEX_PATH)
            with open(self.config.METADATA_PATH, 'r') as f:
                self.metadata = json.load(f)
            logging.info(f"✅ Loaded existing index with {len(self.metadata)} explanations")
        except Exception as e:
            logging.warning(f"⚠️ Could not load existing index: {e}")

# 4. KNOWLEDGE BASE MANAGEMENT
class KnowledgeBaseManager:
    """Manages the knowledge base for explanations"""
    
    def __init__(self, agent: ExplanationAgent):
        self.agent = agent
    
    def add_explanation_documents(self, documents: List[Dict]):
        """
        Add explanation documents to the knowledge base
        
        Args:
            documents: List of dicts with 'title', 'content', 'category', 'tags'
        """
        try:
            # Prepare documents for embedding
            texts_to_embed = []
            new_metadata = []
            
            for doc in documents:
                # Create embedding text
                embedding_text = self._prepare_embedding_text(doc)
                texts_to_embed.append(embedding_text)
                
                # Store metadata
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
            
            # Generate embeddings
            embeddings = self.agent.embedding_model.encode(texts_to_embed)
            embedding_matrix = np.array(embeddings).astype('float32')
            
            # Update FAISS index
            if self.agent.vector_index is None:
                dimension = embedding_matrix.shape[1]
                self.agent.vector_index = faiss.IndexFlatL2(dimension)
            
            self.agent.vector_index.add(embedding_matrix)
            
            # Update metadata
            self.agent.metadata.extend(new_metadata)
            
            # Save updated index and metadata
            self._save_knowledge_base()
            
            logging.info(f"✅ Added {len(documents)} explanation documents to knowledge base")
            return True
            
        except Exception as e:
            logging.error(f"❌ Error adding documents: {e}")
            return False
    
    def _prepare_embedding_text(self, document: Dict) -> str:
        """Prepare text for embedding generation"""
        title = document.get('title', '')
        content = document.get('content', '')
        category = document.get('category', '')
        tags = ' '.join(document.get('tags', []))
        
        return f"{title} {content} {category} {tags}".strip()
    
    def _save_knowledge_base(self):
        """Save FAISS index and metadata to disk"""
        try:
            if self.agent.vector_index is not None:
                faiss.write_index(self.agent.vector_index, self.agent.config.INDEX_PATH)
            
            with open(self.agent.config.METADATA_PATH, 'w') as f:
                json.dump(self.agent.metadata, f, indent=2)
            
            logging.info("💾 Knowledge base saved successfully")
        except Exception as e:
            logging.error(f"❌ Error saving knowledge base: {e}")

# 5. RETRIEVAL SYSTEM
class ExplanationRetriever:
    """Handles retrieval of relevant explanations"""
    
    def __init__(self, agent: ExplanationAgent):
        self.agent = agent
    
    def retrieve_relevant_explanations(self, query: str, top_k: int = None) -> List[Tuple[Dict, float]]:
        """
        Retrieve relevant explanations for a query
        
        Args:
            query: User question
            top_k: Number of results to return
            
        Returns:
            List of (metadata, similarity_score) tuples
        """
        if top_k is None:
            top_k = self.agent.config.TOP_K
        
        if self.agent.vector_index is None or len(self.agent.metadata) == 0:
            logging.warning("⚠️ No knowledge base available for retrieval")
            return []
        
        try:
            # Generate query embedding
            query_embedding = self.agent.embedding_model.encode([query])
            query_vector = np.array(query_embedding).reshape(1, -1).astype('float32')
            
            # Search in FAISS index
            distances, indices = self.agent.vector_index.search(
                query_vector, 
                min(top_k, len(self.agent.metadata))
            )
            
            # Format results
            results = []
            for i, (idx, distance) in enumerate(zip(indices[0], distances[0])):
                if 0 <= idx < len(self.agent.metadata):
                    similarity_score = 1 / (1 + distance)  # Convert distance to similarity
                    if similarity_score >= self.agent.config.SIMILARITY_THRESHOLD:
                        results.append((self.agent.metadata[idx], similarity_score))
            
            # Sort by similarity score (highest first)
            results.sort(key=lambda x: x[1], reverse=True)
            
            logging.info(f"🔍 Retrieved {len(results)} relevant explanations for query: '{query}'")
            return results
            
        except Exception as e:
            logging.error(f"❌ Error during retrieval: {e}")
            return []

# 6. EXPLANATION GENERATOR
class ExplanationGenerator:
    """Generates explanations using LLM with retrieved context"""
    
    def __init__(self, agent: ExplanationAgent):
        self.agent = agent
    
    def generate_explanation(self, query: str, context: List[Tuple[Dict, float]]) -> Dict:
        """
        Generate explanation using retrieved context with robust error handling
        
        Args:
            query: Original user question
            context: Retrieved context with similarity scores
            
        Returns:
            Dictionary with explanation and metadata
        """
        try:
            # Prepare context for LLM
            formatted_context = self._format_context_for_llm(context)
            
            # Create system prompt
            system_prompt = self._create_system_prompt()
            
            # Generate response with better error handling
            try:
                response = self.agent.llm_client.chat.completions.create(
                    model=self.agent.config.MODEL_NAME,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": f"Question: {query}\n\nContext:\n{formatted_context}"}
                    ],
                    temperature=0.3,
                    max_tokens=1000,
                    timeout=30  # Add timeout
                )
                
                # Validate response
                if not response or not response.choices:
                    raise ValueError("Empty response from API")
                    
                explanation_text = response.choices[0].message.content
                
            except Exception as api_error:
                logging.warning(f"API call failed, using fallback explanation: {api_error}")
                explanation_text = self._generate_fallback_explanation(query, context)
            
            # Create explanation record
            explanation_record = {
                'timestamp': datetime.now().isoformat(),
                'query': query,
                'explanation': explanation_text,
                'sources_used': [ctx[0]['title'] for ctx in context],
                'confidence_scores': [ctx[1] for ctx in context],
                'context_count': len(context)
            }
            
            # Store in history
            self.agent.explanation_history.append(explanation_record)
            
            logging.info(f"🤖 Generated explanation for: '{query}'")
            return explanation_record
            
        except Exception as e:
            logging.error(f"❌ Critical error generating explanation: {e}")
            return self._create_error_response(query, str(e))
    
    def _generate_fallback_explanation(self, query: str, context: List[Tuple[Dict, float]]) -> str:
        """Generate explanation without API when LLM fails"""
        if context:
            sources = ", ".join([ctx[0]['title'] for ctx in context])
            return f"""Based on analysis of: {sources}. 

🔍 **Security Analysis:**
This appears to be suspicious network activity requiring immediate security review. The system detected unusual patterns that may indicate a security threat.

**Key Indicators:**
- Unusual traffic patterns detected
- Potential security policy violation
- Requires immediate investigation

**Recommended Actions:**
- Review security logs
- Check for policy violations
- Investigate source behavior"""
        else:
            return """🔍 **Security Alert Analysis:**

**Situation:** Suspicious network activity detected

**Assessment:** 
The system has identified unusual network patterns that deviate from normal behavior. This could indicate potential security threats, policy violations, or anomalous system behavior.

**Immediate Actions Recommended:**
1. Review security event logs
2. Investigate source and destination IPs
3. Check for policy violations
4. Monitor for further anomalous activity

**Note:** This detection is based on behavioral analysis and network pattern monitoring."""
    
    def _create_error_response(self, query: str, error_msg: str) -> Dict:
        """Create a proper error response"""
        return {
            'timestamp': datetime.now().isoformat(),
            'query': query,
            'explanation': f"""🔍 **Security Alert - Manual Analysis Required**

**Detection:** Suspicious network activity detected
**Confidence:** High (Requires investigation)

**Situation Overview:**
The system has flagged potentially malicious network behavior that warrants immediate security review. While the AI explanation service is temporarily unavailable, the detection indicates patterns consistent with security threats.

**Immediate Investigation Steps:**
1. Review source IP 192.168.1.100 activity
2. Check destination 192.168.1.1:80 for anomalies
3. Verify TCP connection legitimacy
4. Inspect firewall and security logs

*[System Note: Explanation service temporarily unavailable - {error_msg}]*""",
            'sources_used': [],
            'confidence_scores': [],
            'context_count': 0,
            'error': True
        }
    
    def _format_context_for_llm(self, context: List[Tuple[Dict, float]]) -> str:
        """Format retrieved context for LLM consumption"""
        if not context:
            return "No relevant context found in the knowledge base."
        
        formatted_parts = []
        for i, (metadata, score) in enumerate(context, 1):
            context_text = f"SOURCE {i} (Relevance: {score:.2f}):\n"
            context_text += f"Title: {metadata.get('title', 'N/A')}\n"
            context_text += f"Category: {metadata.get('category', 'N/A')}\n"
            context_text += f"Content: {metadata.get('content', 'N/A')}\n"
            if metadata.get('tags'):
                context_text += f"Tags: {', '.join(metadata.get('tags', []))}\n"
            formatted_parts.append(context_text)
        
        return "\n".join(formatted_parts)
    
    def _create_system_prompt(self) -> str:
        """Create system prompt for explanation generation"""
        return """
        You are an Expert Security Explanation Agent. Your role is to provide clear, accurate, 
        and comprehensive security explanations based on the provided context.

        GUIDELINES:
        1. Use ONLY the information from the provided context
        2. If the context doesn't contain relevant information, acknowledge this
        3. Structure your explanations clearly and logically for security analysts
        4. Be precise and focus on actionable security insights
        5. If multiple sources are provided, synthesize the information coherently
        6. Always provide practical security recommendations

        FORMAT:
        - Start with a clear security assessment
        - Explain the detected activity in context
        - Provide risk analysis and impact assessment
        - Give specific, actionable recommendations
        - End with key takeaways for the security team

        SECURITY FOCUS:
        - Network security incidents
        - Suspicious activity patterns
        - Threat analysis and risk assessment
        - Incident response recommendations
        """

# 7. MAIN EXPLANATION AGENT CLASS (FINAL)
class AdvancedExplanationAgent:
    """
    Complete Explanation Agent with RAG capabilities
    Follows modular architecture similar to your Detection Agent
    """
    
    def __init__(self, config: ExplanationConfig = None):
        self.config = config or ExplanationConfig()
        self.core_agent = ExplanationAgent(self.config)
        self.knowledge_manager = KnowledgeBaseManager(self.core_agent)
        self.retriever = ExplanationRetriever(self.core_agent)
        self.generator = ExplanationGenerator(self.core_agent)
        
        logging.info("🚀 Advanced Explanation Agent initialized")
    
    def add_knowledge(self, documents: List[Dict]) -> bool:
        """
        Add knowledge documents to the agent
        
        Args:
            documents: List of documents with title, content, category, tags
            
        Returns:
            Success status
        """
        return self.knowledge_manager.add_explanation_documents(documents)
    
    def explain(self, query: str, top_k: int = None) -> Dict:
        """
        Main method: Explain a concept/question using RAG
        
        Args:
            query: User question
            top_k: Number of context documents to use
            
        Returns:
            Complete explanation with metadata
        """
        # Step 1: Retrieve relevant context
        context = self.retriever.retrieve_relevant_explanations(query, top_k)
        
        # Step 2: Generate explanation
        explanation = self.generator.generate_explanation(query, context)
        
        return explanation
    
    def batch_explain(self, queries: List[str]) -> List[Dict]:
        """
        Explain multiple queries
        
        Args:
            queries: List of questions
            
        Returns:
            List of explanations
        """
        explanations = []
        for query in queries:
            explanation = self.explain(query)
            explanations.append(explanation)
        
        return explanations
    
    def get_agent_stats(self) -> Dict:
        """Get agent statistics"""
        return {
            'knowledge_base_size': len(self.core_agent.metadata),
            'explanation_history_count': len(self.core_agent.explanation_history),
            'categories_available': list(set([doc.get('category', 'unknown') for doc in self.core_agent.metadata])),
            'index_loaded': self.core_agent.vector_index is not None
        }
    
    def search_knowledge_base(self, query: str, top_k: int = 5) -> List[Dict]:
        """
        Direct search in knowledge base without generation
        
        Args:
            query: Search query
            top_k: Number of results
            
        Returns:
            List of relevant documents
        """
        results = self.retriever.retrieve_relevant_explanations(query, top_k)
        return [{"document": doc, "similarity": score} for doc, score in results]

# 8. SAMPLE DATA AND INITIALIZATION
def create_sample_knowledge_base():
    """Create sample knowledge base for testing"""
    sample_documents = [
        {
            'title': 'Network Security Basics',
            'content': 'Network security involves implementing measures to protect network infrastructure and data from unauthorized access, misuse, or attacks. This includes firewalls, intrusion detection systems, and access controls.',
            'category': 'security',
            'tags': ['network security', 'firewall', 'ids', 'ips']
        },
        {
            'title': 'Suspicious Network Activity',
            'content': 'Suspicious network activity includes unusual traffic patterns, port scanning, brute force attacks, data exfiltration attempts, and communication with known malicious IP addresses. These activities often indicate potential security breaches or attack preparations.',
            'category': 'security',
            'tags': ['suspicious activity', 'threat detection', 'anomalies', 'malicious traffic']
        },
        {
            'title': 'TCP Protocol Analysis',
            'content': 'TCP (Transmission Control Protocol) is a connection-oriented protocol that ensures reliable data delivery. Security analysis of TCP traffic involves monitoring connection patterns, port usage, packet flags, and traffic volume for anomalies.',
            'category': 'network',
            'tags': ['tcp', 'protocol', 'network analysis', 'traffic monitoring']
        },
        {
            'title': 'Intrusion Detection',
            'content': 'Intrusion detection systems monitor network traffic for suspicious activity and known attack patterns. They analyze traffic in real-time and generate alerts when potential security violations are detected.',
            'category': 'security',
            'tags': ['ids', 'intrusion detection', 'security monitoring', 'threat detection']
        },
        {
            'title': 'Incident Response',
            'content': 'Incident response involves the process of identifying, investigating, and responding to security incidents. Key steps include detection, analysis, containment, eradication, and recovery from security breaches.',
            'category': 'security',
            'tags': ['incident response', 'security operations', 'breach response', 'containment']
        },
        {
            'title': 'Port 80 HTTP Traffic',
            'content': 'Port 80 is used for HTTP web traffic. While normally legitimate, suspicious activity on port 80 can include data exfiltration, command and control communications, or web application attacks. Monitoring should focus on unusual patterns and unauthorized access attempts.',
            'category': 'network',
            'tags': ['port 80', 'http', 'web traffic', 'data exfiltration']
        }
    ]
    return sample_documents

# 9. SECURITY-SPECIFIC EXPLANATION METHODS
class SecurityExplanationAgent:
    """Specialized agent for security incident explanations"""
    
    def __init__(self, base_agent: AdvancedExplanationAgent):
        self.agent = base_agent
        
    def explain_security_incident(self, detection_data: Dict) -> Dict:
        """
        Generate security-focused explanation for detection incidents
        
        Args:
            detection_data: Dictionary with detection details
                Example: {
                    'attack_type': 'Suspicious Activity',
                    'confidence': 75.20,
                    'source': '192.168.1.100 → 192.168.1.1:80',
                    'protocol': 'tcp',
                    'timestamp': '2025-09-29T21:13:08.687712'
                }
        """
        query = self._build_security_query(detection_data)
        explanation = self.agent.explain(query)
        
        # Enhance with security-specific formatting
        enhanced_explanation = self._enhance_security_explanation(explanation, detection_data)
        return enhanced_explanation
    
    def _build_security_query(self, detection_data: Dict) -> str:
        """Build comprehensive security query from detection data"""
        attack_type = detection_data.get('attack_type', 'Unknown')
        source = detection_data.get('source', 'Unknown')
        protocol = detection_data.get('protocol', 'Unknown')
        confidence = detection_data.get('confidence', 0)
        
        return f"""
        Security incident analysis:
        - Attack Type: {attack_type}
        - Confidence: {confidence}%
        - Source: {source}
        - Protocol: {protocol}
        
        Please provide:
        1. What this security detection means
        2. Potential risks and impact
        3. Immediate response actions
        4. Investigation recommendations
        """
    
    def _enhance_security_explanation(self, explanation: Dict, detection_data: Dict) -> Dict:
        """Enhance explanation with security-specific formatting"""
        if 'explanation' in explanation:
            # Add security headers and formatting
            enhanced_text = f"🔒 **SECURITY INCIDENT ANALYSIS** 🔒\n\n"
            enhanced_text += f"**Detection Details:**\n"
            enhanced_text += f"- Type: {detection_data.get('attack_type', 'Unknown')}\n"
            enhanced_text += f"- Confidence: {detection_data.get('confidence', 0)}%\n"
            enhanced_text += f"- Source: {detection_data.get('source', 'Unknown')}\n"
            enhanced_text += f"- Protocol: {detection_data.get('protocol', 'Unknown')}\n"
            enhanced_text += f"- Time: {detection_data.get('timestamp', 'Unknown')}\n\n"
            enhanced_text += "---\n\n"
            enhanced_text += explanation['explanation']
            
            explanation['explanation'] = enhanced_text
        
        return explanation

# 10. SIMPLIFIED INTERFACE (like your DetectionAgent)
class SimpleExplanationAgent:
    """Simplified interface for easy integration"""
    
    def __init__(self):
        self.advanced_agent = AdvancedExplanationAgent()
        self.security_agent = SecurityExplanationAgent(self.advanced_agent)
        
        # Initialize with security knowledge base
        self._initialize_security_knowledge()
    
    def _initialize_security_knowledge(self):
        """Initialize with security-focused knowledge"""
        security_docs = create_sample_knowledge_base()
        self.advanced_agent.add_knowledge(security_docs)
    
    def ask(self, question: str) -> str:
        """Simple Q&A interface"""
        result = self.advanced_agent.explain(question)
        return result['explanation']
    
    def explain_detection(self, detection_results: Dict) -> str:
        """Explain security detection results"""
        result = self.security_agent.explain_security_incident(detection_results)
        return result['explanation']
    
    def add_document(self, title: str, content: str, category: str = "general", tags: List[str] = None):
        """Add a single document to knowledge base"""
        document = {
            'title': title,
            'content': content,
            'category': category,
            'tags': tags or []
        }
        return self.advanced_agent.add_knowledge([document])

# 11. UTILITY FUNCTIONS
def setup_logging():
    """Setup logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('explanation_agent.log')
        ]
    )

def get_fallback_explanation(detection_results: Dict) -> str:
    """Provide fallback explanations when the AI service fails"""
    attack_type = detection_results.get('attack_type', 'Suspicious Activity')
    confidence = detection_results.get('confidence', 0)
    source = detection_results.get('source', 'Unknown')
    
    return f"""
🔒 **SECURITY INCIDENT ANALYSIS** 🔒

**Detection Summary:**
- **Type:** {attack_type}
- **Confidence:** {confidence}%
- **Source:** {source}
- **Status:** REQUIRES IMMEDIATE ATTENTION

**Assessment:**
This security detection indicates potentially malicious network activity that warrants immediate investigation. The high confidence score suggests strong indicators of compromise or policy violation.

**Immediate Actions:**
1. 🔴 **ISOLATE** affected systems
2. 🔴 **BLOCK** source IP addresses
3. 🔴 **PRESERVE** logs and evidence
4. 🔴 **NOTIFY** security team

**Investigation Priorities:**
- Review firewall and IDS logs
- Check for data exfiltration attempts
- Verify system integrity
- Search for related incidents

**Note:** AI explanation service is currently using fallback mode. Manual investigation required.
"""

# 12. Run the system
if __name__ == "__main__":
    setup_logging()
    
    # Initialize agent
    agent = SimpleExplanationAgent()
    
    # Test with your detection results
    detection_results = {
        'attack_type': 'Suspicious Activity',
        'confidence': 75.20,
        'source': '192.168.1.100 → 192.168.1.1:80',
        'protocol': 'tcp',
        'timestamp': '2025-09-29T21:13:08.687712'
    }
    
    print("🧪 Testing Security Explanation Agent...")
    
    try:
        explanation = agent.explain_detection(detection_results)
        print("✅ Explanation generated successfully!")
        print(f"\n{explanation}")
    except Exception as e:
        print(f"❌ Error: {e}")
        print("🔄 Using fallback explanation...")
        fallback = get_fallback_explanation(detection_results)
        print(fallback)
    
    # Show agent statistics
    stats = agent.advanced_agent.get_agent_stats()
    print(f"\n📊 Agent Statistics: {stats}")