def get_sample_documents():
    """Sample documents for demonstration"""
    return [
        {
            'title': 'Machine Learning Fundamentals',
            'content': '''
            Machine learning is a subset of artificial intelligence that focuses on developing algorithms 
            that can learn from and make predictions based on data. There are three main types of ML:
            1. Supervised Learning: Training on labeled data
            2. Unsupervised Learning: Finding patterns in unlabeled data  
            3. Reinforcement Learning: Learning through trial and error with rewards
            ''',
            'category': 'ai_ml',
            'tags': ['machine learning', 'ai', 'algorithms', 'supervised learning']
        },
        {
            'title': 'Neural Networks Deep Dive',
            'content': '''
            Neural networks are computational models inspired by biological neural networks. 
            Key components include:
            - Neurons/Nodes: Basic processing units
            - Layers: Input, hidden, and output layers
            - Weights: Connection strengths between neurons
            - Activation Functions: Determine neuron output (ReLU, Sigmoid, Tanh)
            - Backpropagation: Learning algorithm for adjusting weights
            ''',
            'category': 'ai_ml',
            'tags': ['neural networks', 'deep learning', 'ai', 'backpropagation']
        },
        {
            'title': 'FAISS Vector Database',
            'content': '''
            FAISS (Facebook AI Similarity Search) is a library for efficient similarity search 
            and clustering of dense vectors. Key features:
            - Supports various index types (Flat, IVF, HNSW)
            - GPU acceleration support
            - Optimized for billion-scale datasets
            - Memory-efficient operations
            Common use cases: recommendation systems, semantic search, duplicate detection.
            ''',
            'category': 'vector_search',
            'tags': ['faiss', 'vector search', 'similarity', 'embeddings']
        },
        {
            'title': 'RAG Architecture Explained',
            'content': '''
            Retrieval-Augmented Generation (RAG) combines information retrieval with large language models.
            Architecture components:
            1. Retriever: Finds relevant documents (using vector search)
            2. Generator: LLM that produces answers using retrieved context
            3. Knowledge Base: Collection of documents for retrieval
            Benefits: More accurate, up-to-date, and verifiable responses compared to pure generation.
            ''',
            'category': 'rag',
            'tags': ['rag', 'retrieval', 'generation', 'llm', 'architecture']
        },
        {
            'title': 'Transformer Architecture',
            'content': '''
            Transformers are neural network architectures that use self-attention mechanisms.
            Key components:
            - Self-Attention: Weights importance of different input parts
            - Multi-Head Attention: Multiple attention mechanisms in parallel
            - Positional Encoding: Adds information about token positions
            - Feed-Forward Networks: Applies transformations to each position separately
            Transformers revolutionized NLP with models like BERT, GPT, and T5.
            ''',
            'category': 'ai_ml',
            'tags': ['transformer', 'attention', 'nlp', 'gpt', 'bert']
        }
    ]