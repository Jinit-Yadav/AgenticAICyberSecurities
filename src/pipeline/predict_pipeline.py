import sys
import pandas as pd
from src.utils import load_object

class PredictPipeline:
    def __init__(self):
        self.model = None
        self.preprocessor = None
        
    def load_artifacts(self):
        """Load model and preprocessor"""
        try:
            self.model = load_object('artifacts/cyber_threat_model.pkl')
            # Try to load preprocessor if it exists
            try:
                self.preprocessor = load_object('artifacts/preprocessor.pkl')
            except:
                self.preprocessor = None
        except Exception as e:
            raise Exception(f"Error loading artifacts: {e}")
    
    def predict(self, features):
        """Make prediction"""
        try:
            # Load artifacts if not loaded
            if self.model is None:
                self.load_artifacts()
            
            # If we have a preprocessor, use it
            if self.preprocessor is not None:
                features = self.preprocessor.transform(features)
            
            # Make prediction
            predictions = self.model.predict(features)
            return predictions
            
        except Exception as e:
            raise Exception(f"Error during prediction: {e}")

class CustomData:
    """Class for cybersecurity threat prediction data"""
    
    def __init__(self, 
                 tool: str,
                 attack_category: str, 
                 severity: str,
                 protocol: str,
                 source_ip: str,
                 target_ip: str,
                 target_port: int,
                 dur: float = 0.0,
                 spkts: int = 0,
                 dpkts: int = 0,
                 sbytes: int = 0,
                 dbytes: int = 0):
        
        self.tool = tool
        self.attack_category = attack_category
        self.severity = severity
        self.protocol = protocol
        self.source_ip = source_ip
        self.target_ip = target_ip
        self.target_port = target_port
        self.dur = dur
        self.spkts = spkts
        self.dpkts = dpkts
        self.sbytes = sbytes
        self.dbytes = dbytes
    
    def get_data_as_data_frame(self):
        """Convert input data to dataframe"""
        try:
            custom_data_input_dict = {
                'tool': [self.tool],
                'attack_category': [self.attack_category],
                'severity': [self.severity],
                'protocol': [self.protocol],
                'source_ip': [self.source_ip],
                'target_ip': [self.target_ip],
                'target_port': [self.target_port],
                'dur': [self.dur],
                'spkts': [self.spkts],
                'dpkts': [self.dpkts],
                'sbytes': [self.sbytes],
                'dbytes': [self.dbytes]
            }
            
            return pd.DataFrame(custom_data_input_dict)
            
        except Exception as e:
            raise Exception(f"Error creating dataframe: {e}")