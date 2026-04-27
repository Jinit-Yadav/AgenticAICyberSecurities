#!/usr/bin/env python3
"""
Update detection agent to use clean model
Run: python update_detection_agent.py
"""

import os
import re
from pathlib import Path

detection_agent_path = Path('src/agents/detection_agent.py')

if detection_agent_path.exists():
    print(f"✅ Found detection agent: {detection_agent_path}")
    
    with open(detection_agent_path, 'r') as f:
        content = f.read()
    
    # Update model paths
    content = content.replace('ultimate_model.pkl', 'clean_model.pkl')
    content = content.replace('final_scaler.pkl', 'clean_scaler.pkl')
    content = content.replace('ultimate_scaler.pkl', 'clean_scaler.pkl')
    content = content.replace('selected_features.pkl', 'clean_features.pkl')
    
    # Comment out threat_score usage
    content = re.sub(
        r'(threat_score\s*=.*?)(?=\n)',
        r'# \1  # REMOVED - Data leakage',
        content,
        flags=re.MULTILINE
    )
    
    # Save backup and new version
    backup_path = detection_agent_path.with_suffix('.py.bak')
    with open(backup_path, 'w') as f:
        f.write(open(detection_agent_path, 'r').read())
    
    with open(detection_agent_path, 'w') as f:
        f.write(content)
    
    print(f"✅ Detection agent updated")
    print(f"   Backup saved: {backup_path}")
    print(f"   Now using clean_model.pkl (no data leakage)")
    
else:
    print(f"❌ Detection agent not found at {detection_agent_path}")