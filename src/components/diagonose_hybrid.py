import os
import pandas as pd
import numpy as np

def diagnose_hybrid_issue():
    """Diagnose why UNSW-NB15 data is missing"""
    
    print("🔍 DIAGNOSING HYBRID DATA ISSUE")
    print("="*60)
    
    # Check if UNSW file exists
    unsw_path = 'notebook/data/UNSW_NB15_training-set.csv'
    print(f"📁 Checking UNSW path: {unsw_path}")
    print(f"✅ File exists: {os.path.exists(unsw_path)}")
    
    if os.path.exists(unsw_path):
        # Try to load UNSW data
        try:
            unsw_df = pd.read_csv(unsw_path)
            print(f"📊 UNSW data shape: {unsw_df.shape}")
            print(f"🎯 UNSW columns: {list(unsw_df.columns)}")
            
            # Check if UNSW has threat labels
            if 'label' in unsw_df.columns:
                threats = unsw_df['label'].sum()
                normal = len(unsw_df) - threats
                print(f"⚠️  UNSW Threats: {threats:,} ({threats/len(unsw_df)*100:.2f}%)")
                print(f"✅ UNSW Normal: {normal:,} ({normal/len(unsw_df)*100:.2f}%)")
            else:
                print("❌ 'label' column not found in UNSW data")
                
        except Exception as e:
            print(f"❌ Error loading UNSW data: {e}")
    else:
        print("💡 UNSW file not found! Download it from:")
        print("   https://research.unsw.edu.au/projects/unsw-nb15-dataset")
    
    print("\n" + "="*60)
    
    # Check processed attack data
    attack_path = 'artifacts/processed_attack_data.csv'
    print(f"📁 Checking attack data: {attack_path}")
    print(f"✅ File exists: {os.path.exists(attack_path)}")
    
    if os.path.exists(attack_path):
        attack_df = pd.read_csv(attack_path)
        print(f"📊 Attack data shape: {attack_df.shape}")
        if 'is_threat' in attack_df.columns:
            threats = attack_df['is_threat'].sum()
            print(f"🔧 Attack data threats: {threats:,}")

if __name__ == "__main__":
    diagnose_hybrid_issue()