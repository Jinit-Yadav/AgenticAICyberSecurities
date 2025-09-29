import pandas as pd
import numpy as np

def debug_hybrid_data():
    """Debug the hybrid dataset to see what's happening"""
    
    # Load your ML-ready data
    try:
        df = pd.read_csv("artifacts/ml_ready_dataset.csv")
        print("🔍 DEBUGGING HYBRID DATASET")
        print("="*50)
        
        # Basic info
        print(f"📊 Total records: {len(df):,}")
        print(f"🎯 Columns: {list(df.columns)}")
        
        # Check threat distribution
        if 'is_threat' in df.columns:
            threat_count = df['is_threat'].sum()
            normal_count = len(df) - threat_count
            print(f"⚠️  Threats: {threat_count:,} ({threat_count/len(df)*100:.2f}%)")
            print(f"✅ Normal: {normal_count:,} ({normal_count/len(df)*100:.2f}%)")
        else:
            print("❌ 'is_threat' column not found!")
            
        # Check data sources (if 'tool' column exists)
        if 'tool' in df.columns:
            print(f"\n🔧 Data Sources (Tools):")
            tool_counts = df['tool'].value_counts()
            for tool, count in tool_counts.items():
                print(f"   • {tool}: {count:,} records")
                
        # Check first few rows
        print(f"\n📝 First 5 rows:")
        print(df.head())
        
        # Check for UNSW data
        if 'tool' in df.columns:
            unsw_count = (df['tool'] == 'unsw_dataset').sum()
            print(f"\n🌐 UNSW-NB15 records: {unsw_count:,}")
            
    except Exception as e:
        print(f"❌ Error loading data: {e}")

if __name__ == "__main__":
    debug_hybrid_data()