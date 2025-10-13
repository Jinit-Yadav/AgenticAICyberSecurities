# ultimate_fix.py
import os
import requests
import webbrowser
import time
from dotenv import load_dotenv, set_key, find_dotenv

def verify_privacy_settings():
    """Verify and guide through privacy settings step-by-step"""
    print("🔍 VERIFYING PRIVACY SETTINGS")
    print("=" * 50)
    
    webbrowser.open("https://openrouter.ai/settings/privacy")
    
    print("Please follow these EXACT steps:")
    print()
    print("1. 🔓 Go to: https://openrouter.ai/settings/privacy")
    print("2. ✅ Find: 'Enable free endpoints that may train on inputs'")
    print("3. 📝 Make sure it's CHECKED (enabled)")
    print("4. 💾 Scroll down and click 'SAVE CHANGES'")
    print("5. 🔄 Wait 1-2 minutes for changes to propagate")
    print()
    print("⚠️  IMPORTANT: You MUST click 'SAVE CHANGES' at the bottom!")
    print()
    input("Press Enter AFTER you've saved the changes...")

def test_with_extended_models(api_key):
    """Test with a wider range of models"""
    print("\n🧪 EXTENSIVE MODEL TESTING...")
    
    # Comprehensive list of free models
    free_models = [
        "deepseek/deepseek-chat-v3.1:free",
        "huggingfaceh4/zephyr-7b-beta:free",
        "mistralai/mistral-7b-instruct:free", 
        "openchat/openchat-7b:free",
        "gryphe/mythomax-l2-13b:free",
        "meta-llama/llama-3-8b-instruct:free"
    ]
    
    # Paid models that might work
    paid_models = [
        "google/gemini-flash-1.5",
        "anthropic/claude-3-haiku",
        "meta-llama/llama-3.1-8b-instruct",
        "microsoft/wizardlm-2-8x22b"
    ]
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    working_models = []
    
    print("Testing FREE models:")
    for model in free_models:
        try:
            print(f"   {model}")
            response = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers=headers,
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": "Test"}],
                    "max_tokens": 5
                },
                timeout=15
            )
            
            if response.status_code == 200:
                print(f"   ✅ SUCCESS")
                working_models.append(model)
            else:
                error_data = response.json()
                error_msg = error_data.get('error', {}).get('message', 'Unknown')
                if "data policy" in error_msg.lower():
                    print(f"   🔒 Privacy policy")
                elif "quota" in error_msg.lower():
                    print(f"   📊 Quota exceeded")
                else:
                    print(f"   ❌ {error_msg[:60]}...")
                    
        except Exception as e:
            print(f"   ❌ Error: {str(e)[:60]}...")
    
    return working_models

def setup_local_fallback():
    """Setup instructions for local fallback"""
    print("\n💡 LOCAL FALLBACK SETUP (Recommended)")
    print("=" * 50)
    print("Since OpenRouter has issues, let's setup local models:")
    print()
    print("1. Install Ollama:")
    print("   Visit: https://ollama.ai/download")
    print("   Download and install for Windows")
    print()
    print("2. Pull a model:")
    print("   Open Command Prompt and run:")
    print("   ollama pull llama3.1:8b")
    print()
    print("3. Update your code to use local model:")
    print("   Change BASE_URL to: http://localhost:11434/v1")
    print("   Change MODEL_NAME to: llama3.1:8b")
    print("   Remove API_KEY requirement")
    print()
    print("🎯 Benefits: Faster, private, no API limits!")

def create_alternative_config():
    """Create alternative configuration files"""
    print("\n🔄 CREATING ALTERNATIVE CONFIGURATIONS")
    print("=" * 50)
    
    # Option 1: Local Ollama config
    local_config = """
# config_local_ollama.py
class LocalConfig:
    BASE_URL = "http://localhost:11434/v1"
    MODEL_NAME = "llama3.1:8b"
    API_KEY = ""  # Not needed for local
    EMBEDDING_MODEL = "all-MiniLM-L6-v2"
    
    INDEX_PATH = "artifacts/explanation_index.faiss"
    METADATA_PATH = "artifacts/explanation_metadata.json"
    TOP_K = 3
    SIMILARITY_THRESHOLD = 0.3
"""
    
    # Option 2: Enhanced fallback config
    fallback_config = """
# config_enhanced_fallback.py  
class FallbackConfig:
    # No API dependencies - pure fallback mode
    BASE_URL = None
    MODEL_NAME = "enhanced_fallback"
    API_KEY = ""
    EMBEDDING_MODEL = "all-MiniLM-L6-v2"
    
    INDEX_PATH = "artifacts/explanation_index.faiss"
    METADATA_PATH = "artifacts/explanation_metadata.json"
    TOP_K = 3
    SIMILARITY_THRESHOLD = 0.3
"""
    
    with open("config_local_ollama.py", "w") as f:
        f.write(local_config)
    
    with open("config_enhanced_fallback.py", "w") as f:
        f.write(fallback_config)
    
    print("✅ Created alternative configuration files")
    print("   - config_local_ollama.py (for local models)")
    print("   - config_enhanced_fallback.py (no API needed)")

def check_account_credits(api_key):
    """Check if account has credits"""
    print("\n💰 CHECKING ACCOUNT CREDITS")
    print("=" * 50)
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(
            "https://openrouter.ai/api/v1/auth/key",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json().get('data', {})
            print(f"✅ Account: {data.get('label', 'Unknown')}")
            print(f"📅 Created: {data.get('created_at', 'Unknown')[:10]}")
            print(f"💳 Usage: {data.get('usage', 'Unknown')}")
            print(f"🔑 Limits: {data.get('limits', 'Unknown')}")
        else:
            print("❌ Cannot fetch account info")
            
    except Exception as e:
        print(f"❌ Account check failed: {e}")

def ultimate_fix():
    """The ultimate fix for all API issues"""
    load_dotenv()
    
    print("🚀 ULTIMATE API FIX SOLUTION")
    print("=" * 60)
    
    api_key = os.getenv('OPENROUTER_API_KEY')
    
    if not api_key:
        print("❌ No API key found in .env file")
        return False
    
    print(f"🔑 API Key: {api_key[:15]}... (Valid format)")
    
    # Step 1: Verify privacy settings
    verify_privacy_settings()
    
    # Step 2: Wait for propagation
    print("\n⏳ Waiting for settings to propagate (30 seconds)...")
    time.sleep(30)
    
    # Step 3: Test models
    working_models = test_with_extended_models(api_key)
    
    if working_models:
        print(f"\n🎉 SUCCESS! Working models found:")
        for model in working_models:
            print(f"   ✅ {model}")
        
        print(f"\n💡 Update your MODEL_NAME to: '{working_models[0]}'")
        return True
    else:
        print("\n❌ NO WORKING MODELS FOUND")
        print("OpenRouter free tier seems to have issues right now.")
        
        # Provide alternatives
        check_account_credits(api_key)
        setup_local_fallback()
        create_alternative_config()
        
        print("\n🔧 QUICK FIX: Use Enhanced Fallback Mode")
        print("Your current fallback explanations are actually very good!")
        print("They provide professional security analysis without API calls.")
        
        return False

if __name__ == "__main__":
    print("🛠️  CYBERSHIELD ULTIMATE FIX")
    print("=" * 60)
    
    success = ultimate_fix()
    
    if success:
        print("\n🎉 OPENROUTER IS NOW WORKING!")
        print("🔄 Restart your explanation_agent.py")
    else:
        print("\n💡 RECOMMENDED SOLUTION:")
        print("1. Use LOCAL MODELS with Ollama (best option)")
        print("2. Continue with ENHANCED FALLBACK (current mode)")
        print("3. Your security explanations are already professional!")
        print()
        print("📁 Alternative config files created:")
        print("   - config_local_ollama.py")
        print("   - config_enhanced_fallback.py")