"""
Find the correct NVIDIA model ID
"""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv('OPENROUTER_API_KEY')

# List of NVIDIA models to test
models_to_test = [
    "nvidia/nemotron-3-super:free",
    "nvidia/nemotron-3-super",
    "nvidia/nemotron-3-super-120b-a12b:free",
    "nvidia/nemotron-3-super-120b-a12b",
    "nvidia/llama-nemotron-3-super:free",
    "nvidia/llama-nemotron-3-super",
]

headers = {
    'Authorization': f'Bearer {api_key}',
    'Content-Type': 'application/json'
}

print("Testing NVIDIA models...\n")

working_models = []

for model in models_to_test:
    print(f"Testing: {model}")
    
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "Hi"}],
        "max_tokens": 5
    }
    
    try:
        response = requests.post(
            'https://openrouter.ai/api/v1/chat/completions',
            headers=headers,
            json=payload,
            timeout=10
        )
        
        if response.status_code == 200:
            print(f"  ✅ WORKING!")
            working_models.append(model)
        elif response.status_code == 400:
            error = response.json()
            print(f"  ❌ Invalid model: {error.get('error', {}).get('message', 'Unknown error')[:80]}")
        elif response.status_code == 401:
            print("  ❌ Invalid API key")
            break
        else:
            print(f"  ❌ Error {response.status_code}")
            
    except Exception as e:
        print(f"  ❌ Connection error: {e}")
    
    print()

if working_models:
    print("✅ WORKING MODELS:")
    for model in working_models:
        print(f"   {model}")
else:
    print("❌ No working NVIDIA models found. Trying other free models...")
    
    # Try other free models from your list
    other_models = [
        "stepfun/step-3.5-flash:free",
        "minimax/minimax-m2.5:free",
        "google/gemini-2.0-flash-exp:free",
        "microsoft/phi-3.5-mini-128k-instruct:free"
    ]
    
    for model in other_models:
        print(f"\nTesting: {model}")
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": "Hi"}],
            "max_tokens": 5
        }
        
        try:
            response = requests.post(
                'https://openrouter.ai/api/v1/chat/completions',
                headers=headers,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                print(f"  ✅ WORKING! Use this model: {model}")
                working_models.append(model)
            elif response.status_code == 400:
                error = response.json()
                print(f"  ❌ Invalid: {error.get('error', {}).get('message', 'Unknown')[:80]}")
            else:
                print(f"  ❌ Error {response.status_code}")
        except Exception as e:
            print(f"  ❌ Error: {e}")