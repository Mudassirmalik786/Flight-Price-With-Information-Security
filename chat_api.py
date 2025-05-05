import os
import requests

def chat_with_model(prompt: str):
    api_url = "https://api.groq.com/v1/chat"  # replace with actual GROq API URL
    headers = {
        "Authorization": f"Bearer {os.getenv('GROQ_API_KEY')}",  # Ensure GROQ_API_KEY is in your .env file
        "Content-Type": "application/json"
    }
    data = {
        "messages": [{"role": "user", "content": prompt}]
    }
    
    response = requests.post(api_url, json=data, headers=headers)
    
    if response.status_code == 200:
        return response.json()["choices"][0]["message"]["content"]
    else:
        return "Error: Unable to fetch response."
