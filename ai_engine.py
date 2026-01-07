import os
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from threading import Lock

class AIEngine:
    _instance = None
    _lock = Lock()

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, 'model'):
            self.model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Qwen3-0.6B')
            print(f"Loading AI Model from {self.model_path}...")
            try:
                # Load model efficiently
                self.tokenizer = AutoTokenizer.from_pretrained(self.model_path, trust_remote_code=True)
                self.model = AutoModelForCausalLM.from_pretrained(
                    self.model_path, 
                    torch_dtype=torch.float32, # Use float32 for CPU compatibility and stability on small RAM
                    device_map="auto", 
                    trust_remote_code=True
                )
                print("AI Model Loaded Successfully!")
            except Exception as e:
                print(f"Failed to load AI Model: {e}")
                self.model = None

    def generate(self, prompt, max_new_tokens=100):
        if not self.model:
            return "AI Model is not loaded."
        
        try:
            inputs = self.tokenizer(prompt, return_tensors="pt").to(self.model.device)
            # Generate
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs, 
                    max_new_tokens=max_new_tokens,
                    do_sample=True,
                    temperature=0.7,
                    top_p=0.9
                )
            # Decode
            response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            # Simple post-processing to remove the prompt itself if model echoes it
            if response.startswith(prompt):
               response = response[len(prompt):].strip()
            return response
        except Exception as e:
            return f"Error generating response: {e}"

# Global instance
ai_engine = AIEngine()
