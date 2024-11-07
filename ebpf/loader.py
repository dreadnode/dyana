#!/usr/bin/env python3
from transformers import AutoModel, AutoTokenizer
import torch
import sys
import time

def main():
    # Load a small model for testing
    model_name = "prajjwal1/bert-tiny"

    print(f"Loading model {model_name}...")

    try:
        # Load model and tokenizer
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        model = AutoModel.from_pretrained(model_name)

        # Test inference multiple times
        for i in range(5):
            print(f"Running inference {i+1}/5...")
            text = f"Hello, this is test number {i+1}!"
            inputs = tokenizer(text, return_tensors="pt")
            outputs = model(**inputs)
            time.sleep(1)  # Add some delay to capture more events

        print("Model testing completed successfully!")

    except Exception as e:
        print(f"Error during execution: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()