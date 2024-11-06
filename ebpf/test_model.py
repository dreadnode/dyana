from transformers import AutoModel, AutoTokenizer
import torch

def main():
    # Load a small model for testing
    model_name = "prajjwal1/bert-tiny"

    # Load model and tokenizer
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModel.from_pretrained(model_name)

    # Test inference
    text = "Hello, this is a test!"
    inputs = tokenizer(text, return_tensors="pt")
    outputs = model(**inputs)

    print("Model loaded and tested successfully!")

if __name__ == "__main__":
    main()