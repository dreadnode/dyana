from transformers import AutoModel, AutoTokenizer

import json
import os
import argparse

import profiler


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Profile model files")
    parser.add_argument("path", help="Path to HF model directory")
    parser.add_argument("output", help="Path to output file")
    args = parser.parse_args()

    path = os.path.abspath(args.path)
    base_name = os.path.basename(path)

    print(f"loading {path} ...")

    try:
        profiler.start_trace()
        tokenizer = AutoTokenizer.from_pretrained(path)
        tokenizer_trace = profiler.stop_trace()
    except Exception as e:
        tokenizer_trace = {"error": str(e)}

    try:
        profiler.start_trace()
        model = AutoModel.from_pretrained(path)
        model_trace = profiler.stop_trace()
    except Exception as e:
        model_trace = {"error": str(e)}

    print(f"saving trace to {args.output} ...")
    with open(args.output, "w+t") as f:
        json.dump(
            {
                "base_name": base_name,
                "tokenizer": tokenizer_trace,
                "model": model_trace,
            },
            f,
            indent=2,
        )

    print("done")