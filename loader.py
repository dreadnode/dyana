#!/usr/bin/env python3
from transformers import AutoModel, AutoTokenizer, AutoConfig
import torch
import json
import os
import argparse
import logging
import resource
import sys
import time
import signal
from contextlib import contextmanager
from typing import Dict, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@contextmanager
def timeout(seconds):
    def signal_handler(signum, frame):
        raise TimeoutError(f"Timed out after {seconds} seconds")

    # Set the signal handler and alarm
    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(seconds)

    try:
        yield
    finally:
        # Disable the alarm
        signal.alarm(0)

class ModelProfiler:
    def __init__(self, model_path: str):
        self.model_path = model_path
        self.base_name = os.path.basename(model_path)
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.config = None
        self.tokenizer = None

        logger.info("=== INITIALIZATION PHASE START ===")
        logger.info(f"Using device: {self.device}")
        time.sleep(0.1)  # Give tracer time to catch the marker

    @contextmanager
    def _memory_tracker(self):
        """Track memory usage during operations."""
        try:
            initial_mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            torch_initial = torch.cuda.memory_allocated() if torch.cuda.is_available() else 0
            yield
        finally:
            final_mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            torch_final = torch.cuda.memory_allocated() if torch.cuda.is_available() else 0

            memory_used = final_mem - initial_mem
            torch_used = torch_final - torch_initial

            logger.info(f"System memory used: {memory_used / 1024:.2f} MB")
            if torch.cuda.is_available():
                logger.info(f"GPU memory used: {torch_used / 1024 / 1024:.2f} MB")

    def get_model_metadata(self) -> Dict[str, Any]:
        """Collect model metadata without loading the full model."""
        logger.info("=== METADATA COLLECTION PHASE START ===")
        try:
            self.config = AutoConfig.from_pretrained(self.model_path)
            metadata = {
                "model_type": self.config.model_type,
                "hidden_size": getattr(self.config, "hidden_size", None),
                "num_attention_heads": getattr(self.config, "num_attention_heads", None),
                "num_hidden_layers": getattr(self.config, "num_hidden_layers", None),
                "vocab_size": getattr(self.config, "vocab_size", None),
                "model_path": self.model_path,
                "device": self.device,
                "file_size_mb": self._get_model_size(),
            }
            logger.info("=== METADATA COLLECTION PHASE END ===")
            return metadata
        except Exception as e:
            logger.error(f"Error getting model metadata: {str(e)}")
            return {"error": str(e)}

    def _get_model_size(self) -> float:
        """Calculate total size of model files in MB."""
        if not os.path.isdir(self.model_path):
            return 0.0

        total_size = 0
        for root, _, files in os.walk(self.model_path):
            for file in files:
                if file.endswith(('.bin', '.pt', '.pth', '.safetensors')):
                    file_path = os.path.join(root, file)
                    total_size += os.path.getsize(file_path)
        return total_size / (1024 * 1024)  # Convert to MB

    def profile_tokenizer(self) -> Dict[str, Any]:
        """Profile tokenizer loading and basic operations."""
        logger.info("=== TOKENIZER LOADING PHASE START ===")
        try:
            with self._memory_tracker():
                self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)

                # Test basic tokenizer operations
                sample_text = "Testing tokenizer functionality"
                tokens = self.tokenizer(sample_text)

                results = {
                    "status": "success",
                    "vocab_size": len(self.tokenizer),
                    "sample_encoding": len(tokens["input_ids"]),
                    "tokenizer_type": type(self.tokenizer).__name__
                }

            logger.info("=== TOKENIZER LOADING PHASE END ===")
            return results
        except Exception as e:
            logger.error(f"Tokenizer error: {str(e)}")
            return {"error": str(e)}

    def profile_model(self) -> Dict[str, Any]:
        """Profile model loading and basic operations."""
        try:
            logger.info("=== MODEL LOADING PHASE START ===")
            with self._memory_tracker():
                model = AutoModel.from_pretrained(
                    self.model_path,
                    torch_dtype=torch.float16 if self.device == "cuda" else torch.float32
                )
                model.to(self.device)

                # Get model statistics
                num_parameters = sum(p.numel() for p in model.parameters())
                trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)

            logger.info("=== INFERENCE PHASE START ===")
            # Add timeout for inference
            with self._memory_tracker(), timeout(seconds=30):
                sample_text = "Testing model inference"
                inputs = self.tokenizer(
                    sample_text,
                    return_tensors="pt",
                    padding=True,
                    truncation=True
                ).to(self.device)

                with torch.no_grad():
                    outputs = model(**inputs)

            logger.info("=== CLEANUP PHASE START ===")
            # Force cleanup
            del model
            if torch.cuda.is_available():
                torch.cuda.empty_cache()

            return {
                "status": "success",
                "inference_completed": True,
                "num_parameters": num_parameters,
                "trainable_parameters": trainable_params,
                "model_type": type(model).__name__,
                "output_shapes": {k: list(v.shape) for k, v in outputs.items()},
            }

        except TimeoutError:
            logger.warning("Model inference timed out after 30 seconds")
            return {
                "status": "timeout",
                "inference_completed": False
            }
        except Exception as e:
            logger.error(f"Error in profile_model: {str(e)}")
            return {
                "status": "error",
                "error": str(e)
            }

def main():
    parser = argparse.ArgumentParser(description="Profile HuggingFace models")
    parser.add_argument("--path", help="Path to HF model directory", default=None)
    parser.add_argument("--output", help="Path to output file", default=None)
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    try:
        # Create output directory if it doesn't exist
        output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'traces')
        os.makedirs(output_dir, exist_ok=True)

        # Default test model if no path provided
        model_path = args.path
        if not model_path:
            model_name = "prajjwal1/bert-tiny"
            logger.info(f"No model path provided. Using test model: {model_name}")
            model_path = model_name

        profiler_instance = ModelProfiler(model_path)
        logger.info(f"Profiling model at {profiler_instance.model_path}")

        results = {
            "base_name": profiler_instance.base_name,
            "metadata": profiler_instance.get_model_metadata(),
            "tokenizer": profiler_instance.profile_tokenizer(),
            "model": profiler_instance.profile_model(),
        }

        # Default output filename with absolute path
        output_file = args.output
        if not output_file:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            base_name = model_path.split('/')[-1]
            output_file = os.path.join(output_dir, f"profile_{base_name}_{timestamp}.json")
            logger.info(f"No output path provided. Using default: {output_file}")

        logger.info(f"Saving results to {output_file}")
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)

        logger.info("Profiling completed successfully")

        # Add debug logging
        logger.info(f"Current working directory: {os.getcwd()}")
        logger.info(f"Script location: {os.path.abspath(__file__)}")
        logger.info(f"Output directory: {output_dir}")

    except Exception as e:
        logger.error(f"Fatal error during profiling: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()