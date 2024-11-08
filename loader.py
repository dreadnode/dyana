def main():
    parser = argparse.ArgumentParser(description="Profile HuggingFace models")
    parser.add_argument("--path", help="Path to HF model directory", default=None)
    parser.add_argument("--output", help="Path to output file", default=None)
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    try:
        # Default test model if no path provided (small model)
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

        # Default output filename if none provided
        output_file = args.output
        if not output_file:
            base_name = model_path.split('/')[-1]
            output_file = f"profile_{base_name}.json"
            logger.info(f"No output path provided. Using default: {output_file}")

        logger.info(f"Saving results to {output_file}")
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)

        logger.info("Profiling completed successfully")

    except Exception as e:
        logger.error(f"Fatal error during profiling: {str(e)}")
        sys.exit(1)