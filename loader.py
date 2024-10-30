from transformers import AutoModel, AutoTokenizer

import json
import os
import argparse
import sys
import time


def build_python_function_name(frame):
    func_name = str(frame.f_code.co_name)
    # get the class name if the function is a method
    if "self" in frame.f_locals:
        cls_name = frame.f_locals["self"].__class__.__name__
        func_name = f"{cls_name}.{func_name}"

    module = frame.f_globals.get("__name__", "")
    if module:
        func_name = f"{module}.{func_name}"

    return func_name


def serialize_arg_value(value):
    try:
        return json.dumps(value)
    except:  # noqa: E722
        try:
            return str(value)
        except:  # noqa: E722
            try:
                return f"{type(value)}"
            except:  # noqa: E722
                pass

    return "?"


def build_function_args(frame):
    args = {}
    for i in range(frame.f_code.co_argcount):
        name = frame.f_code.co_varnames[i]
        args[name] = serialize_arg_value(frame.f_locals[name])

    return args


def build_core_function_name(arg):
    if arg.__module__:
        return f"{arg.__module__}.{arg.__name__}"
    else:
        return f"{arg.__qualname__}"


trace = []


def tracefunc(frame, event, arg):
    func_type = None
    func_name = None
    func_args = {}

    if event == "call":
        func_type = "python"
        func_name = build_python_function_name(frame)
        func_args = build_function_args(frame)

    elif event == "c_call":
        func_type = "core"
        func_name = build_core_function_name(arg)
        func_args = build_function_args(frame)

    if func_name:
        trace.append(
            {
                "time": time.time_ns(),
                "type": func_type,
                "name": func_name,
                "args": func_args,
            }
        )

    return tracefunc


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Profile model files")
    parser.add_argument("path", help="Path to HF model directory")
    args = parser.parse_args()

    path = os.path.abspath(args.path)

    print(f"loading {path} ...")

    sys.setprofile(tracefunc)

    model = AutoModel.from_pretrained(path)
    tokenizer = AutoTokenizer.from_pretrained(path)

    sys.setprofile(None)

    print("saving trace to /output/trace.json ...")
    with open("/output/trace.json", "w+t") as f:
        json.dump(trace, f)
