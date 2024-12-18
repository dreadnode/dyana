from bcc import BPF
import ctypes as ct
import torch
import logging
from .categories import CUDA_CATEGORIES
from .bpf_programs import BPF_CUDA_PROGRAM
from .gpu_info import get_gpu_info

class CUDATracer:
    def __init__(self):
        self.bpf = BPF(text=BPF_CUDA_PROGRAM)
        self.events = []
        self.gpu_info = get_gpu_info()
        self.bpf["cuda_events"].open_ring_buffer(self.process_event)

    def process_event(self, cpu, data, size):
        event = self.bpf["cuda_events"].event(data)
        cuda_call = {
            "pid": event.pid,
            "timestamp": event.timestamp,
            "duration": event.duration,
            "function": event.function.decode('utf-8', 'replace'),
            "status": event.status
        }
        self.events.append(cuda_call)

    def get_cuda_stats(self):
        return {
            "total_calls": len(self.events),
            "calls_by_category": self._categorize_calls(),
            "timing": self._analyze_timing(),
            "errors": self._collect_errors(),
            "gpu_info": self.gpu_info
        }

    def _categorize_calls(self):
        categories = {cat: 0 for cat in CUDA_CATEGORIES.keys()}
        for event in self.events:
            for cat, funcs in CUDA_CATEGORIES.items():
                if any(f in event["function"] for f in funcs):
                    categories[cat] += 1
        return categories

    def _analyze_timing(self):
        return {
            "total_duration": sum(e["duration"] for e in self.events),
            "avg_duration": sum(e["duration"] for e in self.events) / len(self.events) if self.events else 0,
            "max_duration": max((e["duration"] for e in self.events), default=0)
        }

    def _collect_errors(self):
        return [e for e in self.events if e["status"] != 0]
