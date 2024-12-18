CUDA_CATEGORIES = {
    'memory': ['cuMemAlloc', 'cuMemFree', 'cuMemcpy'],
    'execution': ['cuLaunchKernel', 'cuStreamSynchronize'],
    'context': ['cuCtxCreate', 'cuCtxDestroy', 'cuCtxPushCurrent'],
    'stream': ['cuStreamCreate', 'cuStreamDestroy', 'cuStreamWaitEvent'],
    'event': ['cuEventCreate', 'cuEventRecord', 'cuEventSynchronize'],
    'module': ['cuModuleLoad', 'cuModuleGetFunction', 'cuModuleUnload']
}
