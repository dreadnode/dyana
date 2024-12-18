from enum import Enum

class CUDAOperationType(Enum):
    MEMORY = "memory"
    EXECUTION = "execution"
    SYNC = "sync"
