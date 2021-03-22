# memflow-system-proxy

## Syscall based proxy-OS for memflow

This is a OS layer that allows to run memflow code on the native system. Theoretically, any code that works here should work on DMA hardware.

The key difference between DMA and this, is that DMA will reach missing (paged out) virtual memory pages, which could result in difference of outcomes.
