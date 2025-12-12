# Fuscen - UDP-over-SCTP Tunnel

Encrypted tunneling with zero-copy, nonblocking algo, async I/O and crypto-acceleration

## 🚀 Features
- UDP over SCTP encrypted with AES-GCM
- Zero-copy optimization with Linux 4.14+
- Epoll/kqueue-based async I/O with fallback
- AES-NI acceleration with your CPU
- Batched packet processing as option
- Real-time traffic statistics
- Nonblocking algoritm

## 🛠️ Stack
- Language: Rust w/ minimal unsafe
- Networking: SCTP w/ Socket2 + Zero-Copy
- Crypto: AES-128/256-GCM with custom KDF
- Async: Custom epoll/kqueue
- Main target platform: Linux/BSD with Kernel optimizations