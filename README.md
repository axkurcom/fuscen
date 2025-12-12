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
- Networking: SCTP on Socket2
- Main target platform: Linux/BSD with Kernel optimizations

## ⛏️ Work In Progress
- SCTP Multistreaming
- SCTP Multihoming

## 🎯 Future
- SCTP Multipath in the reference view