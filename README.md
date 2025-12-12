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
- IO Uring
- SCTP Multistreaming
- SCTP Multihoming

## 🎯 Future
- SCTP Multipath in the reference view
- FEC for super-lossy/error links
- <1 ms latency-overhead
- XDP/eBPF hooks

## ⚡ Benchmarks
1) 100 Mbps w/ IPerf3 + TCP Mode @ lossy link from DC K12 in Saint Petersburg to DC M9 in Moscow @ 1 CPU VM in Proxmox w/ Redhat IO Drivers and SR-IOV NIC on both ends