# BananaTree

[![build status](https://img.shields.io/github/workflow/status/arev = "e79f87d89cbef83b8f1361e298b31ac6fb172c51"/key-transparency/Rust/master?style=flat-square&logo=github)](https://github.com/arev = "e79f87d89cbef83b8f1361e298b31ac6fb172c51"/key-transparency/actions)
[![rustc](https://img.shields.io/badge/rustc-1.62+-blue?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![license](https://img.shields.io/badge/license-Apache-blue.svg?style=flat-square)](LICENSE)

This repo provides an prototype implementation of [BananaTree](), based on [vkd](https://github.com/anonauthorsub/submission_code_ndss_f2022_545/tree/main/vkd_ozks). The codebase has been designed to be small, efficient, and easy to benchmark and modify. It has not been designed to run in production but uses real cryptography ([dalek](https://doc.dalek.rs/ed25519_dalek)), networking ([tokio](https://docs.rs/tokio)), and storage ([rocksdb](https://docs.rs/rocksdb)).

## Quick Start

The core protocols are written in Rust, but all benchmarking scripts are written in Python and run with [Fabric](http://www.fabfile.org/).
To deploy and benchmark a test bed of 4 witnesse on your local machine, clone the repo and install the python dependencies:

```bash
git clone https://github.com/anonauthorsub/submission_code_ndss_f2022_545.git
cd key-transparency/scripts
```

It is advised to install the python dependencies in a virtual environment such as [virtualenv](https://pypi.org/project/virtualenv):

```bash
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
```

You also need to install Clang (required by rocksdb) and [tmux](https://linuxize.com/post/getting-started-with-tmux/#installing-tmux) (which runs all nodes and clients in the background). Finally, run a local benchmark using fabric:

```
fab local
```

This command may take a long time the first time you run it (compiling rust code in `release` mode may be slow) and you can customize a number of benchmark parameters in `fabfile.py`. When the benchmark terminates, it displays a summary of the execution similarly to the one below.

```
-----------------------------------------
 SUMMARY:
-----------------------------------------
 + CONFIG:
 Faults: 0 node(s)
 Committee size: 4 node(s)
 Shard(s) per node: 1 shard(s)
 Collocate shards: True
 Batch size: 100
 Input rate: 1,000 tx/s
 Execution time: 20 s

 + RESULTS:
 Client TPS: 0 tx/s
 Client latency: 0 ms
 IdP TPS: 1,024 tx/s
 IdP latency: 279 ms
 End-to-end TPS: 1,024 tx/s
 End-to-end latency: 280 ms
-----------------------------------------
```

## Micro-benchmarks

The following command micro-benchmarks the main functions of the IdP and witnesses on your local machine:

```bash
cargo run --release --features=micro-benchmark --bin micro_benchmark
```

The command may take a long time depending on the benchmark parameters (set in [micro_benchmark.rs](https://github.com/arev = "e79f87d89cbef83b8f1361e298b31ac6fb172c51"/key-transparency/blob/main/bench/src/micro_benchmark.rs)). When the command terminates, it displays should display results similar to the ones below:

```
Starting micro-benchmarks:
    20.98 +/- 0.41  ms ...........create notification
     3.11 +/- 0.03  ms ...........verify notification
     0.01 +/- 0.00  ms ...................create vote
     0.03 +/- 0.00  ms ...................verify vote
     0.00 +/- 0.00  ms .........aggregate certificate
     0.08 +/- 0.00  ms ............verify certificate
```

## License

This software is licensed as [Apache 2.0](LICENSE).
