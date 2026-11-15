# maisecrets 0.9.12: time per document, rules alone and with NER

The point "time per document" of the benchmark chart. The samples and the scoring are those of the chart:
Benchmark V3, `val` 1 in 25 of Nemotron-PII, Mendeley and Gretel, and Privy 1 in 10, salt `v3/`.

- Host: the reference host (netcup, AMD EPYC 9645, 8 vCPU, Debian 13), alone under the host lock. The run waited
  for a quiet host: no CI build and a load average below 0.5 on three checks 20 s apart. It started at
  2026-11-15T17:45:55Z with a load of 0.17. During the run the load stayed at 1.26 or below, with no build container
  (`monitor.log`, one line every 10 s: time, load, build containers).
- One job at a time. Per sample, first the rules alone (scanner `maisecrets`), then the rules with the name service
  (scanner `maisecrets_remote`), in a checkout of the release commit of v0.9.12 (`aed99bd8`).
- Service: `mcpgate/ner:v2.0.3916@sha256:cde7bdb1d2dc753f41fbf6dd5179af56a570f62804bdc8d0da1021b83ae18a4b`, the pin of
  0.9.12, started with the limits of the plugin's container (`--cpus 4 --memory 1536m`) on 127.0.0.1:8766, with
  `BENCH_REMOTE_MASK=1` (the rules' findings go to the service as filler, as in the plugin).
- The times are each run's `timing` (median and p95 of the time per document).

| Sample | Rules, median | Rules, p95 | With NER, median | With NER, p95 |
|---|---:|---:|---:|---:|
| Nemotron val | 5.7 ms | 24.1 ms | 69.5 ms | 193.0 ms |
| Mendeley val | 3.6 ms | 29.0 ms | 59.9 ms | 238.2 ms |
| Gretel val | 7.5 ms | 14.0 ms | 110.7 ms | 147.5 ms |
| Privy | 1.3 ms | 3.8 ms | 31.2 ms | 86.8 ms |

The detection results of the same runs match `../2026-11-15-v3-0.9.12/` (the rules) and
`../2026-11-15-v3-0.9.12-ner/` (with the name service) on the same samples.
