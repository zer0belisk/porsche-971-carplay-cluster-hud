# PCM access helpers

- `pcm '<cmd>'` — run one command on the unit (root@PCM_IP, ssh-rsa host key).
- `expect pcmget.exp ~/.pcmpw <remote> <local>` — copy a file from the unit.
- `expect pcmput.exp ~/.pcmpw <local> <remote>` — copy a file to the unit.
- `slog_accumulator.sh` — bounded, deduplicating `sloginfo` collector (copy to /tmp, run in background).
- The password lives in `~/.pcmpw` (mode 600) and is never committed.
