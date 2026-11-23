# checks/ — engine checks

Standalone scripts, run from `dev/` (`python3 checks/<name>.py`). Standard library plus
`cryptography`, like `selftest.py`. The fast ones run inside `selftest.py`.

| Script | What it proves | In selftest |
|---|---|---|
| `check_stream_equivalence.py` | `_rand_bytes`, `text_blob` and `csum` give the same bytes and leave the random stream where the plain originals did (a different draw count would move the 466,343 pin) | yes |
| `check_ip_options.py` | default `ipv4()` / `handshake()` bytes equal the engine at an earlier commit (the check is skipped when that history is not available, as in a shallow or fresh clone) for the Windows and macOS layouts; a Linux or embedded host now sends the kernel's own option layout by default, so that case is checked to differ; IP options give a valid IHL, length and checksum; the opt-in Linux SYN-ACK layout is exact. Skips when that commit is not in the clone | yes |
| `scenario_proof.py` | the proof harness: builds a scenario, slices its traffic out of the capture and runs tshark count/distinct checks from a `PROOF.json`; `--selftest` checks the harness itself. Worked examples in `proofs/` (`ir-ipopt-tcp-uaf`, `ip-options-engine`) — they need tshark and a full-scale build, so run them by hand | `--selftest` only |
| `check_png.py` | every `image/png` body the engine sends is a real PNG (signature, chunk CRCs, IEND) across the whole size class | yes |
| `check_isolated_rng.py` | the `npm-web-degradation` pool helpers save and restore every random generator, even with `secrets` imported | yes |
| `check_ransom.py` | `ndr-ransomware-encryption` SMB2: FILE_OPEN with DELETE, block-for-block rewrite, rename on the same handle, the note in its own session. About 30 seconds | no (run by hand) |
| `check_capwap.py` | `npm-wireless-degradation` on the stateful DTLS CAPWAP plane: IPv4/UDP/CAPWAP/DTLS framing, Echo retransmits, rejoin waits, every DHCP exchange of the storm answered. About 30 seconds | no (run by hand) |
| `check_custom_nets.py` | with custom user/server/OT subnets the capture keeps every internal packet on them and the run summary labels each network correctly. A few minutes | no (run by hand) |
| `check_company_identity.py` | every scenario added in the engine update builds under `--company Acme` with custom networks and leaves no default-company name in the capture, key log or certificates, and emits its own traffic. About two minutes | no (run by hand) |
