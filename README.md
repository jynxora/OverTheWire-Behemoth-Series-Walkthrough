# OverTheWire — Behemoth Wargame (Levels 0 → 8)

This repository documents my full journey through the **Behemoth** wargame by OverTheWire.

Behemoth focuses on **real-world vulnerability classes** commonly seen in Linux binaries: unsafe string handling, memory corruption, race conditions, and privilege escalation mistakes. The goal of this repo is **understanding**, not speed.

Each level is documented in **two formats**:

* **PDF** — structured, printable, long-form explanation
* **Markdown (.md)** — readable, version-controlled, quick reference

Both versions cover *what was done*, *what was not done*, *what worked*, and *what failed*.

---

## Repository Structure

```
behemoth/
├── level-0/
│   ├── Behemoth_Level-0.pdf
│   └── Behemoth_Level-0.md
|   └── image(s)
├── level-1/
│   ├── Behemoth_Level-1.pdf
│   └── Behemoth_Level-1.md
|   └── image(s)
├── level-2/
│   └── ...
└── README.md
```

---

## Levels Index

| Level | Vulnerability Class         | Core Concept                                   | Write-ups |
| ----: | --------------------------- | ---------------------------------------------- | --------- |
|     0 | Hardcoded secrets           | Plaintext password comparison                  | PDF · MD  |
|     1 | Stack-based buffer overflow | exploitation under unstable stack & env layout | PDF · MD  |
|     2 | env variable exploitation   | Unsafe command execution via $PATH trust       | PDF · MD  |
|     3 | Format String Vulnerability | Byte-wise GOT overwrite via %n                 | PDF · MD  |
|     4 | TBD                         | To be documented                               | PDF · MD  |
|     5 | TBD                         | To be documented                               | PDF · MD  |
|     6 | TBD                         | To be documented                               | PDF · MD  |
|     7 | TBD                         | To be documented                               | PDF · MD  |
|     8 | TBD                         | To be documented                               | PDF · MD  |

*(Table updated as levels are completed)*

---

## Tooling Used Across the Series

* `ltrace` — runtime library call inspection
* `gdb` — stack, registers, and execution flow analysis
* `objdump` / disassembly reasoning
* Linux core utilities (`strings`, `env`, `ulimit`, etc.)

No exploit frameworks. Manual reasoning first.

---

## Why This Repository Exists

This is not a walkthrough dump.

This repository exists to:

* build intuition around unsafe coding patterns
* document reasoning, not just outcomes
* practice explaining low-level behavior clearly
* maintain a public, verifiable proof-of-work archive

If something failed, it is written down.
If something worked, *why* it worked is written down.

---

## References

* OverTheWire Behemoth: [https://github.com/jynxora/OverTheWire-Behemoth-Series-Walkthrough](https://github.com/jynxora/OverTheWire-Behemoth-Series-Walkthrough)
* Thanks to the OverTheWire team for maintaining these platforms.

If you find these write-ups useful, consider supporting them:
[https://overthewire.org/information/donate.html](https://overthewire.org/information/donate.html)

---

**Author:** Jinay Shah
**Series Status:** In Progress
**Method:** Slow, deliberate, documented
