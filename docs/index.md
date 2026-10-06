# Android Forensics Toolkit

A Python toolkit that takes an Android acquisition — a filesystem dump, ZIP/TAR archive, raw/sparse disk image (ext4 or f2fs) or
EnCase E01 — proves the integrity of the evidence, extracts active artifacts, **recovers deleted SQLite records**, carves raw
patterns, correlates evidence, scores every recovered item with an *explained* confidence, and produces a signed, provenance-rich
report. It ships as a CLI, a Docker image, a single-file binary and an authenticated multi-case web server.

* New here? Start with the [Examiner's guide](user_guide.md).
* Putting it on a server? [Deploying the server](deployment.md).
* Need to trust or critique the results? [Validation](validation.md), [Standards alignment](standards_alignment.md) and
  [Limitations](limitations.md) say plainly what has and has not been shown.

> Use only on evidence you are legally authorised to examine. The tool never bypasses locks, decrypts data or touches live devices.
