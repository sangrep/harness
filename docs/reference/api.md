# Library API

The root exports the tested convenience API, immutable text snapshots, reference
providers, limits and same-process repositories. Functions receive caller-owned
values; only `snapshot_file_v1` opens a caller-selected file. Review output remains
a proposal and does not write evidence.

::: sangrep_harness
    options:
      members: true
      show_root_heading: false
