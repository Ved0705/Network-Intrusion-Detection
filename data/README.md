# Dataset folder

Put the NSL-KDD files here, with exactly these names:

```
data/
  KDDTrain+.txt   (125,973 records)
  KDDTest+.txt    ( 22,544 records)
```

This copy of the project already includes both files, taken from the public NSL-KDD mirror at
https://github.com/defcom17/NSL_KDD. The original dataset is published by the Canadian Institute for
Cybersecurity (https://www.unb.ca/cic/datasets/nsl.html).

## Format

- Comma-separated, **no header row**.
- 41 traffic features, then `label`, then `difficulty_level` (43 columns). Files with 42 columns
  (no difficulty) are accepted and difficulty analysis is switched off.
- The loader applies the standard NSL-KDD column names; it never treats the first record as a header.

## Notes

- NSL-KDD has **no IP addresses and no timestamps**. This project does not invent them.
- If a file is missing the scripts stop with a clear message; sample data is never substituted.

- The original files are never modified; cleaning happens in memory.
