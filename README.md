# Alvara trait-memory generator

This repository compiles the ordered Alvara collection settings into two deterministic artifacts:

- `memory.json`, containing the packed 256-bit words, bit layout, and provenance hashes;
- `AlvaraTraitData.sol`, a Solidity 0.8.38 library containing the same words and
  derived offsets. Consumers can load one word with `word(index)` or copy the
  complete table with `words()`.

The integration source of truth is `../alvara-backend/settings.json`. The generator does not invent or reorder categories, attributes, options, included combinations, exclusions, names, or image-layer records.

## Requirements

- Python 3.11 or newer
- no runtime packages outside the Python standard library

## Generate the checked-in artifacts

Run from this repository:

```sh
python3 main.py \
  --settings ../alvara-backend/settings.json \
  --memory-out generated/memory.json \
  --solidity-out generated/AlvaraTraitData.sol
```

All three paths are required. Outputs are fully rendered and staged before either destination is
replaced. A normal write failure rolls both destinations back to their prior contents. The two files
cannot be swapped as one filesystem transaction, so an abrupt process or power loss between the two
renames can still leave a mixed pair; consumers must verify the embedded hashes before publication.
Repeating the command with byte-identical settings produces byte-identical files.

## Schema and ordering

The backend settings remain unchanged. The fields consumed by this compiler are:

- `categories`: an ordered, non-empty list;
- each category: `name`, `size`, seven ordered `attributes`, `ignored`, and `included`;
- each attribute: `name` and an ordered, non-empty `options` list;
- each option: a unique `name` plus non-empty `pics` records containing `path` and integer `z`;
- each ignored rule: `[attributeIndexA, optionIndexA, attributeIndexB, optionIndexB]`, using zero-based indexes and matching both constraints;
- each included vector: seven zero-based option indexes in attribute order.

Category, attribute, and option order is part of the token-data ABI. Changing it changes how an existing numeric DNA value renders. The compiler therefore hashes the complete canonical `categories` value as `categories_sha256`.

The layout retains the historical five-bit option fields and seven attributes. Unlike the 2022 generator, each ignored option is now also encoded with five bits. Every ignore record is exactly 70 bits: a 35-bit option vector followed by a 35-bit position mask.

Validation rejects malformed records, duplicate categories/options/rules/vectors, conflicting included and ignored combinations, out-of-range indexes, empty options, field-width overflow, impossible collection sizes, and a configuration that requests more unique normal combinations than its legal trait space provides.

The compiler also proves that the contract cursor step is coprime to every normal and included
combination space, exhaustively measures the longest rejection run for the fixed settings, and rejects
settings that could exceed the contract's 128-attempt trait-search bound.

## Reproducibility fields

`generated/memory.json` includes:

- `schema_version`;
- `categories_sha256`, over canonical UTF-8 JSON with object keys sorted and array order retained;
- `bit_length`, before 256-bit word padding;
- `words_sha256`, over the concatenated 32-byte big-endian words;
- derived table offsets and widths in `register`;
- `words`, plus legacy aliases `hex` and `bin` for compatibility.

The Solidity library exposes the same hashes, counts, entry widths, and table offsets. Its `words()` function returns a newly allocated array so importing contracts cannot mutate shared state.

## Tests

The test suite uses `unittest` and also runs under pytest:

```sh
python3 -m unittest discover -s tests -v
```

When the sibling backend checkout is present, the suite recompiles its real settings and verifies that both checked-in generated artifacts are exact golden outputs.

## Integration warning

Correcting ignored records changes the packed words beginning at the ignored table and moves the included table from legacy bit offset 2455 to 2525. A consuming contract must update its words and derived offsets together. Do not copy only one generated artifact into the historical contract, and do not treat these local artifacts as deployment approval.
