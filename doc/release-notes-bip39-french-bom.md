French BIP39 wordlist
=====================

- The French BIP39 wordlist no longer includes a leading UTF-8 BOM on word
  index 0 (`abaisser`). Default builds match BIP-0039 / Trezor reference
  vectors.
- Wallets whose French mnemonics were generated on older Particl versions
  and used word index 0 can be recovered by rebuilding with
  `--enable-bip39-french-legacy-bom` (recovery only; do not use for new
  wallets). After restoring, move funds or re-backup with a standards-
  compliant mnemonic.
