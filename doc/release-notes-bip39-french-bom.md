French BIP39 wordlist
=====================

- The French BIP39 wordlist no longer includes a leading UTF-8 BOM on word
  index 0 (`abaisser`). Default builds match BIP-0039 / Trezor reference
  vectors.
- French mnemonics generated on older Particl versions which contain word
  index 0 derive different keys. They can be restored with the
  `legacy_french_bom` option of `extkeyimportmaster` /
  `extkeygenesisimport`, or the `legacy_french_bom` parameter of
  `mnemonic decode`. Existing wallets are unaffected. After restoring, move
  funds or re-backup with a standards-compliant mnemonic.
