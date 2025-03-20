# BIP-39 Tool

#### This Rust-based command-line utility facilitates deterministic key management by implementing BIP-39 mnemonic generation, BIP-32 hierarchical key derivation, and SSKR-based seed redundancy. It provides direct entropy manipulation, mnemonic-to-seed transformation, and cryptographic key derivation for Bitcoin and Ethereum, with an interactive TUI for streamlined input handling and data visualization.
---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
  - [Custom Mnemonic Generation](#custom-mnemonic-generation)
  - [Final Word Computation](#final-word-computation)
  - [Multi-language Support](#multi-language-support)
  - [SSKR (Sharded Secret Key Recovery)](#sskr-sharded-secret-key-recovery)
  - [Wallet Address Derivation](#wallet-address-derivation)
  - [Backup & Encryption](#backup--encryption)
  - [Cryptographic Security & Validation](#cryptographic-security--validation)

---

## Overview

This tool is designed to offer cryptocurrency users a robust way to:
- **Generate** new BIP-39 seed phrases.
- **Customize** the mnemonic generation process by manually choosing words for the majority of the seed.
- **Automatically compute** the final (24th) word based on the remaining entropy and checksum.
- **Recover** a lost seed by combining SSKR shares.
- **Derive wallet addresses** from a provided BIP-32 Extended Private Key (xprv) for Bitcoin (Native SegWit P2WPKH) and Ethereum.
- **Encrypt and backup** sensitive seed data into a JSON file using AES-256 GCM with robust key derivation via Argon2.

---

## Key Features

### Custom Mnemonic Generation

- **Manual Input for Positions 1-23:**  
  Users can input one or more words for positions 1 through 23 of the seed phrase. If no word is provided at a given position, the tool automatically selects a random, unused word from the BIP-39 wordlist.
  
- **Dynamic Word Selection:**  
  The system ensures that duplicate words are not used, enforcing uniqueness in the manually specified words.

### Final Word Computation

- **Automatic Checksum & Entropy Calculation:**  
  After collecting 23 words (either via manual input or random selection), the tool computes the final (24th) word. This is done by:
  - Converting the selected word indices into a bit vector.
  - Appending candidate bits and then computing the checksum using SHA-256.
  - Presenting multiple candidate words (derived from the remaining entropy bits and checksum) from which the user selects the final word.

### Multi-language Support

- **BIP-39 Wordlists:**  
  Although the current implementation always returns the English wordlist, the design supports multiple languages. The supported languages include:
  - English
  - Simplified Chinese
  - Traditional Chinese
  - Japanese
  - Korean
  - Spanish
  - French
  - Italian
  - Czech
  - Portuguese
  
  This feature allows users to generate and validate seed phrases according to their language preference.

### SSKR (Sharded Secret Key Recovery)

- **Share Generation:**  
  Users have the option to create a backup of their mnemonic entropy using SSKR. This process splits the secret into multiple shares:
  - Users specify the number of groups, total shares per group, and the minimum required shares for recovery.
  - Each share is converted into both a hexadecimal representation and a mnemonic form.
  
- **Share Recovery:**  
  The tool supports recovering a lost seed by accepting SSKR shares. It automatically detects whether an input is in hexadecimal or mnemonic form and validates each share before combining them to reconstruct the original secret.

### Wallet Address Derivation

- **Extended Private Key (xprv) Based Derivation:**  
  The application allows users to input a BIP-32 Extended Private Key (xprv) and derive child addresses.
  
- **Address Types & Derivation Paths:**
  - **Bitcoin Addresses:**  
    Uses Native SegWit P2WPKH addresses derived via the path `m/84'/0'/0'/0/i` (with an option for fully hardened derivation on the final index).
  - **Ethereum Addresses:**  
    Derives Ethereum/EVM addresses using the path `m/44'/60'/0'/0/i` (also offering the hardened index option).
  - **Solana Addresses:**  
    Derives Solana addresses using the path `m/44'/501'/0'/0/i` (with hardened indexes for key derivation).
  
- **Address Table UI:**  
  Derived addresses, along with their public and private keys, are displayed in an interactive table where sensitive values can be toggled (masked/unmasked) using keyboard shortcuts.

### Backup & Encryption

- **Secure JSON Backup:**  
  The tool can encrypt the seed backup information (which includes the seed phrase, entropy, BIP-39 seed, BIP-32 root key, and SSKR backup details) into a JSON file.
  
- **AES-256 GCM Encryption with Argon2 Key Derivation:**  
  Backup files are encrypted using AES-256 GCM. The encryption key is derived from the user-provided password using Argon2id, a modern and memory-hard key derivation function that protects against brute-force attacks by using a configurable amount of computational effort, salt, and nonce.

### Cryptographic Security & Validation

- **Secure Randomness:**  
  Uses the system’s OS random number generator (via the `rand` crate) to ensure high-quality randomness in operations such as selecting random mnemonic words and generating salts/nonces for encryption.
  
- **SHA-256 & Keccak-256:**  
  - SHA-256 is used to compute checksums for the final mnemonic word and for verifying integrity during seed backup.
  - Keccak-256 (via the `tiny_keccak` crate) is used for Ethereum address generation and checksum validation.
  
- **Mnemonic Validation:**  
  The tool validates the generated mnemonic phrase using the `bip39` crate. It also displays the derived entropy and seeds in hexadecimal format, ensuring that the mnemonic conforms to BIP-39 standards.
