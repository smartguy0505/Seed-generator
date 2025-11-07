# Ethereum Wallet Seed Generator

A secure, deterministic Ethereum wallet generator that creates private keys from user-provided passwords and salts using the scrypt key derivation function.

## Overview

This tool generates Ethereum wallet private keys deterministically from multiple user inputs (password, user salt, application salt, and cost parameter). The same inputs will always produce the same wallet, making it possible to regenerate your wallet without storing the private key.

## Features

- 🔐 **Four-Factor Security**: Requires password, user salt, application salt, and cost parameter
- 🛡️ **Memory-Hard KDF**: Uses scrypt for resistance against GPU/ASIC brute-force attacks
- 🔄 **Deterministic**: Same inputs always generate the same wallet
- 🔒 **Hidden Input**: Password and salt inputs are hidden (displayed as asterisks)
- ⚡ **Configurable Security**: Adjustable cost parameter for security vs. performance trade-off

## Installation

### Prerequisites

- Node.js (v14 or higher)
- npm or yarn

### Setup

1. Clone or download this repository
2. Install dependencies:

```bash
npm install
```

## Usage

Run the generator:

```bash
npm start
```

Or directly:

```bash
node generator.js
```

### Input Prompts

The script will prompt you for four inputs:

1. **Password**: Your main password (hidden input)
2. **User Salt/Passphrase**: A second passphrase you must remember (hidden input)
3. **Application Salt**: A third passphrase for additional security (hidden input)
4. **Cost Parameter (N)**: The exponent for the scrypt cost parameter (e.g., 14, 15, 16)

### Example

```
Enter password: ********
Enter user salt/passphrase (remember this!): ********
Enter application salt (remember this!): ********
Enter cost parameter (N, e.g., 14, 15, 16 - higher = more secure but slower): 14

Generating secure wallet (this may take a moment)...

Generated Wallet:
Private Key: 0x23...d9
Address: 0xa905A46F8921f6ec7aD02d0cdcA23928E33a783E

Security Features:
- Wallet generated using scrypt (memory-hard KDF)
- Four-factor: requires password, userSalt, applicationSalt, AND costParameter
- Same inputs = same wallet (deterministic)
- Different any input = different wallet
- Cost parameter (N): 2^14 = 16384

⚠️  IMPORTANT: Remember all four inputs!
   You need password, userSalt, applicationSalt, AND costParameter to regenerate this wallet.
```

## How It Works

### Key Derivation Process

1. **Input Collection**: Collects password, user salt, application salt, and cost parameter
2. **Salt Combination**: Combines user salt and application salt using SHA-256
3. **scrypt Derivation**: Uses scrypt with the following parameters:
   - **N**: 2^costParameter (CPU/memory cost - e.g., 2^14 = 16384)
   - **r**: 8 (block size parameter)
   - **p**: 1 (parallelization parameter)
4. **Private Key Generation**: Derives a 32-byte (256-bit) private key
5. **Wallet Creation**: Creates an Ethereum wallet from the private key

### Security Architecture

- **scrypt**: Memory-hard key derivation function that requires significant RAM, making parallel brute-force attacks expensive
- **Multi-Layer Salting**: Combines user-provided salts for additional security
- **Deterministic**: Same inputs produce the same wallet, but all four inputs are required

## Cost Parameter Guidelines

The cost parameter (N) controls the computational cost of key derivation:

| Exponent | N Value | Security Level | Generation Time | Use Case |
|----------|---------|----------------|-----------------|----------|
| 12 | 4,096 | Low | Fast (< 1s) | Testing |
| 14 | 16,384 | Medium | Moderate (1-3s) | **Recommended** |
| 15 | 32,768 | High | Slow (3-10s) | High security |
| 16 | 65,536 | Very High | Very Slow (10-30s) | Maximum security |

**Recommendation**: Start with 14 for a good balance between security and performance.

## Security Considerations

### ⚠️ Important Warnings

1. **Remember All Inputs**: You must remember all four inputs (password, user salt, application salt, and cost parameter) to regenerate your wallet. If you lose any of them, you cannot recover your wallet.

2. **Strong Passwords**: Use strong, unique passwords and salts. Weak inputs can be brute-forced even with scrypt.

3. **Private Key Storage**: The private key is written to `tmp.log` for convenience. **Delete this file immediately** after use and never commit it to version control.

4. **No Recovery**: There is no password recovery mechanism. If you forget your inputs, the wallet cannot be recovered.

5. **Deterministic Nature**: While deterministic generation is useful, it means anyone with all four inputs can generate your wallet. Keep all inputs secure.

### Best Practices

- Use a password manager to store your inputs securely
- Use different salts for different wallets
- Test wallet regeneration before funding it
- Never share your inputs with anyone
- Delete `tmp.log` immediately after use
- Consider using a hardware wallet for large amounts

## Technical Details

### Dependencies

- **ethers**: Ethereum library for wallet creation and management
- **crypto**: Node.js built-in module for cryptographic functions (scrypt, SHA-256)

### Algorithm

- **Key Derivation**: scrypt (RFC 7914)
- **Hash Function**: SHA-256 (for salt combination)
- **Key Length**: 256 bits (32 bytes)
- **Wallet Format**: Ethereum-compatible (EIP-55 address format)

## Troubleshooting

### Process Doesn't Exit

If the process hangs, press `Ctrl+C` to exit. The script should handle cleanup automatically.

### Input Not Showing

If prompts don't appear, ensure your terminal supports readline and raw mode input.

### Wrong Wallet Generated

Double-check that you're using the exact same inputs (including the cost parameter). Even a single character difference will generate a different wallet.

## License

MIT

## Disclaimer

This software is provided "as is" without warranty. Use at your own risk. Always test with small amounts before using for significant funds. The authors are not responsible for any loss of funds or data.

## Contributing

Contributions are welcome! Please ensure any changes maintain the security and deterministic nature of the wallet generation.

