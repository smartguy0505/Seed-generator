import crypto from 'crypto';
import { getPublicKey } from '@noble/ed25519';
import bs58 from 'bs58';
import readline from 'readline';
import fs from 'fs';

// Function to get password with hidden input
function getPassword(prompt) {
  return new Promise((resolve) => {
    // Write prompt without newline
    process.stdout.write(prompt);

    // Store original stdin settings
    const wasRaw = process.stdin.isRaw;
    const wasPaused = process.stdin.isPaused();

    // Ensure stdin is not paused and set to raw mode
    if (wasPaused) {
      process.stdin.resume();
    }
    process.stdin.setRawMode(true);
    process.stdin.setEncoding('utf8');

    let password = '';
    let buffer = '';

    const onData = (data) => {
      buffer += data.toString();

      // Process buffer character by character
      while (buffer.length > 0) {
        const char = buffer[0];
        const code = char.charCodeAt(0);
        buffer = buffer.slice(1);

        // Handle Enter key
        if (char === '\r' || char === '\n') {
          cleanup();
          process.stdout.write('\n');
          resolve(password);
          return;
        }

        // Handle Ctrl+C
        if (code === 3) {
          cleanup();
          process.stdout.write('\n');
          process.exit(130);
          return;
        }

        // Handle backspace/delete
        if (code === 127 || code === 8) {
          if (password.length > 0) {
            password = password.slice(0, -1);
            // Move cursor back, write space, move cursor back again
            process.stdout.write('\b \b');
          }
          continue;
        }

        // Skip all other control characters
        if (code < 32) {
          continue;
        }

        // Skip escape sequences (ESC = 27)
        if (code === 27) {
          // Consume the rest of the escape sequence
          while (buffer.length > 0 && (buffer[0].charCodeAt(0) < 64 || buffer[0].charCodeAt(0) > 126)) {
            buffer = buffer.slice(1);
          }
          if (buffer.length > 0) {
            buffer = buffer.slice(1);
          }
          continue;
        }

        // Valid character - add to password and show asterisk
        password += char;
        process.stdout.write('*');
      }
    };

    const cleanup = () => {
      process.stdin.setRawMode(wasRaw);
      if (wasPaused) {
        process.stdin.pause();
      }
      process.stdin.removeListener('data', onData);
    };

    process.stdin.on('data', onData);
  });
}

// Function to get a number input (for cost parameter)
function getNumber(prompt) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });

    rl.question(prompt, (answer) => {
      rl.close();
      const num = parseInt(answer.trim(), 10);
      if (isNaN(num) || num <= 0) {
        console.error('\nError: Please enter a valid positive number');
        process.exit(1);
      }
      resolve(num);
    });
  });
}

// Function to hash password and generate Solana wallet using scrypt
async function generateWalletFromPassword(password, userSalt, applicationSalt, costParameter) {
  // Use scrypt - a memory-hard key derivation function
  // More secure than PBKDF2 because it requires significant memory, making GPU/ASIC attacks harder

  // Combine password, user salt, and application salt for multi-layer security
  // This ensures that even if password is known, both salts are still required
  // Attacker needs password AND userSalt AND applicationSalt AND costParameter to generate the wallet

  // Create a combined salt from user salt and application salt
  // This adds an extra layer - attacker needs password, userSalt, AND applicationSalt
  const combinedSalt = crypto.createHash('sha256')
    .update(userSalt + applicationSalt)
    .digest();

  // scrypt parameters:
  // - N: CPU/memory cost parameter (costParameter) - higher = more secure but slower
  //      Must be a power of 2 (e.g., 16384 = 2^14, 32768 = 2^15)
  // - r: block size parameter (8) - memory usage multiplier
  // - p: parallelization parameter (1) - number of parallel threads
  // These parameters make it computationally expensive and memory-intensive

  // Ensure N is a power of 2
  let N = 2 ** costParameter;

  const r = 8;     // block size
  const p = 1;     // parallelization

  // Key length: 32 bytes (256 bits) - required for Solana private keys (Ed25519 uses 32-byte seeds)
  const keyLength = 32;

  // Derive the private key using scrypt (same approach as EVM)
  // scrypt is memory-hard, making it resistant to GPU/ASIC brute-force attacks
  const derivedKey = crypto.scryptSync(
    password,
    combinedSalt,
    keyLength,
    { N, r, p }
  );

  // Solana uses Ed25519 curve
  // Generate public key from the private key seed using @noble/ed25519 v1.7.5
  // @noble/ed25519 handles the Ed25519 key derivation correctly
  // Convert Buffer to Uint8Array as required by @noble/ed25519
  // In v1.7.5, getPublicKey might be async, so we await it
  const derivedKeyUint8 = Uint8Array.from(derivedKey);
  const publicKeyBytes = await getPublicKey(derivedKeyUint8);
  const publicKey = bs58.encode(publicKeyBytes);

  // Solana private key format for Phantom wallet:
  // 64 bytes = 32-byte seed + 32-byte public key, encoded in Base58
  const privateKeyBytes = Buffer.concat([
    derivedKey,                    // 32-byte seed
    Buffer.from(publicKeyBytes)    // 32-byte public key
  ]);
  const privateKey = bs58.encode(privateKeyBytes); // Base58-encoded for Phantom

  return {
    privateKey,  // Base58-encoded 64-byte private key (Phantom format)
    publicKey,
    address: publicKey, // Solana address is the public key in base58
    actualN: N
  };
}

// Main function
async function main() {
  try {
    // Four-factor security: require password, userSalt, applicationSalt, and costParameter
    // Even if someone knows the password, they still need all other parameters
    const password = await getPassword('Enter password: ');
    const userSalt = await getPassword('Enter user salt/passphrase (remember this!): ');
    const applicationSalt = await getPassword('Enter application salt (remember this!): ');
    const costParameter = await getNumber('Enter cost parameter (N, e.g., 14, 15, 16 - higher = more secure but slower): ');

    if (!password || !userSalt || !applicationSalt) {
      console.error('\nError: Password, user salt, and application salt are all required');
      process.exit(1);
    }

    // Show progress message (scrypt takes a moment due to memory-hard computation)
    process.stdout.write('Generating secure Solana wallet (this may take a moment)...\n');

    // Generate wallet from password, user salt, application salt, and cost parameter
    const { privateKey, address, actualN } = await generateWalletFromPassword(password, userSalt, applicationSalt, costParameter);

    console.log('\nGenerated Solana Wallet:');
    console.log('Private Key:', privateKey.slice(0, 3) + '...' + privateKey.slice(-3));
    console.log('Address:', address);
    console.log('\nSecurity Features:');
    console.log('- Wallet generated using scrypt (memory-hard KDF)');
    console.log('- Four-factor: requires password, userSalt, applicationSalt, AND costParameter');
    console.log('- Same inputs = same wallet (deterministic)');
    console.log('- Different any input = different wallet');
    console.log(`- Cost parameter (N): 2^${costParameter} = ${actualN}`);
    console.log('\n⚠️  IMPORTANT: Remember all four inputs!');
    console.log('   You need password, userSalt, applicationSalt, AND costParameter to regenerate this wallet.');

    fs.writeFileSync('tmp-sol.log', privateKey);

  } catch (error) {
    console.error('\nError:', error.message);
    process.exit(1);
  } finally {
    // Ensure stdin is properly closed and process exits
    if (!process.stdin.isPaused()) {
      process.stdin.pause();
    }
    process.exit(0);
  }
}

main();

