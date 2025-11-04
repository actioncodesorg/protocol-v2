**@actioncodes/protocol**

***

## Action Codes Protocol

The Action Codes Protocol is a lightweight way to prove intent and authorize actions across blockchains, apps, and wallets.
Instead of heavy signature popups or complex flows, it uses short-lived one-time codes derived from canonical cryptographic messages.

### This enables:
- Secure intent binding – the code is cryptographically tied to a wallet/public key.
- Fast verification – relayers/servers can validate in microseconds (~3ms per verification).
- Cross-chain support – adapters handle chain-specific quirks (currently supporting Solana)
- Simple dev UX – just generate → sign → verify.
- Issuer support – allows separation between code issuer and intent owner for advanced use cases.

### What's new in v2 (compared to [v1](https://github.com/otaprotocol/actioncodes))
- Now we use Bun as core library. We are down to ~3ms per code signature verification on commodity hardware.
- Canonical Messages only → No ambiguity. Codes are always derived from a canonical serialization (serializeCanonical).
- No AIPs (Action Codes Improvement Proposals) → Overkill for lightweight protocol.
- Chain Adapters simplified → They don't enforce business rules; they just provide utilities:
  - createProtocolMetaIx (for attaching metadata)
  - parseMeta / verifyTransactionMatchesCode (for checking integrity)
  - verifyTransactionSignedByIntentOwner (checks both `int` and `iss` signatures when present).
- Errors are typed → Clear ProtocolError.* categories instead of generic fails.

### Core Concepts

1. Action Codes
   - A short-lived, one-time code bound to a wallet/public key.
   - Generated using HMAC/HKDF and canonical serialization.

2. Protocol Meta
   - The "payload" carried with transactions to tie them to action codes.
   - Versioned, deterministic, size-limited (max 512 bytes).
   - Fields: `ver` (version), `id` (code hash), `int` (intent owner), `iss` (issuer, optional), `p` (params, optional).
   - When `iss` field is present, both issuer and intent owner must sign the transaction.
   - Perfect for attaching to transactions or off-chain messages for tracing.

3. Canonical Message
   - A deterministic JSON serialization of (pubkey, code, timestamp, optional secret)
   - Always signed by the user's wallet.
   - Prevents replay / tampering.

## Strategy Architecture

The Action Codes Protocol supports two main strategies for generating and validating codes:

### 1. Wallet Strategy (Direct)

The **Wallet Strategy** is the simplest approach where codes are generated directly from a user's wallet.

#### How it works:
```typescript
import { ActionCodesProtocol } from '@actioncodes/protocol';
import { SolanaAdapter } from '@actioncodes/protocol';

// Initialize protocol
const protocol = new ActionCodesProtocol({
  codeLength: 8,      // Code length (6-24 digits)
  ttlMs: 120000,      // Time to live (2 minutes)
  clockSkewMs: 5000   // Clock skew tolerance (5 seconds)
});

// Register Solana adapter
protocol.registerAdapter('solana', new SolanaAdapter());

// 1. Generate code with wallet strategy
const signFn = async (message: Uint8Array, chain: string) => {
  // Sign the canonical message with user's wallet
  const signature = await userWallet.signMessage(message);
  return signature; // Returns base58-encoded signature
};

const actionCode = await protocol.generate(
  "wallet",
  userWallet.publicKey.toString(),
  "solana",
  signFn
);

// 2. Validate code
protocol.validate("wallet", actionCode);
// Throws ProtocolError if validation fails
```

#### Key Features:
- **Signature-based security** - Codes require a valid signature over the canonical message (prevents public key + timestamp attacks)
- **Direct wallet binding** - Codes are cryptographically tied to the user's public key
- **HMAC-based generation** - Uses signature as entropy source for secure code generation
- **Immediate validation** - No delegation certificates needed
- **Perfect for** - Direct user interactions, simple authentication flows, transaction authorization

#### Security Model:
- **Signature verification** - All codes require a valid signature over the canonical message
- **Public key + timestamp attack prevention** - Signatures prevent attackers from generating codes with just public key + timestamp
- **HMAC-based entropy** - Codes use HMAC-SHA256 with signature as key, ensuring cryptographic security
- Codes are bound to the specific public key and timestamp
- Time-based expiration prevents replay attacks
- Canonical message signing ensures integrity

### 2. Delegation Strategy (Advanced)

The **Delegation Strategy** allows users to pre-authorize actions through delegation proofs, enabling more complex workflows like relayer services.

#### How it works:

##### Step 1: Create Delegation Proof
```typescript
import { serializeDelegationProof } from '@actioncodes/protocol';

// User creates a delegation proof
const delegationProof = {
  walletPubkey: userWallet.publicKey.toString(),
  delegatedPubkey: delegatedKeypair.publicKey.toString(),
  chain: "solana",
  expiresAt: Date.now() + 3600000, // 1 hour expiration
  signature: "" // Will be set after signing
};

// User signs the delegation proof
const delegationMessage = serializeDelegationProof(delegationProof);
const delegationSignature = await userWallet.signMessage(delegationMessage);
delegationProof.signature = delegationSignature;
```

##### Step 2: Generate Delegated Codes
```typescript
// Sign function for delegated keypair
const delegatedSignFn = async (message: Uint8Array, chain: string) => {
  const signature = await delegatedKeypair.signMessage(message);
  return signature;
};

// Generate code using delegation strategy
const delegatedActionCode = await protocol.generate(
  "delegation",
  delegationProof,
  "solana",
  delegatedSignFn
);
```

##### Step 3: Validate Delegated Codes
```typescript
// Validate the delegated code
protocol.validate("delegation", delegatedActionCode);
// Throws ProtocolError if validation fails
```

#### Key Features:
- **Pre-authorization** - Users can authorize actions for a limited time
- **Relayer support** - Third parties can validate codes without generating them
- **Proof-based** - Codes are bound to specific delegation proofs
- **Time-limited** - Delegation proofs have expiration times
- **Perfect for** - Relayer services, automated systems, complex workflows

#### Security Model:
- **Code-Proof Binding** - Codes are cryptographically bound to their specific delegation proof
- **Signature Verification** - Delegation proof signatures are verified using chain adapters
- **Dual Signature Requirement** - Both wallet signature (on proof) and delegated signature (on code) are required
- **Cross-Proof Protection** - Codes from one delegation proof cannot be used with another
- **Relayer Security** - Relayers can validate codes but cannot generate them without the delegated keypair's signature

#### Important Security Guarantees:

1. **Stolen Delegation Proofs are Limited**
   - Delegation proofs contain public data (pubkeys, expiration, chain)
   - They cannot be used to generate codes without the delegated keypair's private key
   - The proof signature prevents tampering but doesn't enable code generation

2. **Stolen Signatures Cannot Create Valid Codes**
   - Even if an attacker steals a signature, they cannot create valid codes
   - Codes are bound to the ENTIRE delegation proof (not just the signature)
   - Different proof data = different code = validation failure

3. **Relayer Code Generation Prevention**
   - Relayers cannot generate codes even with public delegation proof data
   - Codes require signatures from the delegated keypair (private asset)
   - Only holders of the delegated keypair can generate valid codes

4. **Code-Proof Binding**
   - Codes are cryptographically linked to their specific delegation proof
   - Cross-proof attacks are impossible
   - Each delegation proof produces unique codes

#### Delegation Proof Structure:
```typescript
interface DelegationProof {
  walletPubkey: string;      // Original wallet's public key
  delegatedPubkey: string;    // Delegated keypair's public key
  chain: string;             // Target blockchain
  expiresAt: number;         // Expiration timestamp
  signature: string;         // Wallet's signature of the delegation proof
}
```

#### Delegated Action Code Structure:
```typescript
interface DelegatedActionCode {
  code: string;              // The actual action code
  pubkey: string;            // Delegated pubkey (who signs the code)
  timestamp: number;         // Generation timestamp
  expiresAt: number;         // Code expiration
  signature: string;         // Signature from delegated keypair
  chain: string;            // Target blockchain
  delegationProof: DelegationProof; // The delegation proof
}
```

## Use Cases & Examples

### Wallet Strategy Use Cases

#### 1. Simple Authentication
```typescript
// User logs into a dApp
const signFn = async (message: Uint8Array, chain: string) => {
  return await userWallet.signMessage(message);
};

const actionCode = await protocol.generate(
  "wallet",
  userWallet.publicKey.toString(),
  "solana",
  signFn
);

// dApp validates the code
protocol.validate("wallet", actionCode);
```

#### 2. Transaction Authorization
```typescript
import { buildProtocolMeta, codeHash } from '@actioncodes/protocol';

// User authorizes a specific transaction
const signFn = async (message: Uint8Array, chain: string) => {
  return await userWallet.signMessage(message);
};

const actionCode = await protocol.generate(
  "wallet",
  userWallet.publicKey.toString(),
  "solana",
  signFn
);

// Relayer validates before executing
protocol.validate("wallet", actionCode);

// Attach protocol meta to transaction
const adapter = protocol.getAdapter("solana") as SolanaAdapter;
const meta = buildProtocolMeta({
  ver: 2,
  id: codeHash(actionCode.code),
  int: actionCode.pubkey,
});
const txWithMeta = SolanaAdapter.attachProtocolMeta(transactionBase64, meta);

// Verify transaction is signed by the intended owner
adapter.verifyTransactionSignedByIntentOwner(txWithMeta);
```

### Delegation Strategy Use Cases

#### 1. Relayer Services
```typescript
// User creates delegation proof for relayer
const delegationProof = {
  walletPubkey: userWallet.publicKey.toString(),
  delegatedPubkey: relayerKeypair.publicKey.toString(),
  chain: "solana",
  expiresAt: Date.now() + 3600000, // 1 hour
  signature: await signDelegationProof(delegationProof)
};

// Relayer can validate codes but not generate them
// User generates codes that relayer can validate
const delegatedSignFn = async (message: Uint8Array, chain: string) => {
  return await relayerKeypair.signMessage(message);
};

const actionCode = await protocol.generate(
  "delegation",
  delegationProof,
  "solana",
  delegatedSignFn
);

// Relayer validates the code
protocol.validate("delegation", actionCode);
```

#### 2. Automated Trading Bots
```typescript
// User authorizes trading bot for 24 hours
const delegationProof = {
  walletPubkey: userWallet.publicKey.toString(),
  delegatedPubkey: botKeypair.publicKey.toString(),
  chain: "solana",
  expiresAt: Date.now() + 86400000, // 24 hours
  signature: await signDelegationProof(delegationProof)
};

// Bot generates codes using delegated keypair
const botSignFn = async (message: Uint8Array, chain: string) => {
  return await botKeypair.signMessage(message);
};

const tradeCode = await protocol.generate(
  "delegation",
  delegationProof,
  "solana",
  botSignFn
);
// Bot executes trade with this code
```

## Security Considerations

### What Makes Action Codes Secure?

1. **Cryptographic Binding**
   - Codes are mathematically tied to specific public keys
   - Impossible to forge without the private key

2. **Time-Limited Validity**
   - Codes expire automatically
   - Prevents replay attacks

3. **One-Time Use**
   - Each code is unique and time-bound
   - Cannot be reused

4. **Delegation Security**
   - Delegation proofs are cryptographically signed
   - Codes are bound to specific delegation proofs
   - Cross-proof attacks are impossible

### Best Practices

1. **Delegation Proof Expiration**
   - Set appropriate expiration times for delegation proofs
   - Shorter expiration = higher security
   - Longer expiration = better UX

2. **Relayer Security**
   - Only trust relayers with valid delegation proofs
   - Never share private keys with relayers
   - Monitor relayer behavior

3. **Issuer Field Usage**
   - Use `iss` field when issuer and intent owner are different entities
   - Ensure both signatures are present when `iss` is specified
   - Omit `iss` when it's the same as `int` to save space

4. **Code Validation**
   - Always validate codes server-side
   - Check expiration times
   - Verify the binding to the correct public key

5. **Protocol Meta with Issuer**
   - Use `iss` field when issuer differs from intent owner
   - When `iss` is present, ensure transaction is signed by both
   - If `iss` equals `int`, it's automatically omitted (optimization)

## Performance

- **Code Generation**: ~1ms per code
- **Code Validation**: ~3ms per validation
- **Memory Usage**: Minimal (no state storage required)
- **Network**: No network calls required for validation

## Getting Started

```bash
# Install
npm install @actioncodes/protocol

# Basic usage
import { ActionCodesProtocol } from '@actioncodes/protocol';
import { SolanaAdapter } from '@actioncodes/protocol';

// Initialize protocol
const protocol = new ActionCodesProtocol({
  codeLength: 8,      // Code length (6-24 digits)
  ttlMs: 120000,      // Time to live (2 minutes)
  clockSkewMs: 5000   // Clock skew tolerance (5 seconds)
});

// Register Solana adapter
protocol.registerAdapter('solana', new SolanaAdapter());

// 1. Sign function for wallet
const signFn = async (message: Uint8Array, chain: string) => {
  // Sign the canonical message with your wallet
  const signature = await yourWallet.signMessage(message);
  return signature; // Returns base58-encoded signature
};

// 2. Generate a code
const actionCode = await protocol.generate(
  "wallet",
  yourWallet.publicKey.toString(),
  "solana",
  signFn
);

// 3. Validate a code
protocol.validate("wallet", actionCode);
// Throws ProtocolError if validation fails
```

### Protocol Meta with Issuer Field

When you need to separate the issuer (who created the code) from the intent owner (who will use it):

```typescript
import { buildProtocolMeta } from '@actioncodes/protocol';

// Create protocol meta with issuer
const meta = buildProtocolMeta({
  ver: 2,
  id: codeHash(actionCode.code),
  int: intentOwnerPubkey,    // Who will use the code
  iss: issuerPubkey,          // Who issued the code (optional)
});

// If iss is same as int, it's automatically omitted to save space
// If iss is present, transaction must be signed by BOTH int and iss
```

#### Vision

Action Codes Protocol aim to be the OTP protocol for blockchains but allowing more than authentication: a simple, universal interaction layer usable across apps, chains, and eventually banks/CBDCs interacting with blockchains.
