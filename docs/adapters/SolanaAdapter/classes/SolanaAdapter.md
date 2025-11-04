[**@actioncodes/protocol**](../../../README.md)

***

[@actioncodes/protocol](../../../modules.md) / [adapters/SolanaAdapter](../README.md) / SolanaAdapter

# Class: SolanaAdapter

Defined in: src/adapters/SolanaAdapter.ts:31

## Extends

- [`BaseChainAdapter`](../../BaseChainAdapter/classes/BaseChainAdapter.md)

## Constructors

### Constructor

> **new SolanaAdapter**(): `SolanaAdapter`

#### Returns

`SolanaAdapter`

#### Inherited from

[`BaseChainAdapter`](../../BaseChainAdapter/classes/BaseChainAdapter.md).[`constructor`](../../BaseChainAdapter/classes/BaseChainAdapter.md#constructor)

## Methods

### getProtocolMeta()

> **getProtocolMeta**(`txString`): `null` \| `string`

Defined in: src/adapters/SolanaAdapter.ts:280

Extract protocol metadata string (memo) from a base64-encoded transaction, or null

#### Parameters

##### txString

`string`

#### Returns

`null` \| `string`

***

### parseMeta()

> **parseMeta**(`txString`): `null` \| [`ProtocolMetaFields`](../../../utils/protocolMeta/interfaces/ProtocolMetaFields.md)

Defined in: src/adapters/SolanaAdapter.ts:329

Get parsed ProtocolMeta object from base64-encoded transaction, or null if none or invalid

#### Parameters

##### txString

`string`

#### Returns

`null` \| [`ProtocolMetaFields`](../../../utils/protocolMeta/interfaces/ProtocolMetaFields.md)

***

### verifyMessageSignedByIntentOwner()

> **verifyMessageSignedByIntentOwner**(`message`, `signature`, `pubkey`): `void`

Defined in: src/adapters/SolanaAdapter.ts:525

#### Parameters

##### message

`string`

##### signature

`string`

##### pubkey

`string`

#### Returns

`void`

***

### verifyRevokeWithDelegation()

> **verifyRevokeWithDelegation**(`delegatedActionCode`, `revokeSignature`): `boolean`

Defined in: src/adapters/SolanaAdapter.ts:187

#### Parameters

##### delegatedActionCode

[`DelegatedActionCode`](../../../types/interfaces/DelegatedActionCode.md)

##### revokeSignature

`string`

#### Returns

`boolean`

#### Overrides

[`BaseChainAdapter`](../../BaseChainAdapter/classes/BaseChainAdapter.md).[`verifyRevokeWithDelegation`](../../BaseChainAdapter/classes/BaseChainAdapter.md#verifyrevokewithdelegation)

***

### verifyRevokeWithWallet()

> **verifyRevokeWithWallet**(`actionCode`, `revokeSignature`): `boolean`

Defined in: src/adapters/SolanaAdapter.ts:154

Verify the signature over canonical revoke message (protocol-level)

#### Parameters

##### actionCode

[`ActionCode`](../../../types/interfaces/ActionCode.md)

##### revokeSignature

`string`

#### Returns

`boolean`

#### Overrides

[`BaseChainAdapter`](../../BaseChainAdapter/classes/BaseChainAdapter.md).[`verifyRevokeWithWallet`](../../BaseChainAdapter/classes/BaseChainAdapter.md#verifyrevokewithwallet)

***

### verifyTransactionMatchesCode()

> **verifyTransactionMatchesCode**(`actionCode`, `txString`): `void`

Defined in: src/adapters/SolanaAdapter.ts:375

Validate that a base64-encoded transaction's memo meta aligns with the bound `actionCode`.
Throws ProtocolError if validation fails.

#### Parameters

##### actionCode

[`ActionCode`](../../../types/interfaces/ActionCode.md)

##### txString

`string`

#### Returns

`void`

***

### verifyTransactionSignedByIntentOwner()

> **verifyTransactionSignedByIntentOwner**(`txString`): `void`

Defined in: src/adapters/SolanaAdapter.ts:413

Verify that the base64-encoded transaction is signed by the "intendedFor" pubkey
as declared in the protocol meta of the transaction.
Throws ProtocolError if validation fails.

#### Parameters

##### txString

`string`

#### Returns

`void`

***

### verifyWithDelegation()

> **verifyWithDelegation**(`delegatedActionCode`): `boolean`

Defined in: src/adapters/SolanaAdapter.ts:71

Verify delegation proof signature

#### Parameters

##### delegatedActionCode

[`DelegatedActionCode`](../../../types/interfaces/DelegatedActionCode.md)

#### Returns

`boolean`

#### Overrides

[`BaseChainAdapter`](../../BaseChainAdapter/classes/BaseChainAdapter.md).[`verifyWithDelegation`](../../BaseChainAdapter/classes/BaseChainAdapter.md#verifywithdelegation)

***

### verifyWithWallet()

> **verifyWithWallet**(`actionCode`): `boolean`

Defined in: src/adapters/SolanaAdapter.ts:41

Verify the signature over canonical message (protocol-level)

#### Parameters

##### actionCode

[`ActionCode`](../../../types/interfaces/ActionCode.md)

#### Returns

`boolean`

#### Overrides

[`BaseChainAdapter`](../../BaseChainAdapter/classes/BaseChainAdapter.md).[`verifyWithWallet`](../../BaseChainAdapter/classes/BaseChainAdapter.md#verifywithwallet)

***

### attachProtocolMeta()

> `static` **attachProtocolMeta**(`txString`, `meta`): `string`

Defined in: src/adapters/SolanaAdapter.ts:560

Attach protocol meta into a base64-encoded transaction and return the modified transaction as base64.
Throws ProtocolError if the transaction already contains protocol meta.

#### Parameters

##### txString

`string`

##### meta

[`ProtocolMetaFields`](../../../utils/protocolMeta/interfaces/ProtocolMetaFields.md)

#### Returns

`string`

***

### createProtocolMetaIx()

> `static` **createProtocolMetaIx**(`meta`): `TransactionInstruction`

Defined in: src/adapters/SolanaAdapter.ts:272

Create a Solana memo instruction carrying protocol meta (for SDK/clients)

#### Parameters

##### meta

[`ProtocolMetaFields`](../../../utils/protocolMeta/interfaces/ProtocolMetaFields.md)

#### Returns

`TransactionInstruction`
