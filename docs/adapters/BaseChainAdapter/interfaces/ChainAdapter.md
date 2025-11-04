[**@actioncodes/protocol**](../../../README.md)

***

[@actioncodes/protocol](../../../modules.md) / [adapters/BaseChainAdapter](../README.md) / ChainAdapter

# Interface: ChainAdapter

Defined in: src/adapters/BaseChainAdapter.ts:3

## Methods

### verifyRevokeWithDelegation()

> **verifyRevokeWithDelegation**(`actionCode`, `revokeSignature`): `boolean`

Defined in: src/adapters/BaseChainAdapter.ts:10

#### Parameters

##### actionCode

[`DelegatedActionCode`](../../../types/interfaces/DelegatedActionCode.md)

##### revokeSignature

`string`

#### Returns

`boolean`

***

### verifyRevokeWithWallet()

> **verifyRevokeWithWallet**(`actionCode`, `revokeSignature`): `boolean`

Defined in: src/adapters/BaseChainAdapter.ts:6

#### Parameters

##### actionCode

[`ActionCode`](../../../types/interfaces/ActionCode.md)

##### revokeSignature

`string`

#### Returns

`boolean`

***

### verifyWithDelegation()

> **verifyWithDelegation**(`actionCode`): `boolean`

Defined in: src/adapters/BaseChainAdapter.ts:5

#### Parameters

##### actionCode

[`DelegatedActionCode`](../../../types/interfaces/DelegatedActionCode.md)

#### Returns

`boolean`

***

### verifyWithWallet()

> **verifyWithWallet**(`actionCode`): `boolean`

Defined in: src/adapters/BaseChainAdapter.ts:4

#### Parameters

##### actionCode

[`ActionCode`](../../../types/interfaces/ActionCode.md)

#### Returns

`boolean`
