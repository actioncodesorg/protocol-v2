[**@actioncodes/protocol**](../../../README.md)

***

[@actioncodes/protocol](../../../modules.md) / [strategy/DelegationStrategy](../README.md) / DelegationStrategy

# Class: DelegationStrategy

Defined in: src/strategy/DelegationStrategy.ts:15

## Constructors

### Constructor

> **new DelegationStrategy**(`config`): `DelegationStrategy`

Defined in: src/strategy/DelegationStrategy.ts:19

#### Parameters

##### config

[`CodeGenerationConfig`](../../../types/interfaces/CodeGenerationConfig.md)

#### Returns

`DelegationStrategy`

## Methods

### generateDelegatedCode()

> **generateDelegatedCode**(`delegationProof`, `canonicalMessage`, `chain`, `signature`): [`DelegatedActionCode`](../../../types/interfaces/DelegatedActionCode.md)

Defined in: src/strategy/DelegationStrategy.ts:27

Generate a delegated action code using a delegation proof and signature over message to generate code via delegated keypair

#### Parameters

##### delegationProof

[`DelegationProof`](../../../types/interfaces/DelegationProof.md)

##### canonicalMessage

`Uint8Array`

##### chain

`"solana"`

##### signature

`string`

#### Returns

[`DelegatedActionCode`](../../../types/interfaces/DelegatedActionCode.md)

***

### validateDelegatedCode()

> **validateDelegatedCode**(`actionCode`): `void`

Defined in: src/strategy/DelegationStrategy.ts:56

Validate a delegated action code

#### Parameters

##### actionCode

[`DelegatedActionCode`](../../../types/interfaces/DelegatedActionCode.md)

#### Returns

`void`
