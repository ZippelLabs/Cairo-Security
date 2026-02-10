# Cairo Security Vulnerabilities Checklist

## Table of Contents
1. [Unconstrained Witness Values](#1-unconstrained-witness-values)
2. [Integer Overflow/Underflow](#2-integer-overflowunderflow)
3. [Missing Access Control](#3-missing-access-control)
4. [Signature Replay Attacks](#4-signature-replay-attacks)
5. [Proof Malleability](#5-proof-malleability)
6. [Recursion Depth Attacks](#6-recursion-depth-attacks)
7. [L1↔L2 Message Handling Vulnerabilities](#7-l1l2-message-handling-vulnerabilities)
8. [Felt-to-Address Conversion Issues](#8-felt-to-address-conversion-issues)


### 1. Unconstrained Witness Values

**Summary**

When witness values are not properly constrained in the circuit, an attacker can submit arbitrary values that pass verification but produce incorrect computation results. This is one of the most critical vulnerabilities in zero-knowledge circuits as it completely undermines the security guarantees of the proof system.

**Background**

Cairo circuits operate by having a prover generate witness values that satisfy certain constraints. The verifier then checks that these constraints hold. However, if a witness value is used in computation but never constrained, the prover can set it to any value they choose. This creates a situation where the proof verifies successfully even though the computation is incorrect.

Consider a simple example where a circuit is meant to prove that a user knows the square root of a number:

```cairo
// Vulnerable circuit - proves knowledge of square root
func verify_square_root{range_check_ptr}(number: felt, claimed_root: felt) {
    let square = claimed_root * claimed_root;
    // Missing constraint: assert square = number
    return ();
}
```

**The Vulnerability**

In the above example, the circuit computes the square of `claimed_root` but never verifies that it equals `number`. An attacker can call this function with any values:

```cairo
// Attacker can pass any values and the function succeeds
verify_square_root(100, 999);  // Should fail but doesn't!
```

A more subtle real-world example occurs in token transfer circuits:

```cairo
// Vulnerable token transfer verification
func verify_transfer{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    sender_balance: felt,
    amount: felt,
    new_balance: felt
) {
    // Compute what the new balance should be
    let calculated_balance = sender_balance - amount;
    
    // Missing constraint comparing calculated_balance to new_balance!
    // The witness value new_balance is never verified
    
    return ();
}
```

An attacker could provide `new_balance = 0` while `calculated_balance = 50`, and the proof would still verify because `new_balance` is unconstrained.

**The Fix**

Every witness value that affects correctness must be explicitly constrained. Here's the corrected square root verification:

```cairo
// Fixed circuit - properly constrains the relationship
func verify_square_root{range_check_ptr}(number: felt, claimed_root: felt) {
    let square = claimed_root * claimed_root;
    // The Fix: Add explicit constraint
    assert square = number;
    return ();
}
```

And the corrected token transfer:

```cairo
// Fixed token transfer verification
func verify_transfer{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    sender_balance: felt,
    amount: felt,
    new_balance: felt
) {
    // Compute what the new balance should be
    let calculated_balance = sender_balance - amount;
    
    // The Fix: Assert the witness matches the computation
    assert new_balance = calculated_balance;
    
    // Additional fix: Ensure amount doesn't cause underflow
    assert_nn(calculated_balance);
    
    return ();
}
```

For complex circuits, create a checklist:
1. Identify all witness values in the circuit
2. For each witness, verify it's constrained by an assert statement
3. Ensure no computational paths bypass constraints
4. Use range checks for numeric bounds: `assert_nn()`, `assert_le()`, `assert_lt()`

**References**

1. <a href="https://diligence.security/blog/2022/01/under-constrained-computation-a-new-kind-of-bug/">Under-constraint Commputation</a>
2. <a href="https://starkware-9575960b.mintlify.app/build/starknet-by-example/basic/errors">StarkWare Cairo Documentation - Assertions</a>

---

### 2. Integer Overflow/Underflow

**Summary**

Cairo's felt type operates in a prime field (P = 2^251 + 17 * 2^192 + 1), and arithmetic operations wrap around this modulus. When developers treat felts as standard integers without proper constraints, arithmetic can produce unexpected results leading to critical security vulnerabilities.

**Background**

In traditional programming languages, integers have fixed sizes (e.g., uint256, int64) and overflow/underflow either reverts or wraps predictably. Cairo's felt type is fundamentally different - it represents elements in a finite field where arithmetic is performed modulo a large prime.

When you perform `a - b` where `a < b` in normal integer arithmetic, you'd get a negative number or an underflow error. In Cairo, you get a very large positive number close to the field modulus:

```cairo
let a: felt = 5;
let b: felt = 10;
let result = a - b;  // result ≈ 2^251, not -5!
```

**The Vulnerability**

Consider a vulnerable balance update function:

```cairo
// Vulnerable: Balance subtraction without checks
@storage_var
func balance(user: felt) -> (amount: felt) {
}

@external
func withdraw{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    amount: felt
) {
    let (caller) = get_caller_address();
    let (current_balance) = balance.read(caller);
    
    // Vulnerable: If amount > current_balance, this wraps around!
    let new_balance = current_balance - amount;
    
    balance.write(caller, new_balance);
    // User now has ~2^251 tokens instead of reverting!
    return ();
}
```

If a user with a balance of 100 tokens tries to withdraw 200 tokens, instead of reverting, `new_balance` becomes approximately 2^251 + 100 - 200.

Another common vulnerability involves multiplication overflow:

```cairo
// Vulnerable: Multiplying large values
func calculate_reward{range_check_ptr}(stake: felt, multiplier: felt) -> felt {
    let reward = stake * multiplier;  // Can overflow the field!
    return reward;
}
```

**The Fix**

Always add explicit range checks after arithmetic operations:

```cairo
// Fixed: Balance subtraction with proper checks
@external
func withdraw{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    amount: felt
) {
    let (caller) = get_caller_address();
    let (current_balance) = balance.read(caller);
    
    // The Fix: Ensure balance is sufficient before subtraction
    assert_le(amount, current_balance);
    
    let new_balance = current_balance - amount;
    
    // Additional check: Ensure result is non-negative
    assert_nn(new_balance);
    
    balance.write(caller, new_balance);
    return ();
}
```

For operations requiring strict integer semantics, use the `uint256` type:

```cairo
from starkware.cairo.common.uint256 import (
    Uint256, uint256_add, uint256_sub, uint256_mul, uint256_le
)

// Fixed: Using uint256 for guaranteed overflow protection
@external
func withdraw_safe{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    amount: Uint256
) {
    let (caller) = get_caller_address();
    let (current_balance: Uint256) = balance_uint256.read(caller);
    
    // uint256_le returns 1 if amount <= current_balance, else 0
    let (is_sufficient) = uint256_le(amount, current_balance);
    assert is_sufficient = 1;
    
    // uint256_sub will properly handle the subtraction with overflow checks
    let (new_balance: Uint256) = uint256_sub(current_balance, amount);
    
    balance_uint256.write(caller, new_balance);
    return ();
}
```

For multiplication, check bounds first:

```cairo
from starkware.cairo.common.math import assert_le, assert_nn

// Fixed: Safe multiplication with bounds checking
func calculate_reward{range_check_ptr}(stake: felt, multiplier: felt) -> felt {
    // The Fix: Define maximum safe values
    const MAX_STAKE = 2**128;
    const MAX_MULTIPLIER = 1000;
    
    assert_le(stake, MAX_STAKE);
    assert_le(multiplier, MAX_MULTIPLIER);
    
    let reward = stake * multiplier;
    return reward;
}
```

**References**

1. <a href="https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/cairo/common/math.cairo">Cairo Common Library Math Utilities</a>
2. <a href="https://www.starknet.io/cairo-book/ch12-10-arithmetic-circuits.html">StarkNet Field Arithmetic Documentation</a>
3. <a href="https://www.nethermind.io/blog/zk-circuit-security-a-guide-for-engineers-and-architects">Nethermind Cairo Security Guide</a>

---

### 3. Missing Access Control

**Summary**

Functions that modify critical state or perform privileged operations lack proper authorization checks, allowing unauthorized users to execute sensitive operations. This is one of the most commonly exploited vulnerabilities in smart contracts.

**Background**

Access control is a fundamental security primitive in smart contracts. Certain functions should only be callable by specific addresses (owners, admins, or authorized users). Without proper checks, any user can call these functions and manipulate contract state in unauthorized ways.

In traditional Solidity contracts, modifiers like `onlyOwner` are used. Cairo requires explicit checks using `get_caller_address()` and assertion statements.

**The Vulnerability**

Consider a token contract with a mint function:

```cairo
// Vulnerable: No access control on mint function
@storage_var
func total_supply() -> (supply: felt) {
}

@storage_var
func balances(account: felt) -> (balance: felt) {
}

@external
func mint{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    to: felt,
    amount: felt
) {
    // Vulnerable: Anyone can call this function!
    let (current_balance) = balances.read(to);
    balances.write(to, current_balance + amount);
    
    let (current_supply) = total_supply.read();
    total_supply.write(current_supply + amount);
    
    return ();
}
```

Any user can call this function and mint unlimited tokens to themselves, completely breaking the token economics.

Another example - a vulnerable pause mechanism:

```cairo
// Vulnerable: No access control on emergency functions
@storage_var
func paused() -> (is_paused: felt) {
}

@external
func pause{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    // Vulnerable: Any user can pause the contract!
    paused.write(1);
    return ();
}

@external
func unpause{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    // Vulnerable: Any user can unpause the contract!
    paused.write(0);
    return ();
}
```

**The Fix**

Implement proper access control using owner checks:

```cairo
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.starknet.common.syscalls import get_caller_address

@storage_var
func owner() -> (address: felt) {
}

@storage_var
func total_supply() -> (supply: felt) {
}

@storage_var
func balances(account: felt) -> (balance: felt) {
}

// Helper function to check ownership
func assert_only_owner{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    let (caller) = get_caller_address();
    let (owner_address) = owner.read();
    // The Fix: Assert caller is the owner
    assert caller = owner_address;
    return ();
}

@external
func mint{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    to: felt,
    amount: felt
) {
    // The Fix: Add access control check
    assert_only_owner();
    
    let (current_balance) = balances.read(to);
    balances.write(to, current_balance + amount);
    
    let (current_supply) = total_supply.read();
    total_supply.write(current_supply + amount);
    
    return ();
}

@constructor
func constructor{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    initial_owner: felt
) {
    owner.write(initial_owner);
    return ();
}
```

For more complex access control with roles, use OpenZeppelin's AccessControl:

```cairo
from openzeppelin.access.accesscontrol.library import AccessControl

const MINTER_ROLE = 'MINTER_ROLE';
const PAUSER_ROLE = 'PAUSER_ROLE';

@external
func mint{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    to: felt,
    amount: felt
) {
    // The Fix: Role-based access control
    AccessControl.assert_only_role(MINTER_ROLE);
    
    let (current_balance) = balances.read(to);
    balances.write(to, current_balance + amount);
    
    let (current_supply) = total_supply.read();
    total_supply.write(current_supply + amount);
    
    return ();
}

@external
func pause{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    // The Fix: Only addresses with PAUSER_ROLE can pause
    AccessControl.assert_only_role(PAUSER_ROLE);
    paused.write(1);
    return ();
}

@external
func grant_minter_role{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    account: felt
) {
    // Only admin can grant roles
    AccessControl.grant_role(MINTER_ROLE, account);
    return ();
}
```

Implement two-step ownership transfer for critical contracts:

```cairo
@storage_var
func pending_owner() -> (address: felt) {
}

@external
func transfer_ownership{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    new_owner: felt
) {
    assert_only_owner();
    pending_owner.write(new_owner);
    return ();
}

@external
func accept_ownership{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    let (caller) = get_caller_address();
    let (pending) = pending_owner.read();
    
    // The Fix: Require new owner to accept
    assert caller = pending;
    
    owner.write(pending);
    pending_owner.write(0);
    return ();
}
```

**References**

1. <a href="https://docs.openzeppelin.com/contracts-cairo/3.x/access">OpenZeppelin Cairo Access Control</a>
2. <a href="https://rareskills.io/post/cairo-access-control">RareSkills Access Control</a>

---

### 4. Signature Replay Attacks

**Summary**

Valid signatures can be reused across different contexts, chains, or multiple times, allowing attackers to replay legitimate transactions in unintended ways. This is particularly critical in meta-transaction systems and permit-style approvals.

**Background**

Signature-based authentication allows users to authorize actions off-chain by signing messages. The contract then verifies the signature and executes the action. Without proper safeguards, an attacker who observes a valid signature can replay it to execute the same action multiple times or in different contexts.

Common scenarios include:
- Meta-transactions where a relayer submits signed transactions on behalf of users
- Gasless approvals using EIP-2612 style permits
- Cross-chain applications where the same signature could be valid on multiple chains
- Voucher or claim systems using signatures

**The Vulnerability**

Consider a vulnerable gasless transfer system:

```cairo
from starkware.cairo.common.signature import verify_ecdsa_signature
from starkware.cairo.common.cairo_builtins import SignatureBuiltin

@storage_var
func balances(account: felt) -> (balance: felt) {
}

@external
func transfer_with_signature{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr,
    ecdsa_ptr: SignatureBuiltin*
}(
    from_address: felt,
    to_address: felt,
    amount: felt,
    signature_r: felt,
    signature_s: felt
) {
    alloc_locals;
    
    // Compute message hash
    let (message_hash) = hash2{hash_ptr=pedersen_ptr}(to_address, amount);
    
    // Verify signature
    verify_ecdsa_signature(
        message=message_hash,
        public_key=from_address,
        signature_r=signature_r,
        signature_s=signature_s
    );
    
    // Vulnerable: No nonce, so signature can be replayed indefinitely!
    let (from_balance) = balances.read(from_address);
    let (to_balance) = balances.read(to_address);
    
    balances.write(from_address, from_balance - amount);
    balances.write(to_address, to_balance + amount);
    
    return ();
}
```

An attacker can observe this transaction and replay the same signature multiple times, draining the victim's account.

Another vulnerability - cross-chain replay:

```cairo
// Vulnerable: Same signature valid on all chains
@external
func execute_meta_tx{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr,
    ecdsa_ptr: SignatureBuiltin*
}(
    user: felt,
    target: felt,
    calldata_len: felt,
    calldata: felt*,
    signature_r: felt,
    signature_s: felt
) {
    // Hash only the transaction details
    let (tx_hash) = hash_many(calldata_len, calldata);
    
    verify_ecdsa_signature(
        message=tx_hash,
        public_key=user,
        signature_r=signature_r,
        signature_s=signature_s
    );
    
    // Vulnerable: No chain ID - signature valid on all chains!
    // If contract deployed to multiple chains, same signature works everywhere
    
    call_contract(target, calldata_len, calldata);
    return ();
}
```

**The Fix**

Implement nonces to prevent replay:

```cairo
from starkware.cairo.common.signature import verify_ecdsa_signature
from starkware.cairo.common.cairo_builtins import SignatureBuiltin
from starkware.cairo.common.hash import hash2

@storage_var
func nonces(account: felt) -> (nonce: felt) {
}

@storage_var
func balances(account: felt) -> (balance: felt) {
}

@external
func transfer_with_signature{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr,
    ecdsa_ptr: SignatureBuiltin*
}(
    from_address: felt,
    to_address: felt,
    amount: felt,
    nonce: felt,
    signature_r: felt,
    signature_s: felt
) {
    alloc_locals;
    
    // The Fix: Verify and increment nonce
    let (current_nonce) = nonces.read(from_address);
    assert nonce = current_nonce;
    nonces.write(from_address, current_nonce + 1);
    
    // The Fix: Include nonce in message hash
    let (hash1) = hash2{hash_ptr=pedersen_ptr}(to_address, amount);
    let (message_hash) = hash2{hash_ptr=pedersen_ptr}(hash1, nonce);
    
    verify_ecdsa_signature(
        message=message_hash,
        public_key=from_address,
        signature_r=signature_r,
        signature_s=signature_s
    );
    
    let (from_balance) = balances.read(from_address);
    let (to_balance) = balances.read(to_address);
    
    balances.write(from_address, from_balance - amount);
    balances.write(to_address, to_balance + amount);
    
    return ();
}
```

For cross-chain protection, implement EIP-712 style domain separation:

```cairo
from starkware.starknet.common.syscalls import get_tx_info

// Constants for domain separation
const DOMAIN_NAME = 'MyDApp';
const DOMAIN_VERSION = '1';

@view
func get_chain_id{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
    chain_id: felt
) {
    let (tx_info) = get_tx_info();
    return (chain_id=tx_info.chain_id);
}

@external
func execute_meta_tx{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr,
    ecdsa_ptr: SignatureBuiltin*
}(
    user: felt,
    target: felt,
    calldata_len: felt,
    calldata: felt*,
    nonce: felt,
    deadline: felt,
    signature_r: felt,
    signature_s: felt
) {
    alloc_locals;
    
    // The Fix: Check deadline to prevent old signatures
    let (block_timestamp) = get_block_timestamp();
    assert_le(block_timestamp, deadline);
    
    // The Fix: Verify and increment nonce
    let (current_nonce) = nonces.read(user);
    assert nonce = current_nonce;
    nonces.write(user, current_nonce + 1);
    
    // The Fix: Include chain ID in message hash
    let (chain_id) = get_chain_id();
    let (contract_address) = get_contract_address();
    
    // Build EIP-712 style structured hash
    // domain_separator = hash(DOMAIN_NAME, DOMAIN_VERSION, chain_id, contract_address)
    let (hash1) = hash2{hash_ptr=pedersen_ptr}(DOMAIN_NAME, DOMAIN_VERSION);
    let (hash2) = hash2{hash_ptr=pedersen_ptr}(chain_id, contract_address);
    let (domain_separator) = hash2{hash_ptr=pedersen_ptr}(hash1, hash2);
    
    // message_hash = hash(domain_separator, tx_details)
    let (tx_hash) = hash_many(calldata_len, calldata);
    let (hash3) = hash2{hash_ptr=pedersen_ptr}(nonce, deadline);
    let (hash4) = hash2{hash_ptr=pedersen_ptr}(tx_hash, hash3);
    let (message_hash) = hash2{hash_ptr=pedersen_ptr}(domain_separator, hash4);
    
    verify_ecdsa_signature(
        message=message_hash,
        public_key=user,
        signature_r=signature_r,
        signature_s=signature_s
    );
    
    call_contract(target, calldata_len, calldata);
    return ();
}
```

For one-time use signatures (like vouchers), track used signatures:

```cairo
@storage_var
func used_signatures(signature_hash: felt) -> (used: felt) {
}

@external
func redeem_voucher{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr,
    ecdsa_ptr: SignatureBuiltin*
}(
    user: felt,
    amount: felt,
    voucher_id: felt,
    signature_r: felt,
    signature_s: felt
) {
    alloc_locals;
    
    // Create signature hash for tracking
    let (sig_hash1) = hash2{hash_ptr=pedersen_ptr}(signature_r, signature_s);
    let (sig_hash) = hash2{hash_ptr=pedersen_ptr}(sig_hash1, voucher_id);
    
    // The Fix: Ensure signature hasn't been used
    let (is_used) = used_signatures.read(sig_hash);
    assert is_used = 0;
    
    let (message_hash) = hash2{hash_ptr=pedersen_ptr}(user, amount);
    let (final_hash) = hash2{hash_ptr=pedersen_ptr}(message_hash, voucher_id);
    
    verify_ecdsa_signature(
        message=final_hash,
        public_key=VOUCHER_SIGNER,
        signature_r=signature_r,
        signature_s=signature_s
    );
    
    // The Fix: Mark signature as used
    used_signatures.write(sig_hash, 1);
    
    // Process voucher redemption
    let (balance) = balances.read(user);
    balances.write(user, balance + amount);
    
    return ();
}
```

**References**

1. <a href="https://eips.ethereum.org/EIPS/eip-712">EIP-712: Structured Data Hashing and Signing</a>
2. <a href="https://github.com/OpenZeppelin/cairo-contracts/blob/main/docs/modules/ROOT/pages/accounts.adoc">OpenZeppelin Cairo Contracts</a>

---

### 5. Proof Malleability

**Summary**

A proof is malleable if multiple different valid proofs can be generated for the same statement. This allows attackers to modify valid proofs and replay them, potentially bypassing replay protection or double-spending prevention mechanisms.

**Background**

In zero-knowledge systems, proof malleability occurs when the proof system allows different valid proofs for the same witness and public inputs. Unlike signature malleability in ECDSA, proof malleability in SNARKs/STARKs can arise from the mathematical structure of the proof system itself.

Cairo proofs can be malleable if the circuit doesn't enforce canonical representations or if the proof system allows multiple valid proof representations.

**The Vulnerability**

```cairo
// Vulnerable: Proof doesn't enforce canonical form
@storage_var
func claimed_airdrops(proof_hash: felt) -> (claimed: felt) {
}

@external
func claim_airdrop{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr
}(
    user: felt,
    amount: felt,
    merkle_proof_len: felt,
    merkle_proof: felt*
) {
    // Verify merkle proof
    let is_valid = verify_merkle_proof(user, amount, merkle_proof_len, merkle_proof);
    assert is_valid = 1;
    
    // Vulnerable: Hash only includes user and amount, not the actual proof
    let (claim_hash) = hash2{hash_ptr=pedersen_ptr}(user, amount);
    
    let (already_claimed) = claimed_airdrops.read(claim_hash);
    assert already_claimed = 0;
    
    // An attacker could construct a different valid merkle proof
    // for the same (user, amount) and claim multiple times!
    
    claimed_airdrops.write(claim_hash, 1);
    transfer_tokens(user, amount);
    return ();
}
```

Another example with malleable point representations:

```cairo
// Vulnerable: Accepts non-canonical EC points
func verify_signature{range_check_ptr}(
    message: felt,
    public_key_x: felt,
    public_key_y: felt,
    sig_r: felt,
    sig_s: felt
) {
    // Vulnerable: No check that public_key is in canonical form
    // EC points (x, y) and (x, -y mod P) both lie on the curve
    // Attacker can use either form to create different valid proofs
    
    verify_ecdsa_signature(
        message=message,
        public_key=public_key_x,
        signature_r=sig_r,
        signature_s=sig_s
    );
    return ();
}
```

**The Fix**

Include the complete proof in uniqueness checks:

```cairo
from starkware.cairo.common.hash_chain import hash_chain

@external
func claim_airdrop{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr
}(
    user: felt,
    amount: felt,
    merkle_proof_len: felt,
    merkle_proof: felt*
) {
    alloc_locals;
    
    // Verify merkle proof
    let is_valid = verify_merkle_proof(user, amount, merkle_proof_len, merkle_proof);
    assert is_valid = 1;
    
    // The Fix: Hash includes the complete proof to ensure uniqueness
    let (proof_hash) = hash_chain{hash_ptr=pedersen_ptr}(merkle_proof_len, merkle_proof);
    let (temp_hash) = hash2{hash_ptr=pedersen_ptr}(user, amount);
    let (claim_hash) = hash2{hash_ptr=pedersen_ptr}(temp_hash, proof_hash);
    
    let (already_claimed) = claimed_airdrops.read(claim_hash);
    assert already_claimed = 0;
    
    claimed_airdrops.write(claim_hash, 1);
    transfer_tokens(user, amount);
    return ();
}
```

Enforce canonical representations:

```cairo
from starkware.cairo.common.math import assert_le

// Fixed: Enforce canonical EC point representation
func verify_signature_canonical{range_check_ptr}(
    message: felt,
    public_key_x: felt,
    public_key_y: felt,
    sig_r: felt,
    sig_s: felt
) {
    // The Fix: Enforce canonical y-coordinate
    // Require y to be the smaller of (y, P - y)
    const HALF_PRIME = (PRIME - 1) / 2;
    assert_le(public_key_y, HALF_PRIME);
    
    // The Fix: Also enforce low-s signature (canonical s value)
    assert_le(sig_s, HALF_PRIME);
    
    verify_ecdsa_signature(
        message=message,
        public_key=public_key_x,
        signature_r=sig_r,
        signature_s=sig_s
    );
    return ();
}
```

**References**

1. <a href="https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki">ECDSA Malleability and How to Prevent It</a>
2. <a href="https://eprint.iacr.org/2019/953.pdf">Canonical Representation in Zero-Knowledge Proofs</a>

---

### 6. Recursion Depth Attacks

**Summary**

Unbounded recursion in Cairo can cause proof generation to fail or consume excessive computational resources, leading to denial of service or failed transactions.

**Background**

Cairo compiles to a trace of execution steps. Deep recursion creates very long execution traces, which:
- Increases proof generation time exponentially
- Can exceed trace length limits
- Consumes excessive memory during proving
- May make proofs economically unviable to generate

Unlike traditional stack overflow (Cairo has no stack limit), the issue is practical: proofs become too expensive or impossible to generate.

**The Vulnerability**

```cairo
// Vulnerable: Unbounded recursion based on user input
func factorial{range_check_ptr}(n: felt) -> felt {
    // Vulnerable: No limit on recursion depth!
    // User can pass n = 1000000 and cause DoS
    if (n == 0) {
        return 1;
    }
    
    let prev = factorial(n - 1);
    return n * prev;
}

@external
func calculate{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    n: felt
) -> (result: felt) {
    // Attacker can pass huge n value
    let result = factorial(n);
    return (result,);
}
```

Array processing with unbounded recursion:

```cairo
// Vulnerable: Recursion depth equals array length
func sum_array{range_check_ptr}(arr_len: felt, arr: felt*) -> felt {
    // Vulnerable: No limit on arr_len!
    // Attacker can pass huge array causing excessive recursion
    if (arr_len == 0) {
        return 0;
    }
    
    let rest_sum = sum_array(arr_len - 1, arr + 1);
    return [arr] + rest_sum;
}
```

**The Fix**

Impose maximum recursion depth limits:

```cairo
// Fixed: Maximum recursion depth enforced
const MAX_FACTORIAL_INPUT = 100;

func factorial{range_check_ptr}(n: felt) -> felt {
    // The Fix: Limit maximum input
    assert_le(n, MAX_FACTORIAL_INPUT);
    
    if (n == 0) {
        return 1;
    }
    
    let prev = factorial(n - 1);
    return n * prev;
}

@external
func calculate{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    n: felt
) -> (result: felt) {
    let result = factorial(n);
    return (result,);
}
```

Use iterative approaches instead of recursion:

```cairo
// Fixed: Iterative instead of recursive
func sum_array{range_check_ptr}(arr_len: felt, arr: felt*) -> felt {
    // The Fix: Still limit array length
    const MAX_ARRAY_LEN = 1000;
    assert_le(arr_len, MAX_ARRAY_LEN);
    
    return sum_array_iter(arr_len, arr, 0);
}

func sum_array_iter{range_check_ptr}(arr_len: felt, arr: felt*, acc: felt) -> felt {
    if (arr_len == 0) {
        return acc;
    }
    
    // Tail recursion - compiler can optimize
    return sum_array_iter(arr_len - 1, arr + 1, acc + [arr]);
}
```

Use loops for bounded operations:

```cairo
// Fixed: Loop-based approach with clear bounds
func sum_array_loop{range_check_ptr}(arr_len: felt, arr: felt*) -> felt {
    alloc_locals;
    const MAX_ARRAY_LEN = 1000;
    assert_le(arr_len, MAX_ARRAY_LEN);
    
    local sum = 0;
    local index = 0;
    
    loop:
    if (index == arr_len) {
        return sum;
    }
    
    let sum = sum + arr[index];
    let index = index + 1;
    jmp loop;
}
```

Paginate large data processing:

```cairo
// Fixed: Process in batches to limit recursion depth
const BATCH_SIZE = 100;

struct ProcessingState {
    processed: felt,
    total: felt,
}

@external
func process_large_array{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    arr_len: felt,
    arr: felt*,
    batch_index: felt
) -> (state: ProcessingState) {
    alloc_locals;
    
    let start_idx = batch_index * BATCH_SIZE;
    let end_idx = start_idx + BATCH_SIZE;
    
    // The Fix: Process only one batch at a time
    let actual_end = min(end_idx, arr_len);
    let batch_len = actual_end - start_idx;
    
    // Process this batch
    let batch_result = process_batch(batch_len, arr + start_idx);
    
    let state = ProcessingState(
        processed=actual_end,
        total=arr_len
    );
    
    return (state,);
}
```

**References**

1. <a href="https://www.cairo-lang.org/docs/how_cairo_works/cairo_intro.html">Cairo Execution Model</a>
2. <a href="https://book.cairo-lang.org/ch11-00-advanced-features.html">Advanced Cairo Programming</a>

---

### 7. L1↔L2 Message Handling Vulnerabilities

**Summary**

Improper handling of messages between Layer 1 (Ethereum) and Layer 2 (Starknet) can lead to message replay attacks, failed message deliveries, and inconsistent state between layers. This is critical for bridge security and cross-layer applications.

**Background**

Starknet enables communication between L1 and L2 through a messaging system. L1 contracts can send messages to L2 contracts, and vice versa. However, this creates several security challenges:
- Messages must be properly validated on both sides
- Message cancellation must be handled correctly
- Nonce management prevents replay
- Failed messages must be properly handled
- State synchronization between layers is critical

**The Vulnerability**

```cairo
// Vulnerable: No validation of L1 sender
@l1_handler
func handle_deposit{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    from_address: felt,
    user: felt,
    amount: felt
) {
    // Vulnerable: Doesn't verify from_address is the authorized L1 contract!
    // Any L1 contract could send messages and mint tokens
    
    let (balance) = balances.read(user);
    balances.write(user, balance + amount);
    
    return ();
}
```

Another vulnerability - missing message consumption:

```cairo
// Vulnerable: Message not consumed after processing
@l1_handler
func handle_withdrawal_completion{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr
}(
    from_address: felt,
    user: felt,
    amount: felt,
    nonce: felt
) {
    // Process withdrawal
    let (balance) = balances.read(user);
    balances.write(user, balance + amount);
    
    // Vulnerable: Message not marked as consumed!
    // Could potentially be replayed
    
    return ();
}
```

Message ordering issues:

```cairo
// Vulnerable: No handling of message ordering
@l1_handler
func handle_state_update{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    from_address: felt,
    state_root: felt,
    block_number: felt
) {
    // Vulnerable: Doesn't check if block_number > current_block_number
    // Old messages could overwrite newer state!
    
    current_state_root.write(state_root);
    current_block.write(block_number);
    
    return ();
}
```

**The Fix**

Validate L1 sender address:

```cairo
@storage_var
func l1_bridge_address() -> (address: felt) {
}

@l1_handler
func handle_deposit{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    from_address: felt,
    user: felt,
    amount: felt
) {
    // The Fix: Verify message comes from authorized L1 contract
    let (authorized_l1) = l1_bridge_address.read();
    assert from_address = authorized_l1;
    
    let (balance) = balances.read(user);
    balances.write(user, balance + amount);
    
    return ();
}

@constructor
func constructor{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    l1_bridge: felt
) {
    l1_bridge_address.write(l1_bridge);
    return ();
}
```

Properly track message consumption:

```cairo
@storage_var
func processed_messages(message_hash: felt) -> (processed: felt) {
}

@l1_handler
func handle_withdrawal_completion{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr
}(
    from_address: felt,
    user: felt,
    amount: felt,
    nonce: felt
) {
    alloc_locals;
    
    // The Fix: Verify authorized sender
    let (authorized_l1) = l1_bridge_address.read();
    assert from_address = authorized_l1;
    
    // The Fix: Create unique message identifier
    let (hash1) = hash2{hash_ptr=pedersen_ptr}(user, amount);
    let (message_hash) = hash2{hash_ptr=pedersen_ptr}(hash1, nonce);
    
    // The Fix: Ensure message hasn't been processed
    let (is_processed) = processed_messages.read(message_hash);
    assert is_processed = 0;
    
    // Process withdrawal
    let (balance) = balances.read(user);
    balances.write(user, balance + amount);
    
    // The Fix: Mark message as processed
    processed_messages.write(message_hash, 1);
    
    return ();
}
```

Handle message ordering correctly:

```cairo
@storage_var
func current_block() -> (block: felt) {
}

@storage_var
func current_state_root() -> (root: felt) {
}

@l1_handler
func handle_state_update{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    from_address: felt,
    state_root: felt,
    block_number: felt
) {
    alloc_locals;
    
    // The Fix: Verify authorized sender
    let (authorized_l1) = l1_oracle_address.read();
    assert from_address = authorized_l1;
    
    // The Fix: Ensure block number is greater than current
    let (current) = current_block.read();
    assert_lt(current, block_number);
    
    current_state_root.write(state_root);
    current_block.write(block_number);
    
    return ();
}
```

Implement proper message cancellation handling:

```cairo
@storage_var
func pending_withdrawals(user: felt, nonce: felt) -> (amount: felt) {
}

@storage_var
func withdrawal_initiated_time(user: felt, nonce: felt) -> (timestamp: felt) {
}

const MESSAGE_CANCEL_DELAY = 86400 * 5;  // 5 days

@external
func initiate_withdrawal{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    amount: felt
) {
    alloc_locals;
    let (caller) = get_caller_address();
    let (nonce) = withdrawal_nonce.read(caller);
    
    // Deduct balance
    let (balance) = balances.read(caller);
    assert_le(amount, balance);
    balances.write(caller, balance - amount);
    
    // Record withdrawal
    pending_withdrawals.write(caller, nonce, amount);
    let (block_timestamp) = get_block_timestamp();
    withdrawal_initiated_time.write(caller, nonce, block_timestamp);
    
    // Send message to L1
    send_message_to_l1(L1_BRIDGE, caller, amount, nonce);
    
    withdrawal_nonce.write(caller, nonce + 1);
    return ();
}

@external
func cancel_withdrawal{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    nonce: felt
) {
    alloc_locals;
    let (caller) = get_caller_address();
    
    // The Fix: Can only cancel after delay period
    let (initiated_time) = withdrawal_initiated_time.read(caller, nonce);
    let (current_time) = get_block_timestamp();
    assert_le(initiated_time + MESSAGE_CANCEL_DELAY, current_time);
    
    // Refund the pending amount
    let (amount) = pending_withdrawals.read(caller, nonce);
    assert amount != 0;  // Ensure withdrawal exists
    
    let (balance) = balances.read(caller);
    balances.write(caller, balance + amount);
    
    // Clear pending withdrawal
    pending_withdrawals.write(caller, nonce, 0);
    withdrawal_initiated_time.write(caller, nonce, 0);
    
    return ();
}
```

**References**

1. <a href="https://docs.starknet.io/documentation/architecture_and_concepts/Network_Architecture/messaging-mechanism/">Starknet L1-L2 Messaging</a>
2. <a href="https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/starknet/core/os/contract_class/deprecated_class.cairo">L1 Handler Best Practices</a>
3. <a href="https://www.starknet.io/cairo-book/ch13-03-l1-l2-messaging.html">Cairo Book: L1-L2 Communication</a>

---

### 8. Felt-to-Address Conversion Issues

**Summary**

Improper conversion between felt values and addresses can lead to invalid addresses, loss of funds, or unauthorized access. Cairo's felt type can represent values larger than valid Ethereum addresses, and StarkNet addresses have different validation requirements.

**Background**

In Cairo, addresses are represented as felt values. However:
- Ethereum addresses are 160 bits (20 bytes), but felt can hold values up to 251 bits
- StarkNet contract addresses must be valid field elements
- Converting between felt and address types without validation can lead to issues
- Address validation is critical for security

Common issues include:
- Accepting invalid addresses that are too large
- Not validating zero addresses when required
- Confusion between L1 Ethereum addresses and L2 StarkNet addresses
- Improper address derivation in contract deployments

**The Vulnerability**

```cairo
// Vulnerable: No validation of address size
@external
func transfer{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    to: felt,
    amount: felt
) {
    // Vulnerable: 'to' could be any felt value, including invalid addresses
    // No check that it's a valid StarkNet address
    
    let (caller) = get_caller_address();
    let (sender_balance) = balances.read(caller);
    
    assert_le(amount, sender_balance);
    balances.write(caller, sender_balance - amount);
    
    let (recipient_balance) = balances.read(to);
    balances.write(to, recipient_balance + amount);
    
    return ();
}
```

Ethereum address validation issues:

```cairo
// Vulnerable: No validation of L1 address size
@storage_var
func l1_address_mapping(l2_address: felt) -> (l1_address: felt) {
}

@external
func register_l1_address{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    l1_address: felt
) {
    // Vulnerable: l1_address could be larger than 160 bits
    // Invalid Ethereum address could be stored
    
    let (caller) = get_caller_address();
    l1_address_mapping.write(caller, l1_address);
    
    return ();
}
```

Zero address handling:

```cairo
// Vulnerable: Allows zero address transfers
@external
func set_owner{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    new_owner: felt
) {
    assert_only_owner();
    
    // Vulnerable: new_owner could be 0, locking the contract!
    owner.write(new_owner);
    
    return ();
}
```

**The Fix**

Validate StarkNet addresses:

```cairo
from starkware.cairo.common.math import assert_not_zero, assert_le

// Fixed: Validate address is non-zero and in valid range
@external
func transfer{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    to: felt,
    amount: felt
) {
    alloc_locals;
    
    // The Fix: Ensure address is not zero
    assert_not_zero(to);
    
    // The Fix: Ensure address is within valid felt range
    // StarkNet addresses are valid field elements less than PRIME
    // This is generally enforced by the type system, but explicit check is safer
    
    let (caller) = get_caller_address();
    assert_not_zero(caller);  // Paranoid check
    
    let (sender_balance) = balances.read(caller);
    assert_le(amount, sender_balance);
    
    balances.write(caller, sender_balance - amount);
    
    let (recipient_balance) = balances.read(to);
    balances.write(to, recipient_balance + amount);
    
    return ();
}
```

Validate Ethereum addresses:

```cairo
const ETH_ADDRESS_BOUND = 2**160;

// Fixed: Validate L1 Ethereum address size
@external
func register_l1_address{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    l1_address: felt
) {
    alloc_locals;
    
    // The Fix: Ensure it's a valid Ethereum address (160 bits)
    assert_not_zero(l1_address);
    assert_lt(l1_address, ETH_ADDRESS_BOUND);
    
    let (caller) = get_caller_address();
    l1_address_mapping.write(caller, l1_address);
    
    return ();
}
```

Prevent zero address in critical functions:

```cairo
// Fixed: Validate non-zero address for ownership
@external
func set_owner{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    new_owner: felt
) {
    assert_only_owner();
    
    // The Fix: Ensure new owner is not zero address
    assert_not_zero(new_owner);
    
    owner.write(new_owner);
    
    return ();
}

// Fixed: Proper two-step ownership transfer
@storage_var
func pending_owner() -> (address: felt) {
}

@external
func transfer_ownership{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    new_owner: felt
) {
    assert_only_owner();
    
    // The Fix: Validate new owner address
    assert_not_zero(new_owner);
    
    pending_owner.write(new_owner);
    return ();
}

@external
func accept_ownership{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    let (caller) = get_caller_address();
    let (pending) = pending_owner.read();
    
    // The Fix: Caller must be the pending owner
    assert caller = pending;
    assert_not_zero(pending);
    
    owner.write(pending);
    pending_owner.write(0);
    return ();
}
```

Validate contract addresses before calls:

```cairo
from starkware.starknet.common.syscalls import call_contract

// Fixed: Validate target contract address
@external
func call_external{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    target_contract: felt,
    function_selector: felt,
    calldata_len: felt,
    calldata: felt*
) {
    alloc_locals;
    
    // The Fix: Validate target address
    assert_not_zero(target_contract);
    
    // The Fix: Optionally check if it's a whitelisted contract
    let (is_whitelisted) = whitelisted_contracts.read(target_contract);
    assert is_whitelisted = 1;
    
    let (retdata_size, retdata) = call_contract(
        contract_address=target_contract,
        function_selector=function_selector,
        calldata_size=calldata_len,
        calldata=calldata
    );
    
    return ();
}
```

Proper address derivation for contract deployment:

```cairo
from starkware.starknet.common.syscalls import deploy

// Fixed: Properly handle contract address derivation
@external
func deploy_contract{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    class_hash: felt,
    contract_address_salt: felt,
    constructor_calldata_len: felt,
    constructor_calldata: felt*
) -> (deployed_address: felt) {
    alloc_locals;
    
    // The Fix: Validate class hash
    assert_not_zero(class_hash);
    
    // Deploy contract
    let (deployed_address) = deploy(
        class_hash=class_hash,
        contract_address_salt=contract_address_salt,
        constructor_calldata_size=constructor_calldata_len,
        constructor_calldata=constructor_calldata,
        deploy_from_zero=0
    );
    
    // The Fix: Validate deployment succeeded with valid address
    assert_not_zero(deployed_address);
    
    // Store deployed contract
    deployed_contracts.write(deployed_address, 1);
    
    return (deployed_address,);
}
```

**References**

1. <a href="https://docs.starknet.io/documentation/architecture_and_concepts/Smart_Contracts/contract-address/">StarkNet Contract Address Computation</a>
2. <a href="https://www.cairo-lang.org/docs/how_cairo_works/consts.html#field-elements">Cairo Field Elements</a>
3. <a href="https://eips.ethereum.org/EIPS/eip-55">EIP-55: Mixed-case checksum address encoding</a>

---

## Contributing

This checklist is a living document. If you discover new vulnerability patterns or have improvements to suggest, please:

1. Open an issue describing the vulnerability pattern
2. Provide example vulnerable code and fixes
3. Include references to real-world incidents or security research

## Disclaimer

This checklist is provided for educational purposes. Always conduct thorough security audits with professional auditors before deploying contracts to production. The examples provided are simplified for illustration and may not cover all edge cases.

## License

See [LICENSE](LICENSE) for more information.
