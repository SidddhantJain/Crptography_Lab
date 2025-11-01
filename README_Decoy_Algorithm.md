# Custom Decoy Encryption Algorithm

## Algorithm Overview

This is a custom encryption/decryption algorithm that provides **plausible deniability** by showing fake coherent messages when the wrong key is used, but reveals the correct message only with the right key.

## Design Concept

**Key Innovation**: Traditional encryption either works or fails. This algorithm always "works" but shows different content based on the key used.

- ✅ **Correct Key**: Shows the real encrypted message
- 🎭 **Wrong Key**: Shows plausible fake messages that look legitimate

## Algorithm Components

### 1. **Multi-Layer Encryption**
- **Layer 1**: Caesar cipher with shift based on key
- **Layer 2**: XOR cipher with the provided key
- **Layer 3**: Key verification hash embedding

### 2. **Decoy Message System**
- Pre-defined pool of coherent fake messages
- Consistent decoy selection based on wrong key hash
- Length matching to make decoys believable

### 3. **Key Verification**
- SHA-256 hash of correct key embedded in encrypted data
- Hash comparison determines real vs decoy decryption path

## Algorithm Steps

### Encryption Process:
1. Generate SHA-256 hash of correct key
2. Select appropriate decoy message for wrong keys
3. Apply Caesar shift to original message (shift = sum of key characters % 26)
4. Apply XOR encryption with correct key
5. Embed verification hash + hex-encoded encrypted data
6. Return final encrypted form

### Decryption Process:
1. Extract verification hash from encrypted data
2. Generate hash of provided key
3. **If hashes match** (correct key):
   - Reverse XOR encryption
   - Reverse Caesar shift
   - Return original message
4. **If hashes don't match** (wrong key):
   - Generate consistent decoy based on wrong key hash
   - Return plausible fake message

## Security Features

### ✅ **Advantages**
- **Plausible Deniability**: Wrong keys produce believable content
- **Consistent Decoys**: Same wrong key always produces same fake message
- **Multi-layer Protection**: Combined Caesar + XOR + Hash verification
- **Length Matching**: Decoys match approximate length of original

### ⚠️ **Considerations**
- Decoy messages are pre-defined (could be expanded with AI-generated content)
- Hash verification in encrypted data could be a fingerprint
- More sophisticated cryptanalysis might detect the pattern

## Example Usage

```python
# Create instance
decoy_system = DecoyEncryption()

# Encrypt
original = "My name is Siddhant Mishrikotkar"
correct_key = "secret123"
encrypted, sample_decoy = decoy_system.encrypt(original, correct_key)

# Decrypt with correct key
result = decoy_system.decrypt(encrypted, correct_key)
# Result: "My name is Siddhant Mishrikotkar"

# Decrypt with wrong key
fake_result = decoy_system.decrypt(encrypted, "wrongkey")
# Result: "the entity is unrelated to the appendix"
```

## Use Cases

1. **Sensitive Communication**: Protect against forced decryption
2. **Data Hiding**: Multiple layers of information in single encrypted form
3. **Security Research**: Study plausible deniability in cryptography
4. **Privacy Protection**: Avoid revealing existence of sensitive data

## Potential Enhancements

1. **Dynamic Decoy Generation**: Use AI/LLMs to generate contextual fake messages
2. **Multiple Real Messages**: Store multiple messages with different keys
3. **Steganography Integration**: Hide encrypted data in images/files
4. **Time-based Decoys**: Different fake messages based on decryption time
5. **Language-aware Decoys**: Generate decoys in same language as original

---

*This algorithm demonstrates an innovative approach to encryption where "failure" is indistinguishable from "success" with wrong credentials, providing an additional layer of security through deception.*