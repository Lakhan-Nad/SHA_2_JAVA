## SHA-2 Library Made in Java

### CLASSES

- SHA_2 - Contains static methods to create new hash

### Supports
- SHA224
- SHA256
- SHA384
- SHA512
- SHA512/224
- SHA512/256

### API for Each Digest
- public static hash(byte[] message) - Hashes the given message and return hex string.
- public static final **BLOCK_SIZE** - SIZE of each chunk in which processing happens.
- public static final **DIGEST_SIZE** - SIZE of digest in bytes.

- New Digest can be created using **new** operator
    - new DIGEST() - creates a new DIGEST
    - new DIGEST(byte[] message) - creates a new DIGEST with immediate processing of message
    - update(byte[] message) - updates(appends) the given message (used if the original string is too large we can process it in chunks)
    - finals() - Completes the DIGEST (after this function call update won't be accepted)
    - getDigest() - return the digest till now in bytes.
    - getHexDigest() - return the digest till now in Hex string.
    - resetDigest() - resets the whole DIGEST context