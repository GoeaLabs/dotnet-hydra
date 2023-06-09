### GoeaLabs.Hydra

![GitHub](https://img.shields.io/github/license/GoeaLabs/dotnet-hydra?style=for-the-badge)
![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/GoeaLabs/dotnet-hydra?include_prereleases&style=for-the-badge)
![Nuget (with prereleases)](https://img.shields.io/nuget/vpre/GoeaLabs.Hydra?style=for-the-badge)

# Project Description

Hydra is an authenticated cipher with associated data (AEAD). Hydra draws its lineage from the ChaCha family of ciphers, 
which presently includes ChaCha20 and XChaChaPoly-1305. 

While it shares this heritage, Hydra stands apart from its predecessors with a distinct design and features. Although it 
may have originated from the same cryptographic family tree, Hydra has been evolved to offer unique capabilities and 
enhancements beyond what the ChaCha ciphers provide.

The main characteristics of ChaCha20, XChaCha20-Poly1305 and **Hydra** at a glance:

| Cipher Name        | Key Size (bits) | Nonce Size (bits) | Rounds       | Hashing Algorithm                                                                                  | Encrypts Signature | Max Plaintext (GB) |
|--------------------|-----------------|-------------------|--------------|----------------------------------------------------------------------------------------------------|--------------------|--------------------|
| ChaCha20           | 256             | 96                | 20           | N/A                                                                                                | N/A                | 4                  |
| XChaCha20-Poly1305 | 256             | 192               | 20           | Poly1305                                                                                           | No                 | 256                |
| Hydra              | 256             | 256               | &#8805; 20** | Sha256Plain*, Sha384Plain*, Sha512Plain*, Sha256Keyed, Sha384Keyed, Sha512Keyed & **user defined** | Yes                | 1.498 × 10^27      |

\*  Due to the fact that **Hydra** always encrypts the resulting ciphertext signature, it is safe to use cryptographically secure hashing functions that do not require a secret hashing key.
<br>
\** Number of rounds must be even.

# Technical summary

The key to understanding **Hydra** lies in understanding its key system (pun intended). During the encryption process, **Hydra** makes use of either 4 or 5 keys, depending
on whether the hashing algorithm of choice requires a secret key of its own or not.

The following table displays a short overview of these keys and their purpose:

| Key Name | Key Size (bits) | Generated by | Managed by | Description                                                                                                        |
|----------|-----------------|--------------|------------|--------------------------------------------------------------------------------------------------------------------|
| X-KEY    | 256             | User         | User       | The secret key. It is almost never* used to encrypt data directly.                                                 |
| N-KEY    | 256             | Hydra        | Hydra      | The nonce. Randomly generated every time encryption is performed.                                                  |
| E-KEY    | 256             | Hydra        | Hydra      | The key used to encrypt plaintext. E-KEY = X-KEY &#x2295; N-KEY.                                                   |
| H-KEY    | Variable        | Hydra        | Hydra      | Hashing key if a particular hashing algorithm requires one. Randomly generated every time encryption is performed. |
| S-KEY    | Variable        | Hydra        | Hydra      | Signature encryption key. Randomly generated every time encryption is performed.                                   |

\* The probability that the X-KEY directly participates in encryption is 1/2^256. This is because, there is a probability of 1/2^256 of randomly generating an all zero N-KEY, 
in which case E-KEY and X-KEY will be the same. Please note that this has no impact on the security of the cipher.

Beyond its unique key system, **Hydra** has the following attributes:

- It supports 6 built-in hashing algorithms and allows users to plug-in other hashing algorithms of their choice;
- It not only signs the resulting ciphertext, but it also encrypts the resulting signature, thus enabling the use of cryptographically secure hashing algorithms that do not 
require a secret key. The reason why this might be desirable is that usually keyed hashing algorithms need to perform multiple passes over the data which negatively impacts
performance.
- Although up to 5 keys participate in the encryption/decryption process, the user is never burdened with the management of any key beyond the secret key (X-KEY);

## API

| Method Signature                                                        | Description                                                                          |
|-------------------------------------------------------------------------|--------------------------------------------------------------------------------------|
| public Hydra(byte[] xKey, uint rounds, IHasher hasher)                  | Instantiates a new Hydra object with user supplied xKey, rounds and hasher instance. |
| public void Encrypt(ReadOnlySpan<byte> plaintext, Span<byte> encrypted) | Encrypts a buffer.                                                                   |
| public async Task EncryptAsync(byte[] plaintext, byte[] encrypted)      | Performs CPU-bound encryption work on the thread pool.                               | 
| public void Decrypt(ReadOnlySpan<byte> encrypted, Span<byte> plaintext) | Decrypts a buffer.                                                                   |
| public async Task DecryptAsync(byte[] encrypted, byte[] plaintext)      | Performs CPU-bound decryption work on the thread pool.                               |
| public int EncryptedLen(ReadOnlySpan<byte> plaintext)                   | Computes the resulting ciphertext length from the given plaintext.                   |
| public int PlaintextLen(ReadOnlySpan<byte> encrypted)                   | Computes the resulting plaintext length from the given ciphertext.                   |

Plugging-in additional hashing schemes is as simple as implementing the ```IHasher``` interface.

## Examples

- See tests.

## Installation

Install with NuGet Package Manager Console
```
Install-Package GoeaLabs.Hydra
```

Install with .NET CLI
```
dotnet add package GoeaLabs.Hydra
```
