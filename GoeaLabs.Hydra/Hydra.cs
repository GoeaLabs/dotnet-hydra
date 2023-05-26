// ReSharper disable CheckNamespace
// ReSharper disable IdentifierTypo
// ReSharper disable CommentTypo
// ReSharper disable InconsistentNaming
// ReSharper disable MemberCanBePrivate.Global

/*
   Copyright 2023, GoeaLabs

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using CommunityToolkit.Diagnostics;
using GoeaLabs.Bedrock.Extensions;

namespace GoeaLabs.Crypto;

[SkipLocalsInit]
public class Hydra
{
    /// <summary>
    /// Wether we are running in the browser.
    /// </summary>
    private static readonly OSPlatform WebAssembly = OSPlatform.Create("WEBASSEMBLY");
    
    /// <summary>
    /// Key length in bytes.
    /// </summary>
    public const int KeyLen = 32;
    
    /// <summary>
    /// <see cref="IHasher"/> implementation.
    /// </summary>
    public IHasher Hasher { get; }
    
    /// <summary>
    /// Number of <see cref="Chaos"/> rounds to apply.
    /// </summary>
    public uint Rounds { get; }
    
    /// <summary>
    /// Secret key.
    /// </summary>
    public byte[] Secret { get; }
    
    /// <summary>
    /// Instantiates a new instance of Hydra.
    /// </summary>
    /// <param name="secret">Secret key.</param>
    /// <param name="rounds">Number of rounds.</param>
    /// <param name="hasher">Hashing engine.</param>
    /// <exception cref="ArgumentException">
    /// If <paramref name="secret"/> length is not equal to <see cref="KeyLen"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// If <paramref name="rounds"/> is not greater than or equal to 20 and even.
    /// </exception>
    public Hydra(byte[] secret, uint rounds, IHasher hasher)
    {
        Guard.HasSizeEqualTo(secret, KeyLen);
        
        if (rounds < 20 || rounds % 2 > 0)
            ThrowHelper.ThrowArgumentException(nameof(rounds), 
                "Must be greater than or equal to 20 and even.");
        
        Secret = secret;
        Rounds = rounds;
        Hasher = hasher;
    }
    
    /// <summary>
    /// XORs each byte from <see cref="source"/> buffer and
    /// writes the results to <see cref="output"/> buffer.
    /// </summary>
    /// <param name="kernel">Chaos seed.</param>
    /// <param name="source">Source buffer.</param>
    /// <param name="output">Output buffer.</param>
    private void Xor(Span<uint> kernel, ReadOnlySpan<byte> source, Span<byte> output)
    {
        Span<byte> buffer = stackalloc byte[(int)BlockLength.WhenInt8];
        
        (ulong Pebble, ulong Stream) locale = (0, 1);
        
        var n = -1;
        var m = source.Length - 1;

        do
        {
            Chaos.LoadBytes(buffer, kernel, ref locale, Rounds);
            
            foreach (var member in buffer)
            {
                n += 1;
                output[n] = (byte)(source[n] ^ member);

                if (n == m)
                    break;
            }
            
        } while (n != m);
    }

    /// <summary>
    /// Given a plaintext buffer, computes the necessary length of the encrypted buffer.
    /// </summary>
    /// <param name="plaintext">The buffer to compute for.</param>
    /// <returns>The length of the encrypted buffer.</returns>
    /// <exception cref="ArgumentException">
    /// If <paramref name="plaintext"/> buffer length is not greater than 0.
    /// </exception>
    public int EncryptedLen(ReadOnlySpan<byte> plaintext)
    {
        Guard.HasSizeGreaterThan(plaintext, 0);
        return KeyLen + Hasher.SigLen + plaintext.Length;
    }
    
    /// <summary>
    /// Given an encrypted buffer, computes the necessary length of the plaintext buffer.
    /// </summary>
    /// <param name="encrypted">The buffer to compute for.</param>
    /// <returns>The length of the plaintext buffer.</returns>
    /// <exception cref="ArgumentException">
    /// If <paramref name="encrypted"/> buffer length is not greater than 0.
    /// </exception>
    public int PlaintextLen(ReadOnlySpan<byte> encrypted)
    {
        var len = encrypted.Length - KeyLen - Hasher.SigLen;

        if (len < 1)
            ThrowHelper.ThrowArgumentException("Minimum buffer length is 1.", nameof(encrypted));

        return len;
    }

    /// <summary>
    /// Encrypts a buffer using the given nonce.
    /// </summary>
    /// <param name="nonce">Random nonce.</param>
    /// <param name="plaintext">Plaintext buffer.</param>
    /// <param name="encrypted">Encrypted buffer.</param>
    /// <exception cref="ArgumentException">
    /// If <paramref name="plaintext"/> buffer length is not greater than 0.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// If <paramref name="encrypted"/> buffer length is not large enough to accomodate the
    /// encrypted data.
    /// </exception>
    internal void Encrypt(Span<byte> nonce, ReadOnlySpan<byte> plaintext, Span<byte> encrypted)
    {
        Guard.HasSizeEqualTo(encrypted, EncryptedLen(plaintext));
        
        var nonceSlice = encrypted[..KeyLen];
        var signatureSlice = encrypted[KeyLen..(KeyLen + Hasher.SigLen)];
        var ciphertextSlice = encrypted[(KeyLen + Hasher.SigLen)..];
        
        // Copy nonce key to output
        nonce.CopyTo(nonceSlice);

        // Compute actual encryption key bytes
        nonce.Xor(Secret);

        // Compute uint encryption key (Chaos kernel)
        Span<uint> encryptionKey = stackalloc uint[Chaos.KernelLen];
        nonce.Merge(encryptionKey);
        
        // Encrypt plaintext
        Xor(encryptionKey, plaintext, ciphertextSlice);
        
        // Produce all the bytes necessary for hashing key (optional) and signature encryption key 
        Span<byte> hashingKeys = stackalloc byte[Hasher.KeyLen + Hasher.SigLen];
        Chaos.LoadBytes(hashingKeys, encryptionKey, new Locale(0, 0), Rounds);
        
        // Assign hashing key bytes
        var hashingKey = Hasher.KeyLen > 0 ? hashingKeys[..Hasher.KeyLen] : Span<byte>.Empty;
        // Assign signature encryption key bytes
        var signatureKey = Hasher.KeyLen > 0 ? hashingKeys[Hasher.KeyLen..] : hashingKeys;
        
        // Compute signature and write it to output
        Hasher.Compute(ciphertextSlice, hashingKey, signatureSlice);
        
        // Encrypt signature
        signatureSlice.Xor(signatureKey);
    }

    /// <summary>
    /// Encrypts a buffer.
    /// </summary>
    /// <param name="plaintext">Plaintext buffer.</param>
    /// <param name="encrypted">Encrypted buffer.</param>
    /// <exception cref="ArgumentException">
    /// If <paramref name="plaintext"/> buffer length is
    /// not greater than 0.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// If <paramref name="encrypted"/> buffer length is
    /// not large enough to accomodate the encrypted data.
    /// </exception>
    public void Encrypt(ReadOnlySpan<byte> plaintext, Span<byte> encrypted)
    {
        Span<byte> nonce = stackalloc byte[KeyLen];
        nonce.FillRandom();
        
        Encrypt(nonce, plaintext, encrypted);
    }
    
    /// <summary>
    /// Encrypts a buffer.
    /// </summary>
    /// <param name="plaintext">Plaintext buffer.</param>
    /// <param name="encrypted">Encrypted buffer.</param>
    /// <exception cref="ArgumentException">
    /// If <paramref name="plaintext"/> buffer length is
    /// not greater than 0.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// If <paramref name="encrypted"/> buffer length is
    /// not large enough to accomodate the encrypted data.
    /// </exception>
    /// <remarks>
    /// Performs CPU bound work on the thread pool, except
    /// for WEBASSEMBLY where it runs synchronously.
    /// </remarks>
    public async Task EncryptAsync(byte[] plaintext, byte[] encrypted)
    {
        if (RuntimeInformation.IsOSPlatform(WebAssembly))
        {
            Encrypt(plaintext, encrypted);
        }
        else
        {
            await Task.Run(() => Encrypt(plaintext, encrypted)).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Decrypts a buffer.
    /// </summary>
    /// <param name="encrypted">Encrypted buffer.</param>
    /// <param name="plaintext">Plaintext buffer.</param>
    /// <exception cref="ArgumentException">
    /// If <paramref name="encrypted"/> buffer length is
    /// invalid.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// If <paramref name="plaintext"/> buffer length is
    /// not large enough to accomodate the decrypted data.
    /// </exception>
    /// <exception cref="CryptographicException">
    /// If the signature of <see cref="encrypted"/> buffer
    /// cannot be verified.
    /// </exception>
    public void Decrypt(ReadOnlySpan<byte> encrypted, Span<byte> plaintext)
    {
        Guard.HasSizeEqualTo(plaintext, PlaintextLen(encrypted));
        
        var nonceSlice = encrypted[..KeyLen];
        var signatureSlice = encrypted[KeyLen..(KeyLen + Hasher.SigLen)];
        var ciphertextSlice = encrypted[(KeyLen + Hasher.SigLen)..];
        
        // Extract nonce bytes from ciphertext
        Span<byte> nonce = stackalloc byte[KeyLen];
        
        // Compute uint encryption key from nonce bytes and secret key
        nonceSlice.CopyTo(nonce);
        nonce.Xor(Secret);
        Span<uint> encryptionKey = stackalloc uint[Chaos.KernelLen];
        nonce.Merge(encryptionKey);
        
        // Extract encrypted signature bytes
        Span<byte> signature = stackalloc byte[Hasher.SigLen];
        signatureSlice.CopyTo(signature);
        
        // Produce all the bytes necessary for optional hashing key and signature encryption key 
        Span<byte> hashingKeys = stackalloc byte[Hasher.KeyLen + Hasher.SigLen];
        Chaos.LoadBytes(hashingKeys, encryptionKey, new Locale(0, 0), Rounds);

        // Decrypt signature
        signature.Xor(Hasher.KeyLen > 0 ? hashingKeys[Hasher.KeyLen..] : hashingKeys);
        
        // Assign optional hashing key
        var hashingKey = Hasher.KeyLen > 0 ? hashingKeys[..Hasher.KeyLen] : Span<byte>.Empty;
        
        // Compute ciphertext signature
        Span<byte> computedSignature = stackalloc byte[Hasher.SigLen];
        Hasher.Compute(ciphertextSlice, hashingKey, computedSignature);

        // Abort if signature does not match
        if (!signature.SequenceEqual(computedSignature))
            throw new CryptographicException("Failed signature verification.");
        
        // Decrypt ciphertext
        Xor(encryptionKey, ciphertextSlice, plaintext);
    }

    /// <summary>
    /// Decrypts a buffer.
    /// </summary>
    /// <param name="encrypted">Encrypted buffer.</param>
    /// <param name="plaintext">Plaintext buffer.</param>
    /// <exception cref="ArgumentException">
    /// If <paramref name="encrypted"/> buffer length is
    /// invalid.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// If <paramref name="plaintext"/> buffer length is
    /// not large enough to accomodate the decrypted data.
    /// </exception>
    /// <exception cref="CryptographicException">
    /// If the signature of <see cref="encrypted"/> buffer
    /// cannot be verified.
    /// </exception>
    /// <remarks>
    /// Performs CPU bound work on the thread pool, except
    /// for WEBASSEMBLY where it runs synchronously.
    /// </remarks>
    public async Task DecryptAsync(byte[] encrypted, byte[] plaintext)
    {
        if (RuntimeInformation.IsOSPlatform(WebAssembly))
        {
            Decrypt(encrypted, plaintext);
        }
        else
        {
            await Task.Run(() => Decrypt(encrypted, plaintext)).ConfigureAwait(false);
        }
    }
}