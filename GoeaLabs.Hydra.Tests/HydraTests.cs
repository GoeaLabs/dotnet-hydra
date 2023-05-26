// ReSharper disable IdentifierTypo
// ReSharper disable CommentTypo
// ReSharper disable CheckNamespace

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

using System.Security.Cryptography;

namespace GoeaLabs.Crypto.Tests;

[TestClass]
public class HydraTests
{
    private const int CiphertextNKeyOffset = 0;
    
    private const int CiphertextNKeyCount = 32;
    
    private const int CiphertextSignatureOffset = 32;
    
    private const int CiphertextSignatureCount = 32;
    
    
    private static readonly IHasher Sha256PlainHasher = new Sha256Plain();

    private static readonly IHasher Sha256KeyedHasher = new Sha256Keyed();
    
    private static readonly IHasher Sha384PlainHasher = new Sha384Plain();

    private static readonly IHasher Sha384KeyedHasher = new Sha384Keyed();
    
    private static readonly IHasher Sha512PlainHasher = new Sha512Plain();

    private static readonly IHasher Sha512KeyedHasher = new Sha512Keyed();
    

    private static readonly Hydra HydraSha256Plain = 
        new (TestVectors.SKey, TestVectors.Rounds, Sha256PlainHasher);
    
    private static readonly Hydra HydraSha256Keyed = 
        new (TestVectors.SKey, TestVectors.Rounds, Sha256KeyedHasher);
    
    private static readonly Hydra HydraSha384Plain = 
        new (TestVectors.SKey, TestVectors.Rounds, Sha384PlainHasher);
    
    private static readonly Hydra HydraSha384Keyed = 
        new (TestVectors.SKey, TestVectors.Rounds, Sha384KeyedHasher);
    
    private static readonly Hydra HydraSha512Plain = 
        new (TestVectors.SKey, TestVectors.Rounds, Sha512PlainHasher);
    
    private static readonly Hydra HydraSha512Keyed = 
        new (TestVectors.SKey, TestVectors.Rounds, Sha512KeyedHasher);
    
    
    [TestMethod]
    [DataRow(Hydra.KeyLen - 1, TestVectors.Rounds)]
    [DataRow(Hydra.KeyLen + 1, TestVectors.Rounds)]
    [ExpectedException(typeof(ArgumentException))]
    public void Constructor_throws_ArgumentException_if_incorrect_key_length(int length, uint rounds) =>
        _ = new Hydra(new byte[length], rounds, Sha256PlainHasher);

    [TestMethod]
    [DataRow((uint)19)]
    [DataRow((uint)21)]
    [ExpectedException(typeof(ArgumentException))]
    public void Constructor_throws_ArgumentException_if_incorrect_number_of_rounds(uint rounds) =>
        _ = new Hydra(TestVectors.SKey, rounds, Sha256PlainHasher);

    [TestMethod]
    [ExpectedException(typeof(ArgumentException))]
    public void Encrypt_throws_ArgumentException_if_plaintext_buffer_is_not_minimum_1_byte_length() =>
        HydraSha256Plain.Encrypt(Span<byte>.Empty, Span<byte>.Empty);

    [TestMethod]
    public void Encrypt_does_not_throw_if_plaintext_buffer_is_minimum_1_byte_length()
    {
        Span<byte> plaintext = stackalloc byte[1];
        Span<byte> encrypted = stackalloc byte[HydraSha256Plain.EncryptedLen(plaintext)];

        var throws = false;

        try
        {
            HydraSha256Plain.Encrypt(plaintext, encrypted);
        }
        catch (ArgumentException)
        {
            throws = true;
        }
        
        Assert.IsFalse(throws);
    }

    // Correct length is 65 (32 + 32 + 1)
    [TestMethod]
    [DataRow(64)]
    [DataRow(66)]
    [ExpectedException(typeof(ArgumentException))]
    public void Encrypt_throws_ArgumentException_if_encrypted_buffer_is_not_of_correct_length(int wrongLen)
    {
        Span<byte> plaintext = stackalloc byte[1];
        Span<byte> encrypted = stackalloc byte[wrongLen];
        
        HydraSha256Plain.Encrypt(plaintext, encrypted);
    }
    
    [TestMethod]
    public void Encrypt_does_not_throw_if_encrypted_buffer_is_of_correct_length()
    {
        Span<byte> plaintext = stackalloc byte[1];
        Span<byte> encrypted = stackalloc byte[HydraSha256Plain.EncryptedLen(plaintext)];

        var throws = false;

        try
        {
            HydraSha256Plain.Encrypt(plaintext, encrypted);
        }
        catch (ArgumentException)
        {
            throws = true;
        }
        
        Assert.IsFalse(throws);
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentException))]
    public void EncryptedLen_throws_ArgumentException_if_buffer_length_is_zero() =>
        HydraSha256Plain.EncryptedLen(Span<byte>.Empty);

    [TestMethod]
    [DataRow(1, 65)]
    [DataRow(100, 164)]
    public void EncryptedLen_behaves_correctly(int length, int correct)
    {
        Span<byte> plaintext = stackalloc byte[length];
        Assert.IsTrue(HydraSha256Plain.EncryptedLen(plaintext) == correct);
    }

    [TestMethod]
    [DataRow(63)] // - 1
    [DataRow(64)] // 0
    [ExpectedException(typeof(ArgumentException))]
    public void PlaintextLen_throws_ArgumentException_if_result_is_zero_or_negative(int length) =>
        HydraSha256Plain.PlaintextLen(new byte[length]);

    [TestMethod]
    public void Hydra_Sha256Plain_encrypts_correctly()
    {
        var encrypted = new byte[HydraSha256Plain.EncryptedLen(TestVectors.PlainBytes)];
        HydraSha256Plain.Encrypt(TestVectors.NKey, TestVectors.PlainBytes, encrypted);
        
        Assert.IsTrue(TestVectors.Sha256PlainCiphertext.SequenceEqual(encrypted));
    }
    
    [TestMethod]
    public void Hydra_Sha384Plain_encrypts_correctly()
    {
        var encrypted = new byte[HydraSha384Plain.EncryptedLen(TestVectors.PlainBytes)];
        HydraSha384Plain.Encrypt(TestVectors.NKey, TestVectors.PlainBytes, encrypted);
        
        Assert.IsTrue(TestVectors.Sha384PlainCiphertext.SequenceEqual(encrypted));
    }
    
    [TestMethod]
    public void Hydra_Sha512Plain_encrypts_correctly()
    {
        var encrypted = new byte[HydraSha512Plain.EncryptedLen(TestVectors.PlainBytes)];
        HydraSha512Plain.Encrypt(TestVectors.NKey, TestVectors.PlainBytes, encrypted);
        
        Assert.IsTrue(TestVectors.Sha512PlainCiphertext.SequenceEqual(encrypted));
    }
    
    [TestMethod]
    public void Hydra_Sha256Keyed_encrypts_correctly()
    {
        var encrypted = new byte[HydraSha256Keyed.EncryptedLen(TestVectors.PlainBytes)];
        HydraSha256Keyed.Encrypt(TestVectors.NKey, TestVectors.PlainBytes, encrypted);
        
        Assert.IsTrue(TestVectors.Sha256KeyedCiphertext.SequenceEqual(encrypted));
    }

    [TestMethod]
    public void Hydra_Sha384Keyed_encrypts_correctly()
    {
        var encrypted = new byte[HydraSha384Keyed.EncryptedLen(TestVectors.PlainBytes)];
        HydraSha384Keyed.Encrypt(TestVectors.NKey, TestVectors.PlainBytes, encrypted);
        
        Assert.IsTrue(TestVectors.Sha384KeyedCiphertext.SequenceEqual(encrypted));
    }
    
    [TestMethod]
    public void Hydra_Sha512Keyed_encrypts_correctly()
    {
        var encrypted = new byte[HydraSha512Keyed.EncryptedLen(TestVectors.PlainBytes)];
        HydraSha512Keyed.Encrypt(TestVectors.NKey, TestVectors.PlainBytes, encrypted);
        
        Assert.IsTrue(TestVectors.Sha512KeyedCiphertext.SequenceEqual(encrypted));
    }
    
    [TestMethod]
    public void Hydra_Sha256Plain_decrypts_correctly()
    {
        var encrypted = new byte[HydraSha256Plain.EncryptedLen(TestVectors.PlainBytes)];
        HydraSha256Plain.Encrypt(TestVectors.NKey, TestVectors.PlainBytes, encrypted);

        var decrypted = new byte[HydraSha256Plain.PlaintextLen(encrypted)];
        HydraSha256Plain.Decrypt(encrypted, decrypted);
        
        Assert.IsTrue(TestVectors.PlainBytes.SequenceEqual(decrypted));
    }
    
    [TestMethod]
    public void Hydra_Sha384Plain_decrypts_correctly()
    {
        var encrypted = new byte[HydraSha384Plain.EncryptedLen(TestVectors.PlainBytes)];
        HydraSha384Plain.Encrypt(TestVectors.NKey, TestVectors.PlainBytes, encrypted);

        var decrypted = new byte[HydraSha384Plain.PlaintextLen(encrypted)];
        HydraSha384Plain.Decrypt(encrypted, decrypted);
        
        Assert.IsTrue(TestVectors.PlainBytes.SequenceEqual(decrypted));
    }
    
    [TestMethod]
    public void Hydra_Sha512Plain_decrypts_correctly()
    {
        var encrypted = new byte[HydraSha512Plain.EncryptedLen(TestVectors.PlainBytes)];
        HydraSha512Plain.Encrypt(TestVectors.NKey, TestVectors.PlainBytes, encrypted);

        var decrypted = new byte[HydraSha512Plain.PlaintextLen(encrypted)];
        HydraSha512Plain.Decrypt(encrypted, decrypted);
        
        Assert.IsTrue(TestVectors.PlainBytes.SequenceEqual(decrypted));
    }
    
    [TestMethod]
    public void Hydra_Sha256Keyed_decrypts_correctly()
    {
        var encrypted = new byte[HydraSha256Keyed.EncryptedLen(TestVectors.PlainBytes)];
        HydraSha256Keyed.Encrypt(TestVectors.NKey, TestVectors.PlainBytes, encrypted);

        var decrypted = new byte[HydraSha256Keyed.PlaintextLen(encrypted)];
        HydraSha256Keyed.Decrypt(encrypted, decrypted);
        
        Assert.IsTrue(TestVectors.PlainBytes.SequenceEqual(decrypted));
    }

    [TestMethod]
    public void Hydra_Sha384Keyed_decrypts_correctly()
    {
        var encrypted = new byte[HydraSha384Keyed.EncryptedLen(TestVectors.PlainBytes)];
        HydraSha384Keyed.Encrypt(TestVectors.NKey, TestVectors.PlainBytes, encrypted);

        var decrypted = new byte[HydraSha384Keyed.PlaintextLen(encrypted)];
        HydraSha384Keyed.Decrypt(encrypted, decrypted);
        
        Assert.IsTrue(TestVectors.PlainBytes.SequenceEqual(decrypted));
    }
    
    [TestMethod]
    public void Hydra_Sha512Keyed_decrypts_correctly()
    {
        var encrypted = new byte[HydraSha512Keyed.EncryptedLen(TestVectors.PlainBytes)];
        HydraSha512Keyed.Encrypt(TestVectors.NKey, TestVectors.PlainBytes, encrypted);

        var decrypted = new byte[HydraSha512Keyed.PlaintextLen(encrypted)];
        HydraSha512Keyed.Decrypt(encrypted, decrypted);
        
        Assert.IsTrue(TestVectors.PlainBytes.SequenceEqual(decrypted));
    }
    
    [TestMethod]
    [ExpectedException(typeof(CryptographicException))]
    public void Hydra_throws_CryptographicException_if_nonce_is_modified()
    {
        Span<byte> tamperedCiphertext = new byte[TestVectors.Sha256PlainCiphertext.Length];
        TestVectors.Sha256PlainCiphertext.CopyTo(tamperedCiphertext);

        var randomIndex = Chaos.NextRange(CiphertextNKeyOffset, CiphertextNKeyCount);
        tamperedCiphertext[randomIndex] = unchecked(++tamperedCiphertext[randomIndex]);
        
        HydraSha256Plain.Decrypt(
            tamperedCiphertext, 
            new byte[HydraSha256Plain.PlaintextLen(tamperedCiphertext)]);
    }
    
    [TestMethod]
    [ExpectedException(typeof(CryptographicException))]
    public void Hydra_throws_CryptographicException_if_signature_is_modified()
    {
        Span<byte> tamperedCiphertext = new byte[TestVectors.Sha256PlainCiphertext.Length];
        TestVectors.Sha256PlainCiphertext.CopyTo(tamperedCiphertext);

        var randomIndex = Chaos.NextRange(
            CiphertextSignatureOffset, 
            CiphertextSignatureOffset + 
            CiphertextSignatureCount);
        
        tamperedCiphertext[randomIndex] = unchecked(++tamperedCiphertext[randomIndex]);
        
        HydraSha256Plain.Decrypt(
            tamperedCiphertext, 
            new byte[HydraSha256Plain.PlaintextLen(tamperedCiphertext)]);
    }
    
    [TestMethod]
    [ExpectedException(typeof(CryptographicException))]
    public void Hydra_throws_CryptographicException_if_encrypted_data_is_modified()
    {
        Span<byte> tamperedCiphertext = new byte[TestVectors.Sha256PlainCiphertext.Length];
        TestVectors.Sha256PlainCiphertext.CopyTo(tamperedCiphertext);

        var randomIndex = Chaos.NextRange(
            CiphertextSignatureOffset + CiphertextSignatureCount, 
            TestVectors.Sha256PlainCiphertext.Length);
        
        tamperedCiphertext[randomIndex] = unchecked(++tamperedCiphertext[randomIndex]);
        
        HydraSha256Plain.Decrypt(
            tamperedCiphertext, 
            new byte[HydraSha256Plain.PlaintextLen(tamperedCiphertext)]);
    }
    
    
    [TestMethod]
    [Ignore]
    public void Vectos()
    {
        var a = TestVectors.SKey;
    }

}