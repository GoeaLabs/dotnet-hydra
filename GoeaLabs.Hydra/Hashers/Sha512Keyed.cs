// ReSharper disable CheckNamespace
// ReSharper disable IdentifierTypo
// ReSharper disable CommentTypo
// ReSharper disable InconsistentNaming

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
using CommunityToolkit.Diagnostics;

namespace GoeaLabs.Crypto;

/// <summary>
/// Keyed SHA512 hasher.
/// </summary>
public class Sha512Keyed : IHasher
{
    private const int _keyLen = 128;
    
    private const int _sigLen = 64;
    
    /// <inheritdoc/>
    public int KeyLen => _keyLen;

    /// <inheritdoc/>
    public int SigLen => _sigLen;

    /// <inheritdoc/>
    public void Compute(ReadOnlySpan<byte> src, ReadOnlySpan<byte> key, Span<byte> sig)
    {
        Guard.HasSizeEqualTo(key, KeyLen);
        Guard.HasSizeEqualTo(sig, SigLen);
        
        HMACSHA512.TryHashData(key, src, sig, out var num);
    }
}