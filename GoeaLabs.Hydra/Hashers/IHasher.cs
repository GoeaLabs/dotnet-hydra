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

namespace GoeaLabs.Crypto;

/// <summary>
/// AEAD interface.
/// </summary>
public interface IHasher
{
    /// <summary>
    /// Key length in <see cref="byte"/>(s).
    /// </summary>
    public int KeyLen { get; }
    
    /// <summary>
    /// Signature length in <see cref="byte"/>(s).
    /// </summary>
    public int SigLen { get; }

    /// <summary>
    /// Computes the signature of the source data.
    /// </summary>
    /// <param name="src">Span to hash.</param>
    /// <param name="key">Key to hash with.</param>
    /// <param name="sig">Resulting signature.</param>
    public void Compute(ReadOnlySpan<byte> src, ReadOnlySpan<byte> key, Span<byte> sig);
}