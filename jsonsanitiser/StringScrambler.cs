// <copyright file="StringScrambler.cs" company="Universität Stuttgart">
// Copyright © 2020 SAPPAN Consortium. All rights reserved.
// </copyright>
// <author>Christoph Müller</author>

using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;


namespace Sappan.JsonSanitiser {

    /// <summary>
    /// Utility class for pseudonymising strings using an AES encryptor with a
    /// user-defined key as the one-way function.
    /// </summary>
    internal sealed class StringScrambler : IDisposable {

        #region Public class fields
        /// <summary>
        /// The size of the AES key in bytes.
        /// </summary>
        public const int KeySize = 32;
        #endregion

        #region Public constructor
        /// <summary>
        /// Initialises a new instance.
        /// </summary>
        /// <param name="key"></param>
        /// <exception cref="ArgumentNullException">If <paramref name="key"/>
        /// is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">If <paramref name="key"/>
        /// is too short for <see cref="KeySize"/>.</exception>
        public StringScrambler(string key) {
            if (key == null) {
                throw new ArgumentNullException(nameof(key));
            }

            var keyBytes = Encoding.ASCII.GetBytes(key);
            if (keyBytes.Length < KeySize) {
                var msg = Properties.Resources.ErrorKeyTooShort;
                msg = string.Format(CultureInfo.CurrentCulture, msg,
                    KeySize);
                throw new ArgumentException(msg);
            }

            // Prepare the AES algorithm.
            this._cryptoAlgorithm = Aes.Create();
            this._cryptoAlgorithm.KeySize = KeySize * 8;
            this._cryptoAlgorithm.Key = keyBytes.Take(KeySize).ToArray();
            // Note: we want the same input to produce the same scrambled
            // output, wherefore we need to use a deterministic IV.
            this._cryptoAlgorithm.IV = keyBytes.Take(
                this._cryptoAlgorithm.BlockSize / 8).ToArray();

            this._cryptoTransform = this._cryptoAlgorithm.CreateEncryptor();
        }
        #endregion

        #region Finaliser
        /// <summary>
        /// Finalises the instance.
        /// </summary>
        ~StringScrambler() {
            this.Dispose(false);
        }
        #endregion

        #region Public methods
        /// <inheritdoc />
        public void Dispose() {
            this.Dispose(true);
             GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Hash the given string with the configured encryption key and return
        /// the scrambled version of the same length.
        /// </summary>
        /// <param name="input">The input string.</param>
        /// <param name="alphabet">The alphabet used for the output.</param>
        /// <param name="lengthScale">A scaling factor for the output length.
        /// This defaults to 1.</param>
        /// <returns>A scrambled string.</returns>
        public string Scramble(string input, string alphabet,
                float lengthScale = 1.0f) {
            if (input == null) {
                return null;
            }
            if (input.Length == 0) {
                return string.Empty;
            }
            if (string.IsNullOrEmpty(alphabet)) {
                throw new ArgumentNullException(nameof(alphabet));
            }

            var inputBytes = Encoding.UTF8.GetBytes(input);
            var encrypted = this._cryptoTransform.TransformFinalBlock(
                inputBytes, 0, inputBytes.Length);

            // Compute what the length of the target string will be.
            var targetLength = (int) Math.Ceiling(input.Length
                * Math.Abs(lengthScale));
            if (targetLength == 0) {
                targetLength = 1;
            }

            // Merge all bytes to the target length.
            var outputBytes = new byte[targetLength];
            Array.Fill(outputBytes, (byte) 0);

            for (int i = 0; i < encrypted.Length; ++i) {
                outputBytes[i % outputBytes.Length] ^= encrypted[i];
            }

            // Transform the stuff using the alphabet.
            var retval = outputBytes.Aggregate(string.Empty,
                (r, b) => r += alphabet[b % alphabet.Length]);

            return retval;
        }

        /// <summary>
        /// Hash the given command line string while preserving the number
        /// of original elements.
        /// </summary>
        /// <remarks>
        /// The method honours grouping by single or double quotes like one
        /// would handle an actual command line. If the
        /// <paramref name="alphabet"/> contains reserved characters (spaces
        /// or quotes), these are removed.
        /// </remarks>
        /// <param name="input">A command line string.</param>
        /// <param name="alphabet">The alphabet used for the parts of the
        /// command line.</param>
        /// <param name="lengthScale">The scaling factor for the length of
        /// the parts of the command line. This defaults to 1.</param>
        /// <returns>A scrambled version of the dommand line.</returns>
        public string ScrambleCommandLine(string input, string alphabet,
                float lengthScale = 1.0f) {
            if (input == null) {
                return null;
            }

            // Remove reserved characters from the alphabet.
            alphabet = new string(alphabet.Except(
                new[] { ' ', '\"', '\'' }).ToArray());

            // Split the command line into its parts.
            bool inQuotes = false;
            var parts = input.SplitIf(c => {
                if ((c == '\"') || (c == '\'')) {
                    inQuotes = !inQuotes;
                }
                return (!inQuotes && char.IsWhiteSpace(c));
            }).ToArray();

            // Scramble each part separately.
            for (int i = 0; i < parts.Length; ++i) {
                parts[i] = this.Scramble(parts[i], alphabet, lengthScale);
            }

            // Recreate the command line as a single string.
            var retval = string.Join(' ', parts);

            return retval;
        }

        /// <summary>
        /// Hash the given fully-qualified domain name while keeping the
        /// subdomain structure.
        /// </summary>
        /// <param name="input">The fully-qualified domain name to scramble.
        /// </param>
        /// <param name="alphabet">The alphabet used for the parts of the
        /// domain name.</param>
        /// <param name="lengthScale">The scaling factor for the length of
        /// the parts of the domain. This defaults to 1.</param>
        /// <returns>A scrambled version of the fully-qualified domain name.
        /// </returns>
        public string ScrambleDomainName(string input, string alphabet,
                float lengthScale = 1.0f) {
            if (input == null) {
                return null;
            }

            // Remove reserved characters from the alphabet.
            alphabet = new string(alphabet.Except(
                new[] { ' ', '\"', '\'' }).ToArray());

            // Split the domain name into its parts.
            var parts = input.Split('.');

            // Scramble each part separately.
            for (int i = 0; i < parts.Length; ++i) {
                parts[i] = this.Scramble(parts[i], alphabet, lengthScale);
            }

            // Recreate the domain name from scrabled strings.
            var retval = string.Join('.', parts);

            return retval;
        }

        /// <summary>
        /// Has the given file system path while keeping the directory
        /// structure.
        /// </summary>
        /// <param name="input">The input path.</param>
        /// <param name="alphabet">The alphabet used for the parts of the
        /// path.</param>
        /// <param name="lengthScale">The scaling factor for the length of
        /// the parts of the path. This defaults to 1.</param>
        /// <returns>A scrambled version of the path.</returns>
        public string ScramblePath(string input, string alphabet,
                float lengthScale = 1.0f) {
            if (input == null) {
                return null;
            }

            // Determine what the actual separator is.
            var cntSep = input.Count(c => c == Path.DirectorySeparatorChar);
            var cntAlt = input.Count(c => c == Path.AltDirectorySeparatorChar);
            var sep = (cntAlt > cntSep)
                ? Path.AltDirectorySeparatorChar
                : Path.DirectorySeparatorChar;

            // Remove reserved characters from the alphabet.
            alphabet = new string(alphabet.Except(Path.GetInvalidPathChars()
                .Append(sep).Append(' ')).ToArray());

            // Split the domain name into its parts.
            var parts = input.Split(sep);

            // Scramble each part separately.
            for (int i = 0; i < parts.Length; ++i) {
                parts[i] = this.Scramble(parts[i], alphabet, lengthScale);
            }

            // Recreate the domain name from scrabled strings.
            var retval = string.Join(sep, parts);

            return retval;
        }
        #endregion

        #region Private methods
        private void Dispose(bool isDisposing) {
            if (this._cryptoTransform != null) {
                if (isDisposing) {
                    Debug.Assert(this._cryptoAlgorithm != null);
                    this._cryptoAlgorithm.Dispose();
                    this._cryptoTransform.Dispose();
                }

                this._cryptoAlgorithm = null;
                this._cryptoTransform = null;
            }
        }
        #endregion

        #region Private fields
        /// <summary>
        /// The cryptographic algorithm that <see cref="_cryptoTransform"/> is
        /// derived from.
        /// </summary>
        /// <returns></returns>
        private SymmetricAlgorithm _cryptoAlgorithm;

        /// <summary>
        /// The cryptographic transform used as pseudorandom function.
        /// </summary>
        private ICryptoTransform _cryptoTransform;
        #endregion
    }
}
