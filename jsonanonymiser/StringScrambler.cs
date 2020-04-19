// <copyright file="StringScrambler.cs" company="Universität Stuttgart">
// Copyright © 2020 SAPPAN Consortium. All rights reserved.
// </copyright>
// <author>Christoph Müller</author>

using System;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;


namespace Sappan.JsonAnyonmiser {

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
        /// <returns>A scrambled string of the same length.</returns>
        public string Scramble(string input) {
            if (input == null) {
                return null;
            }
            if (input.Length == 0) {
                return string.Empty;
            }

            var inputBytes = Encoding.UTF8.GetBytes(input);
            var encrypted = this._cryptoTransform.TransformFinalBlock(
                inputBytes, 0, inputBytes.Length);

            var outputBytes = new byte[(3 * input.Length + 4 - 1) / 4];
            Array.Fill(outputBytes, (byte) 0);

            for (int i = 0; i < encrypted.Length; ++i) {
                outputBytes[i % outputBytes.Length] ^= encrypted[i];
            }

            var retval = Convert.ToBase64String(outputBytes);
            retval = retval.Substring(0, input.Length);

            return retval;
        }

        /// <summary>
        /// Hash the given fully-qualified domain name while keeping the
        /// subdomain structure.
        /// </summary>
        /// <param name="input">The fully-qualified domain name to scramble.
        /// </param>
        /// <returns>A scrambled version of the fully-qualified domain name.
        /// </returns>
        public string ScrambleDomainName(string input) {
            if (input == null) {
                return null;
            }

            var parts = input.Split('.');

            for (int i = 0; i < parts.Length; ++i) {
                parts[i] = this.Scramble(parts[i]).Replace('.', '-');
            }

            var retval = string.Join('.', parts);

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
