﻿// <copyright file="Configuration.cs" company="Universität Stuttgart">
// Copyright © 2020 SAPPAN Consortium. All rights reserved.
// </copyright>
// <author>Christoph Müller</author>

using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;


namespace Sappan.JsonSanitiser {

    /// <summary>
    /// Defines the structure of the JSON configuration file.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance",
        "CA1812:Avoid uninstantiated internal classes",
        Justification = "Instantiated during JSON deserialisation.")]
    internal sealed class Configuration {

        #region Nested class StringPseudonymisation
        /// <summary>
        /// Groups the settings for the pseudonymisation of a specific class of
        /// strings.
        /// </summary>
        internal sealed class StringPseudonymisation {

            /// <summary>
            /// Gets or sets the characters being used for pseudonymising the
            /// strings.
            /// </summary>
            /// <remarks>
            /// If this alphabet is smaller thatn 256 elements, the mapping
            /// function is surjective.
            /// </remarks>
            public string Alphabet { get; set; } = new string(
                Enumerable.Range(32, 126 - 32)
                .Select(c => Convert.ToChar(c))
                .ToArray());

            /// <summary>
            /// Gets or sets the JSONPath expressions to the fields that should be
            /// scrambled.
            /// </summary>
            /// <remarks>
            /// <para>The paths are relative to a single record, ie line or JSON
            /// array element.</para>
            /// </remarks>
            public IEnumerable<string> Paths { get; set; }
                = Enumerable.Empty<string>();

            /// <summary>
            /// Gets or sets a scaling factor for the length of the strings.
            /// </summary>
            public float Scaling { get; set; } = 1.0f;
        }
        #endregion

        #region Public class methods
        /// <summary>
        /// Loads the configuration file from the specified path.
        /// </summary>
        /// <remarks>
        /// This method also performs sanity checks like whether the source data
        /// exist and initialises missing random members.
        /// </remarks>
        /// <param name="path">The path to the configuration file.</param>
        /// <param name="writer">An optional <see cref="TextWriter"/> to write
        /// status messages to.</param>
        /// <returns>The configuration stored in the specified configuration
        /// file.</returns>
        public static async Task<Configuration> Load(string path,
                TextWriter writer = null) {
            var config = await File.ReadAllTextAsync(path)
                .ConfigureAwait(false);
            var retval = JsonConvert.DeserializeObject<Configuration>(config);

            if (!File.Exists(path) && !Directory.Exists(path)) {
                var msg = Properties.Resources.ErrorSourceMissing;
                msg = string.Format(CultureInfo.CurrentCulture, msg,
                    path ?? string.Empty);
                throw new ArgumentException(msg);
            }

            if (string.IsNullOrEmpty(retval.CryptoPAnKey)) {
                if (writer != null) {
                    var msg = Properties.Resources.MsgGenerateCryptoPAnKey;
                    writer.WriteLine(msg);
                }
                retval.CryptoPAnKey = GenerateKey(32);
            }

            if (string.IsNullOrEmpty(retval.StringCryptoKey)) {
                if (writer != null) {
                    var msg = Properties.Resources.MsgGenerateStringKey;
                    writer.WriteLine(msg);
                }
                retval.StringCryptoKey = GenerateKey(StringScrambler.KeySize);
            }

            if (writer != null) {
                {
                    var msg = Properties.Resources.MsgSourcePath;
                    msg = string.Format(CultureInfo.CurrentCulture, msg,
                        retval.SourcePath);
                    writer.WriteLine(msg);
                }
                {
                    var msg = Properties.Resources.MsgCryptoPAnKey;
                    msg = string.Format(CultureInfo.CurrentCulture, msg,
                        retval.CryptoPAnKey);
                    writer.WriteLine(msg);
                }
                {
                    var msg = Properties.Resources.MsgStringCryptoKey;
                    msg = string.Format(CultureInfo.CurrentCulture, msg,
                        retval.StringCryptoKey);
                    writer.WriteLine(msg);
                }
            }

            return retval;
        }
        #endregion

        #region Public properties
        /// <summary>
        /// Gets or sets the string pseudonymisation settings for command lines.
        /// </summary>
        public StringPseudonymisation CommandLineFields { get; set; }
            = new StringPseudonymisation();

        /// <summary>
        /// Gets or sets the key used for the Crypto-PAn algorithm.
        /// </summary>
        /// <remarks>
        /// If this property is <c>null</c> or empty, a new random key will be
        /// generated once the programme is started.
        /// </remarks>
        public string CryptoPAnKey { get; set; }

        /// <summary>
        /// Gets or sets the suffix added to the anonymised files if
        /// <see cref="Inline"/> is <c>false</c>.
        /// </summary>
        public string DestinationSuffix { get; set; } = ".anon";

        /// <summary>
        /// Gets or sets the string pseudonymisation settings for domain names.
        /// </summary>
        public StringPseudonymisation DomainNameFields { get; set; }
            = new StringPseudonymisation() {
                Alphabet = "abcdefghijklmnopqrstuvqxyz0123456789-"
            };

        /// <summary>
        /// Gets or sets the JSONPath expression to fields that should be
        /// completely removed from the output.
        /// </summary>
        /// <remarks>
        /// <para>The paths are relative to a single record, ie line or JSON
        /// array element.</para>
        /// </remarks>
        public IEnumerable<string> EraseFields { get; set; }
            = Enumerable.Empty<string>();

        /// <summary>
        /// Gets or sets the string pseudonymisation settings for strings
        /// that are not scaled in length.
        /// </summary>
        public StringPseudonymisation FixedLengthStringFields { get; set; }
            = new StringPseudonymisation();

        /// <summary>
        /// Gets or sets whether the anonymisation should be performed inline,
        /// ie the original file should be overwritten.
        /// </summary>
        public bool Inline { get; set; } = false;

        /// <summary>
        /// Gets or sets the JSONPath expressions to the fields that should be
        /// processed as <see cref="System.Net.IPAddress"/> and pseudonymised
        /// using <see cref="Sappan.CryptoPAn.Anonymiser"/>.
        /// </summary>
        /// <remarks>
        /// <para>The paths are relative to a single record, ie line or JSON
        /// array element.</para>
        /// </remarks>
        public IEnumerable<string> IPAddressFields { get; set; }
            = Enumerable.Empty<string>();

        /// <summary>
        /// Gets or sets whether line-by-line processing of JSON records should
        /// be enabled.
        /// </summary>
        /// <remarks>
        /// Setting this property to <c>true</c> can speed-up the processing
        /// significantly provided you know that you have this format as it
        /// prevents the tool from probing the content for a JSON array.
        /// </remarks>
        public bool LineByLine { get; set; } = false;

        /// <summary>
        /// Gets or sets the JSONPath expressions to the fields that should be
        /// processed as MAC addresses and pseudonymised using
        /// <see cref="Sappan.CryptoPAn.Anonymiser"/>.
        /// </summary>
        /// <remarks>
        /// <para>The paths are relative to a single record, ie line or JSON
        /// array element.</para>
        /// <para>MAC addresses are expected to be given in the typical
        /// hexadecimal string representations. These strings will be converted
        /// to byte arrays and pseudonymised using Crypto-PAn, which will
        /// preserve the information about devices from the same vendors.</para>
        /// </remarks>
        public IEnumerable<string> MacAddressFields { get; set; }
            = Enumerable.Empty<string>();

        /// <summary>
        /// Gets or sets the string pseudonymisation settings for file system
        /// paths.
        /// </summary>
        public StringPseudonymisation PathFields { get; set; }
            = new StringPseudonymisation();

        /// <summary>
        /// Gets or sets whether subfolders of <see cref="SourcePath"/> should
        /// be processed recursively.
        /// </summary>
        public bool Recurse { get; set; } = false;

        /// <summary>
        /// Gets or sets the string pseudonymisation settings for strings
        /// scaled in length.
        /// </summary>
        public StringPseudonymisation ScaledStringFields { get; set; }
            = new StringPseudonymisation();

        /// <summary>
        /// Gets or sets the search pattern for the files in
        /// <see cref="SourcePath"/>.
        /// </summary>
        /// <remarks>
        /// This property has no effect if <see cref="SourcePath"/> designates a
        /// file rather than a directory.
        /// </remarks>
        public string SearchPattern { get; set; } = "*";

        /// <summary>
        /// Gets or sets the path to the file or directory to be processed.
        /// </summary>
        /// <remarks>
        /// If the property designates a directory, all files in that directory
        /// will be processed. If it designates a file, only that file is
        /// processed.
        /// </remarks>
        public string SourcePath { get; set; }

        /// <summary>
        /// Gets or sets the key used to create the one-time-pad for scrambling
        /// strings.
        /// </summary>
        /// <remarks>
        /// If this property is <c>null</c> or empty, a new random key will be
        /// generated once the programme is started.
        /// </remarks>
        public string StringCryptoKey { get; set; }
        #endregion

        #region Private methods
        /// <summary>
        /// Generates a sequence of <paramref name="length"/> random ASCII
        /// characters.
        /// </summary>
        /// <param name="length"></param>
        /// <returns></returns>
        private static string GenerateKey(int length) {
            Debug.Assert(length > 0);
            using (var rng = new RNGCryptoServiceProvider()) {
                var bytes = new byte[1];
                var data = new char[length];

                for (int i = 0; i < data.Length; ++i) {
                    rng.GetNonZeroBytes(bytes);
                    if ((bytes[0] >= 0x20) && (bytes[0] <= 0x7e)) {
                        data[i] = (char) bytes[0];
                    } else {
                        --i;
                    }
                }

                return new string(data);
            }
        }
        #endregion
    }
}
