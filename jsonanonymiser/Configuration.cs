// <copyright file="Configuration.cs" company="Universität Stuttgart">
// Copyright © 2020 SAPPAN Consortium. All rights reserved.
// </copyright>
// <author>Christoph Müller</author>

using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;


namespace Sappan.JsonAnyonmiser {

    /// <summary>
    /// Defines the structure of the JSON configuration file.
    /// </summary>
    internal sealed class Configuration {

        /// <summary>
        /// Loads the configuration file from the specified path.
        /// </summary>
        /// <remarks>
        /// This method also performs sanity checks like whether the source data
        /// exist and initialises missing random members.
        /// </remarks>
        /// <param name="path">The path to the configuration file.</param>
        /// <returns>The configuration stored in the specified configuration
        /// file.</returns>
        public static async Task<Configuration> Load(string path) {
            var config = await File.ReadAllTextAsync(path)
                .ConfigureAwait(false);
            var retval = JsonConvert.DeserializeObject<Configuration>(config);

            if (!File.Exists(path) && !Directory.Exists(path)) {
                var msg = Properties.Resources.ErrorSourceMissing;
                msg = string.Format(msg, path ?? string.Empty);
                throw new ArgumentException(msg);
            }

            if (string.IsNullOrEmpty(retval.CryptoPAnKey)) {
                retval.CryptoPAnKey = GenerateKey(32);
            }

            if (string.IsNullOrEmpty(retval.StringCryptoKey)) {
                retval.StringCryptoKey = GenerateKey(32);
            }

            return retval;
        }

        /// <summary>
        /// Gets or sets the key used for the Crypto-PAn algorithm.
        /// </summary>
        /// <remarks>
        /// If this property is <c>null</c> or empty, a new random key will be
        /// generated once the programme is started.
        /// </remarks>
        public string CryptoPAnKey { get; set; }

        /// <summary>
        /// Gets or sets the JSONPath expressions to the fields that should be
        /// processed as <see cref="System.Net.IPAddress"/> and pseudonymised
        /// using <see cref="Sappan.CryptoPAn.Anonymiser"/>.
        /// </summary>
        /// <remarks>
        /// The paths are relative to a single record, ie line or JSON array
        /// element.
        /// </remarks>
        public IEnumerable<string> CryptoPAnTargets { get; set; }
            = Enumerable.Empty<string>();

        /// <summary>
        /// Gets or sets whether the anonymisation should be performed inline,
        /// ie the original file should be overwritten.
        /// </summary>
        public bool Inline { get; set; } = false;

        /// <summary>
        /// Gets or sets the key used to create the one-time-pad for scrambling
        /// strings.
        /// </summary>
        /// <remarks>
        /// If this property is <c>null</c> or empty, a new random key will be
        /// generated once the programme is started.
        /// </remarks>
        public string StringCryptoKey { get; set; }

        /// <summary>
        /// Gets or sets the JSONPath expressions to the fields that should be
        /// scrambled.
        /// </summary>
        /// <remarks>
        /// The paths are relative to a single record, ie line or JSON array
        /// element.
        /// </remarks>
        public IEnumerable<string> StringCryptoTargets { get; set; }
            = Enumerable.Empty<string>();

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
    }
}
