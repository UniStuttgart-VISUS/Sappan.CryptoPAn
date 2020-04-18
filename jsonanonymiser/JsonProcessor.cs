// <copyright file="JsonProcessor.cs" company="Universität Stuttgart">
// Copyright © 2020 SAPPAN Consortium. All rights reserved.
// </copyright>
// <author>Christoph Müller</author>

using Sappan.CryptoPAn;
using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Threading.Tasks;

namespace Sappan.JsonAnyonmiser {

    /// <summary>
    /// Implements the processing of the JSON data of a single file.
    /// </summary>
    internal sealed class JsonProcessor {

        /// <summary>
        /// Initialises a new instance.
        /// </summary>
        /// <param name="configuration"></param>
        /// <param name="anonymiser"></param>
        /// <param name="stringScrambler"></param>
        /// <param name="writer"></param>
        public JsonProcessor(Configuration configuration,
                Anonymiser anonymiser, StringScrambler stringScrambler,
                TextWriter writer) {
            this._anonymiser = anonymiser
                ?? throw new ArgumentNullException(nameof(anonymiser));
            this._configuration = configuration
                ?? throw new ArgumentNullException(nameof(configuration));
            this._stringScrambler = stringScrambler
                ?? throw new ArgumentNullException(nameof(stringScrambler));
            this._writer = writer;
        }

        /// <summary>
        /// Process the JSON file at <paramref name="inputPath"/> and store the
        /// anonymised version to <paramref name="outputPath"/>.
        /// </summary>
        /// <param name="inputPath"></param>
        /// <param name="outputPath"></param>
        /// <returns></returns>
        public async Task ProcessAsync(string inputPath, string outputPath) {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Perform the configured transforms.
        /// </summary>
        /// <returns></returns>
        public async Task ProcessAsync() {
            if (Directory.Exists(this._configuration.SourcePath)) {
                this.WriteOutput(Properties.Resources.MsgProcessingDirectory,
                    this._configuration.SourcePath,
                    this._configuration.SearchPattern);

                var files = Directory.GetFiles(this._configuration.SourcePath,
                    this._configuration.SearchPattern);
                foreach (var f in files) {
                    await this.ProcessAsync(f, Path.GetTempFileName())
                        .ConfigureAwait(false);
                }

            } else {
                await this.ProcessAsync(this._configuration.SourcePath,
                    Path.GetTempFileName()).ConfigureAwait(false);
            }
        }

        #region Private methods
        private void WriteOutput(string output) {
            if (this._writer != null) {
                this._writer.WriteLine(output);
            }
        }

        private void WriteOutput(string format, params object[] args) {
            var msg = string.Format(CultureInfo.CurrentCulture, format, args);
            this.WriteOutput(msg);
        }
        #endregion

        #region Private fields
        /// <summary>
        /// The Crypto-PAn implementation.
        /// </summary>
        private readonly Anonymiser _anonymiser;

        /// <summary>
        /// The configuration pointing towards the fields to be transformed.
        /// </summary>
        private readonly Configuration _configuration;

        /// <summary>
        /// The utility to pseudonymise strings.
        /// </summary>
        private readonly StringScrambler _stringScrambler;

        /// <summary>
        /// An optional text writer for progress messages.
        /// </summary>
        private readonly TextWriter _writer;
        #endregion
    }
}
