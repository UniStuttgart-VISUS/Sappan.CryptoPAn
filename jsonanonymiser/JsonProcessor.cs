// <copyright file="JsonProcessor.cs" company="Universität Stuttgart">
// Copyright © 2020 SAPPAN Consortium. All rights reserved.
// </copyright>
// <author>Christoph Müller</author>

using Sappan.CryptoPAn;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;


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
