// <copyright file="Programme.cs" company="Universität Stuttgart">
// Copyright © 2020 SAPPAN Consortium. All rights reserved.
// </copyright>
// <author>Christoph Müller</author>

using Sappan.CryptoPAn;
using System;
#if DEBUG
using System.Diagnostics;
#endif // DEBUG
using System.Threading.Tasks;


namespace Sappan.JsonSanitiser {

    /// <summary>
    /// Container for the entry point of the application.
    /// </summary>
    internal sealed class Programme {

        /// <summary>
        /// The entry point of the application.
        /// </summary>
        /// <param name="args">The command line arguments.</param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design",
            "CA1031:Do not catch general exception types",
            Justification = "Transform any uncaught error into message at top level.")]
        internal static async Task<int> Main(string[] args) {
            try {
                if ((args == null) || (args.Length < 1)) {
                    throw new ArgumentException(
                        Properties.Resources.ErrorConfigMissing,
                        nameof(args));
                }

                var output = args.Length > 1 ? null : Console.Out;
                var config = await Configuration.Load(args[0], output)
                    .ConfigureAwait(false);

                using (var anonymiser = new Anonymiser(config.CryptoPAnKey))
                using (var scrambler = new StringScrambler(config.StringCryptoKey)) {
                    var processor = new JsonProcessor(config, anonymiser,
                        scrambler, output);

                    if (args.Length > 1) {
                        Console.WriteLine(processor.ProcessRecord(args[1]));
                    } else {
                        await processor.ProcessAsync().ConfigureAwait(false);
                    }
                }

                return 0;
            } catch (Exception ex) {
#if DEBUG
                if (Debugger.IsAttached) {
                    Debugger.Break();
                }
#endif // DEBUG
                Console.Error.WriteLine(ex.Message);
                return -1;
            }
        }
    }
}
