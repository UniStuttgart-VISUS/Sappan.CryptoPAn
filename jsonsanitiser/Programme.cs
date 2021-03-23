// <copyright file="Programme.cs" company="Universität Stuttgart">
// Copyright © 2020 SAPPAN Consortium. All rights reserved.
// </copyright>
// <author>Christoph Müller</author>

using CommandLine;
using Sappan.CryptoPAn;
using System;
using System.Text;
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
                await Parser.Default.ParseArguments<Options>(args)
                        .WithParsedAsync(async o => {
                    var output = o.IsVerbose ? Console.Out : null;
                    var config = await Configuration.Load(o.Configuration, output)
                        .ConfigureAwait(false);

                    using (var anonymiser = new Anonymiser(config.CryptoPAnKey))
                    using (var scrambler = new StringScrambler(config.StringCryptoKey)) {
                        var processor = new JsonProcessor(config, anonymiser,
                            scrambler, output);

                        if (o.IsStandardInput) {
                            string l;
                            var sb = new StringBuilder();

                            while (((l = Console.ReadLine()) != null)
                                    && (l != string.Empty)) {
                                sb.Append(l);
                            }

                            Console.WriteLine(processor.ProcessRecord(sb.ToString()));
                        } else {
                            await processor.ProcessAsync().ConfigureAwait(false);
                        }
                    }
                });


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
