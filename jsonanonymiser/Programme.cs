// <copyright file="Programme.cs" company="Universität Stuttgart">
// Copyright © 2020 SAPPAN Consortium. All rights reserved.
// </copyright>
// <author>Christoph Müller</author>

using System;
using System.Threading.Tasks;


namespace Sappan.JsonAnyonmiser {

    /// <summary>
    /// Container for the entry point of the application.
    /// </summary>
    internal sealed class Programme {

        /// <summary>
        /// The entry point of the application.
        /// </summary>
        /// <param name="args">The command line arguments.</param>
        internal static async Task<int> Main(string[] args) {
            try {
                if ((args == null) || (args.Length < 1)) {
                    throw new ArgumentException(
                        Properties.Resources.ErrorConfigMissing,
                        nameof(args));
                }

                var config = await Configuration.Load(args[0]);


                return 0;
            } catch (Exception ex) {
                Console.Error.WriteLine(ex.Message);
                return -1;
            }
        }
    }
}
