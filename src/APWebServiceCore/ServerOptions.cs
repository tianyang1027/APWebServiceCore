namespace Microsoft.Bing.Multimedia.APWebServiceCore
{
    using System;

    internal class ServerOptions
    {
        public Uri[] Endpoints { get; set; }

        public string CertificatePath { get; set; }

        public string PrivateKeyPasswordPath { get; set; }

        public bool ApEncrypted { get; set; }
    }
}
