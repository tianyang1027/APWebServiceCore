namespace Microsoft.Bing.Multimedia.APWebServiceCore
{
    using System;
    using System.IO;
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.Extensions.Configuration;
    using Microsoft.Search.Autopilot;
    using Microsoft.Search.Autopilot.Security;

    public class Service<T>
        where T : ServiceStartup
    {
        private readonly string _environment;

        public Service()
        {
            _environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
            if (!string.IsNullOrEmpty(_environment))
                _environment = _environment.Trim();

            if (File.Exists("../autopilot.ini"))
            {
                APRuntime.Initialize();

                if (string.IsNullOrEmpty(_environment))
                    _environment = APRuntime.EnvironmentName;
            }
            else
            {
                Console.Error.WriteLine("Could not find autopilot.ini, defaulting to non-autopilot environment.");

                if (string.IsNullOrEmpty(_environment))
                    _environment = "Development";
            }

            Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", _environment);
        }

        public static void Main() => new Service<T>().Run();

        public X509Certificate2 GetMachineCertificate()
        {
            if (APRuntime.IsInitialized)
                return ApPkiClient.ApLookupLocalCert(ApAuthType.Client, ApLookupFlags.MfCertOnly);

            return null;
        }

        public void Run()
        {
            Console.WriteLine($"ASPNETCORE_ENVIRONMENT=\"{_environment}\"");

            var config = new ConfigurationBuilder()
               .SetBasePath(Directory.GetCurrentDirectory())
               .AddJsonFile("hosting.json", optional: false)
               .AddJsonFile($"hosting.{_environment}.json", optional: true)
               .Build();

            Start(config.Get<ServerOptions>());
        }

        private static bool TryParseHostname(string hostname, out IPAddress address)
        {
            if (string.Equals(hostname, "localhost", StringComparison.OrdinalIgnoreCase))
            {
                address = IPAddress.Loopback;
                return true;
            }

            if (string.Equals(hostname, "any", StringComparison.OrdinalIgnoreCase))
            {
                address = IPAddress.Any;
                return true;
            }

            return IPAddress.TryParse(hostname, out address);
        }

        private static X509Certificate2 LoadUnencryptedCertificate(string pfxFilename, string passwordFilename)
        {
            var certBytes = File.ReadAllBytes(pfxFilename);
            var password = File.ReadAllText(passwordFilename).Trim();

            return new X509Certificate2(certBytes, password, X509KeyStorageFlags.PersistKeySet);
        }

        private static X509Certificate2 LoadEncryptedCertificate(string pfxFilename, string passwordFilename)
        {
            var certBytes = File.ReadAllBytes(pfxFilename);
            var passwordBytes = File.ReadAllBytes(passwordFilename);

            using (var protect = new ApSecretProtection())
            {
                certBytes = protect.Decrypt(certBytes);
                passwordBytes = protect.Decrypt(passwordBytes);
            }

            // Rely on StreamReader's capability to detect encoding instead of using a fixed one
            // (this is equivalent of what File.ReadAllText does)
            string password;
            using (var reader = new StreamReader(new MemoryStream(passwordBytes)))
                password = reader.ReadToEnd().Trim();

            return new X509Certificate2(certBytes, password, X509KeyStorageFlags.PersistKeySet);
        }

        private static void RegisterCertificate(X509Certificate2 certificate)
        {
            var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);

            store.Open(OpenFlags.ReadWrite);

            try
            {
                store.Add(certificate);
            }
            finally
            {
                store.Close();
            }
        }

        private void Start(ServerOptions options)
        {
            X509Certificate2 certificate = null;
            if (!string.IsNullOrEmpty(options.CertificatePath) && !string.IsNullOrEmpty(options.PrivateKeyPasswordPath))
            {
                if (options.ApEncrypted)
                {
                    if (!APRuntime.IsInitialized)
                        Console.Error.WriteLine("Cannot decrypt certificate with SecretStore API because autopilot environment is not initialized.");
                    else
                        certificate = LoadEncryptedCertificate(options.CertificatePath, options.PrivateKeyPasswordPath);
                }
                else
                {
                    certificate = LoadUnencryptedCertificate(options.CertificatePath, options.PrivateKeyPasswordPath);
                }

                if (certificate != null)
                    RegisterCertificate(certificate);
            }

            var host = new WebHostBuilder()
                .UseKestrel(o =>
                {
                    foreach (var endpoint in options.Endpoints)
                    {
                        if (!TryParseHostname(endpoint.Host, out IPAddress address))
                            continue;

                        if (endpoint.Scheme == Uri.UriSchemeHttp)
                            o.Listen(address, endpoint.Port);
                        else if (endpoint.Scheme == Uri.UriSchemeHttps && certificate != null)
                            o.Listen(address, endpoint.Port, l => l.UseHttps(certificate));
                    }
                })
                .UseContentRoot(Directory.GetCurrentDirectory())
                .UseStartup<T>()
                .Build();

            host.Run();
        }
    }
}
