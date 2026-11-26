using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using BlackBrowser;

namespace BlackBrowserTests
{
    internal static class SecurityRegressionTests
    {
        private static int _passed = 0;
        private static int _failed = 0;

        private static void Assert(bool condition, string name)
        {
            if (condition)
            {
                _passed++;
                Console.WriteLine("PASS: " + name);
            }
            else
            {
                _failed++;
                Console.Error.WriteLine("FAIL: " + name);
            }
        }

        private static void TestUpdaterUrlAllowlist()
        {
            Assert(UpdateManager.IsAllowedReleaseUrl("https://github.com/shivamkumarmehta64-sketch/BlackBrowser/releases/download/v9.1.0/BlackBrowser.zip"),
                "Allows official GitHub release URL");
            Assert(UpdateManager.IsAllowedReleaseUrl("https://objects.githubusercontent.com/github-production-release-asset/12345"),
                "Allows GitHub objects CDN URL");
            Assert(!UpdateManager.IsAllowedReleaseUrl("http://github.com/shivamkumarmehta64-sketch/BlackBrowser/releases/download/v9.1.0/BlackBrowser.zip"),
                "Rejects non-HTTPS release URL");
            Assert(!UpdateManager.IsAllowedReleaseUrl("https://evil.example.com/BlackBrowser.zip"),
                "Rejects untrusted host URL");
            Assert(!UpdateManager.IsAllowedReleaseUrl("https://github.com/attacker/BlackBrowser/releases/download/v9.1.0/BlackBrowser.zip"),
                "Rejects different GitHub owner URL");
            Assert(!UpdateManager.IsAllowedReleaseUrl(""),
                "Rejects empty release URL");
        }

        private static void TestManifestParsingFailClosed()
        {
            string sampleSha = new string('a', 64);
            string validManifest = sampleSha + "  BlackBrowser-v9.1.0-Windows-x64.zip\n" + new string('b', 64) + "  OtherFile.exe\n";

            Assert(UpdateManager.ParseExpectedSha256FromManifest(validManifest, "BlackBrowser-v9.1.0-Windows-x64.zip") == sampleSha,
                "Parses exact filename SHA-256 from valid manifest");
            Assert(UpdateManager.ParseExpectedSha256FromManifest("", "BlackBrowser-v9.1.0-Windows-x64.zip") == null,
                "Fails closed on empty manifest");
            Assert(UpdateManager.ParseExpectedSha256FromManifest("   \r\n  ", "BlackBrowser-v9.1.0-Windows-x64.zip") == null,
                "Fails closed on whitespace manifest");
            Assert(UpdateManager.ParseExpectedSha256FromManifest("not-a-sha256  BlackBrowser-v9.1.0-Windows-x64.zip", "BlackBrowser-v9.1.0-Windows-x64.zip") == null,
                "Fails closed on malformed SHA-256 entry");
            Assert(UpdateManager.ParseExpectedSha256FromManifest(validManifest, "MissingPackage.zip") == null,
                "Fails closed when target filename is missing from manifest");
        }

        private static void TestDownloadedPackageChecksum()
        {
            string tempFile = Path.GetTempFileName();
            try
            {
                byte[] payload = Encoding.UTF8.GetBytes("synthetic-release-package-bytes");
                File.WriteAllBytes(tempFile, payload);
                string actualSha;
                using (SHA256 sha = SHA256.Create())
                {
                    actualSha = BitConverter.ToString(sha.ComputeHash(payload)).Replace("-", "").ToLowerInvariant();
                }

                Assert(UpdateManager.VerifyDownloadedPackage(tempFile, "pkg.zip", actualSha),
                    "Accepts package when SHA-256 matches");
                Assert(!UpdateManager.VerifyDownloadedPackage(tempFile, "pkg.zip", new string('f', 64)),
                    "Rejects package on SHA-256 mismatch");
                Assert(!UpdateManager.VerifyDownloadedPackage(tempFile, "pkg.zip", ""),
                    "Rejects package when expected hash is empty");

                File.WriteAllBytes(tempFile, new byte[0]);
                Assert(!UpdateManager.VerifyDownloadedPackage(tempFile, "pkg.zip", actualSha),
                    "Rejects 0-byte package");
            }
            finally
            {
                try { if (File.Exists(tempFile)) File.Delete(tempFile); } catch { }
            }
        }

        private static void TestManifestRsaSignature()
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
            {
                string pubXml = rsa.ToXmlString(false);
                string manifest = new string('c', 64) + "  BlackBrowser.zip\n";
                byte[] sigBytes = rsa.SignData(Encoding.UTF8.GetBytes(manifest), CryptoConfig.MapNameToOID("SHA256"));
                string sigB64 = Convert.ToBase64String(sigBytes);

                Assert(UpdateManager.VerifyManifestSignature(manifest, sigB64, pubXml),
                    "Verifies valid RSA-SHA256 manifest signature");
                Assert(!UpdateManager.VerifyManifestSignature(manifest + "#tampered", sigB64, pubXml),
                    "Rejects tampered manifest against RSA-SHA256 signature");
                Assert(!UpdateManager.VerifyManifestSignature(manifest, "", pubXml),
                    "Rejects missing signature");
            }
        }

        private static void TestBootstrapperAuthenticodeFailClosed()
        {
            string unsignedTemp = Path.Combine(Path.GetTempPath(), "bf_unsigned_test_" + Guid.NewGuid().ToString("N") + ".exe");
            try
            {
                File.WriteAllBytes(unsignedTemp, Encoding.ASCII.GetBytes("MZ-unsigned-dummy"));
                string reason;
                bool ok = Program.VerifyAuthenticodePublisher(unsignedTemp, "Microsoft Corporation", out reason);
                Assert(!ok && !string.IsNullOrEmpty(reason),
                    "Rejects unsigned bootstrapper binary with explicit failure reason");

                bool missingOk = Program.VerifyAuthenticodePublisher(unsignedTemp + ".missing", "Microsoft Corporation", out reason);
                Assert(!missingOk && !string.IsNullOrEmpty(reason),
                    "Rejects missing bootstrapper binary");
            }
            finally
            {
                try { if (File.Exists(unsignedTemp)) File.Delete(unsignedTemp); } catch { }
            }
        }

        private static void TestPasswordStorageIsolation()
        {
            string testSite = "example.invalid";
            string testUser = "synthetic-user";
            string testSecret = "synthetic-non-real-token-value";
            PasswordManager.SavePassword(testSite, testUser, testSecret);
            var list = PasswordManager.GetPasswords();
            bool found = false;
            foreach (var item in list)
            {
                if (item.Site == testSite && item.Username == testUser && item.Password == testSecret)
                {
                    found = true;
                    break;
                }
            }
            Assert(found, "PasswordManager encrypts/decrypts synthetic credential round-trip");
            var exactHost = PasswordManager.GetCredentialsForHost(testSite);
            var spoofHost = PasswordManager.GetCredentialsForHost("evil-" + testSite);
            Assert(exactHost.Count >= 1 && spoofHost.Count == 0, "GetCredentialsForHost does not leak to suffix-spoofed hostnames");
            PasswordManager.RemovePassword(testSite, testUser);
        }

        public static int Main()
        {
            TestUpdaterUrlAllowlist();
            TestManifestParsingFailClosed();
            TestDownloadedPackageChecksum();
            TestManifestRsaSignature();
            TestBootstrapperAuthenticodeFailClosed();
            TestPasswordStorageIsolation();

            Console.WriteLine("Summary: " + _passed + " passed, " + _failed + " failed.");
            return _failed == 0 ? 0 : 1;
        }
    }
}
