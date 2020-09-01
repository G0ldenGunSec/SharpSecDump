using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace SharpSecDump
{
    //code to query a service and parse the resulting struct (https://docs.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-query_service_configa)
    //struct is passed back to us as a combo of int values + pointers to the locations of the strings
    //this class is based on example code found here: http://www.pinvoke.net/default.aspx/advapi32/queryserviceconfig.html
    class QueryService
    {
        public static ServiceInfo serviceInfo;
        public QueryService(IntPtr qscPtr)
        {
            QueryServiceConfigStruct qscs = new QueryServiceConfigStruct();
            qscs = (QueryServiceConfigStruct)
                    Marshal.PtrToStructure(qscPtr,
                    new QueryServiceConfigStruct().GetType());

            serviceInfo = new ServiceInfo();
            serviceInfo.binaryPathName =
            Marshal.PtrToStringAuto(qscs.binaryPathName);
            serviceInfo.dependencies =
            Marshal.PtrToStringAuto(qscs.dependencies);
            serviceInfo.displayName =
            Marshal.PtrToStringAuto(qscs.displayName);
            serviceInfo.loadOrderGroup =
            Marshal.PtrToStringAuto(qscs.loadOrderGroup);
            serviceInfo.startName =
            Marshal.PtrToStringAuto(qscs.startName);

            serviceInfo.errorControl = qscs.errorControl;
            serviceInfo.serviceType = qscs.serviceType;
            serviceInfo.startType = qscs.startType;
            serviceInfo.tagID = qscs.tagID;

            Marshal.FreeCoTaskMem(qscPtr);
        }

        public string getStartName()
        {
            return serviceInfo.startName;
        }
        public int getStartType()
        {
            return serviceInfo.startType;
        }



        [StructLayout(LayoutKind.Sequential)]
        private struct QueryServiceConfigStruct
        {
            public int serviceType;
            public int startType;
            public int errorControl;
            public IntPtr binaryPathName;
            public IntPtr loadOrderGroup;
            public int tagID;
            public IntPtr dependencies;
            public IntPtr startName;
            public IntPtr displayName;
        }
        public struct ServiceInfo
        {
            public int serviceType;
            public int startType;
            public int errorControl;
            public string binaryPathName;
            public string loadOrderGroup;
            public int tagID;
            public string dependencies;
            public string startName;
            public string displayName;
        }


    }
}
