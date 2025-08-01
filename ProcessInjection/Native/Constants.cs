using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ProcessInjection.Native
{
    public static class Constants
    {
        public const uint MEM_COMMIT = 0x1000;
        public const uint MEM_RESERVE = 0x2000;
        public const uint MEM_RELEASE = 0x8000;


        public const uint PAGE_READONLY = 0x02;
        public const uint PAGE_READWRITE = 0x04;
        public const uint PAGE_EXECUTE = 0x10;
        public const uint PAGE_EXECUTE_READ = 0x20;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;

        public const uint SEC_IMAGE = 0x1000000;


        #region PPID Spoofing

        // https://stackoverflow.com/questions/10554913/how-to-call-createprocess-with-startupinfoex-from-c-sharp-and-re-parent-the-ch
        public const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;
        public const int STARTF_USESTDHANDLES = 0x00000100;
        public const int STARTF_USESHOWWINDOW = 0x00000001;
        public const ushort SW_HIDE = 0x0000;
        public const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        public const uint CREATE_NO_WINDOW = 0x08000000;
        public const uint CreateSuspended = 0x00000004;

        #endregion PPID Spoofing


        #region Process Hollowing
        public const uint PageReadWriteExecute = 0x40;
        public const uint PageReadWrite = 0x04;
        public const uint PageExecuteRead = 0x20;
        public const uint MemCommit = 0x00001000;
        public const uint SecCommit = 0x08000000;
        public const uint GenericAll = 0x10000000;
        public const uint DetachedProcess = 0x00000008;
        public const uint CreateNoWindow = 0x08000000;
        public const ulong PatchSize = 0x10;
        public const int AttributeSize = 24;

        #endregion Process Hollowing



        public const uint CREATE_NEW_CONSOLE = 0x00000010;
        public const int ProcessBasicInformation = 0;
        public const uint WM_COPYDATA = 0x004A;
    }
}
