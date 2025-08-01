using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace ProcessInjection.Native
{
    public static class Structs
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ANSI_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public UIntPtr UniqueProcessId;
            public int InheritedFromUniqueProcessId;

            public int Size => Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION));
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IO_STATUS_BLOCK
        {
            public IntPtr Status;
            public IntPtr Information;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OSVERSIONINFOEX
        {
            public uint OSVersionInfoSize;
            public uint MajorVersion;
            public uint MinorVersion;
            public uint BuildNumber;
            public uint PlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string CSDVersion;
            public ushort ServicePackMajor;
            public ushort ServicePackMinor;
            public ushort SuiteMask;
            public byte ProductType;
            public byte Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LIST_ENTRY
        {
            public IntPtr Flink;
            public IntPtr Blink;
        }


        // Kernel32

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_IMPORT_DESCRIPTOR
        {
            public uint OriginalFirstThunk;
            public uint TimeDateStamp;
            public uint ForwarderChain;
            public uint Name;
            public uint FirstThunk;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public uint cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttributes;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdErr;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }



        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct LARGE_INTEGER
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_INFO
        {
            public uint dwOem;
            public uint dwPageSize;
            public IntPtr lpMinAppAddress;
            public IntPtr lpMaxAppAddress;
            public IntPtr dwActiveProcMask;
            public uint dwNumProcs;
            public uint dwProcType;
            public uint dwAllocGranularity;
            public ushort wProcLevel;
            public ushort wProcRevision;
        }

        // https://github.com/ricardojoserf/GetModuleHandleRemote/blob/279f04f94a1d2b4343ba134194ee6af5afd28bab/GetModuleHandleRemote/Program.cs#L15C116-L15C128
        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct COPYDATASTRUCT
        {
            public IntPtr dwData;
            public uint cbData;
            public IntPtr lpData;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PEB
        {
            public byte InheritedAddressSpace;
            public byte ReadImageFileExecOptions;
            public byte BeingDebugged;
            public byte BitField;
            public IntPtr Mutant;
            public IntPtr ImageBaseAddress;
            public IntPtr Ldr;
            public IntPtr ProcessParameters;
            public IntPtr SubSystemData;
            public IntPtr ProcessHeap;
            public IntPtr FastPebLock;
            public IntPtr AtlThunkSListPtr;
            public IntPtr IFEOKey;
            public uint CrossProcessFlags;
            public IntPtr KernelCallbackTable; // Offset 0x58 for x64
                                               // Other fields omitted
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERNELCALLBACKTABLE
        {
            public IntPtr __fnCOPYDATA;
            // Other fields omitted (undocumented structure)
        }
    }
}
