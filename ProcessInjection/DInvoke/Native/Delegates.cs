using System;
using System.Linq;
using System.Runtime.InteropServices;

namespace ProcessInjection.DInvoke.Native
{
    public static class Delegates
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate Enum.NTSTATUS NtCreateThreadEx(
            out IntPtr threadHandle,
            Enum.ACCESS_MASK desiredAccess,
            IntPtr objectAttributes,
            IntPtr processHandle,
            IntPtr startAddress,
            IntPtr parameter,
            bool createSuspended,
            int stackZeroBits,
            int sizeOfStack,
            int maximumStackSize,
            IntPtr attributeList);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate Enum.NTSTATUS NtCreateSection(
            ref IntPtr sectionHandle,
            uint desiredAccess,
            IntPtr objectAttributes,
            ref ulong maximumSize,
            uint sectionPageProtection,
            uint allocationAttributes,
            IntPtr fileHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate Enum.NTSTATUS NtUnmapViewOfSection(
            IntPtr hProc,
            IntPtr baseAddr);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate Enum.NTSTATUS NtMapViewOfSection(
            IntPtr sectionHandle,
            IntPtr processHandle,
            out IntPtr baseAddress,
            IntPtr zeroBits,
            IntPtr commitSize,
            IntPtr sectionOffset,
            out ulong viewSize,
            uint inheritDisposition,
            uint allocationType,
            uint win32Protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint LdrLoadDll(
            IntPtr pathToFile,
            uint dwFlags,
            ref Structs.UNICODE_STRING moduleFileName,
            ref IntPtr moduleHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void RtlInitUnicodeString(
            ref Structs.UNICODE_STRING destinationString,
            [MarshalAs(UnmanagedType.LPWStr)]
            string sourceString);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void RtlZeroMemory(
            IntPtr destination,
            int length);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtQueryInformationProcess(
            IntPtr processHandle,
            Enum.PROCESSINFOCLASS processInformationClass,
            IntPtr processInformation,
            int processInformationLength,
            ref uint returnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtAllocateVirtualMemory(
            IntPtr processHandle,
            ref IntPtr baseAddress,
            IntPtr zeroBits,
            ref IntPtr regionSize,
            uint allocationType,
            uint protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtFreeVirtualMemory(
            IntPtr processHandle,
            ref IntPtr baseAddress,
            ref IntPtr regionSize,
            uint freeType);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtProtectVirtualMemory(
            IntPtr processHandle,
            ref IntPtr baseAddress,
            ref IntPtr regionSize,
            uint newProtect,
            ref uint oldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtWriteVirtualMemory(
            IntPtr processHandle,
            IntPtr baseAddress,
            IntPtr buffer,
            uint bufferLength,
            ref uint bytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint LdrGetProcedureAddress(
            IntPtr hModule,
            IntPtr functionName,
            IntPtr ordinal,
            ref IntPtr functionAddress);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint RtlGetVersion(
            ref Structs.OSVERSIONINFOEX versionInformation);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtOpenFile(
            ref IntPtr fileHandle,
            Enum.FileAccessFlags accessFlags,
            ref Structs.OBJECT_ATTRIBUTES objectAttributes,
            ref Structs.IO_STATUS_BLOCK ioStatusBlock,
            Enum.FileShareFlags shareAccess,
            Enum.FileOpenFlags openOptions);

        //[UnmanagedFunctionPointer(CallingConvention.StdCall)]
        //public delegate bool InitializeProcThreadAttributeList(
        //   IntPtr lpAttributeList,
        //   int dwAttributeCount,
        //   int dwFlags,
        //   ref IntPtr lpSize);

        //[UnmanagedFunctionPointer(CallingConvention.StdCall)]
        //public delegate bool UpdateProcThreadAttribute(
        //    IntPtr lpAttributeList,
        //    uint dwFlags,
        //    IntPtr Attribute,
        //    IntPtr lpValue,
        //    IntPtr cbSize,
        //    IntPtr lpPreviousValue,
        //    IntPtr lpReturnSize);

        //[UnmanagedFunctionPointer(CallingConvention.StdCall)]
        //public delegate bool CreateProcess(
        //    string lpApplicationName,
        //    string lpCommandLine,
        //    ref Structs.SECURITY_ATTRIBUTES lpProcessAttributes,
        //    ref Structs.SECURITY_ATTRIBUTES lpThreadAttributes,
        //    bool bInheritHandles,
        //    Enum.CreationFlags dwCreationFlags,
        //    IntPtr lpEnvironment,
        //    string lpCurrentDirectory,
        //    ref Structs.STARTUPINFOEX lpStartupInfo,
        //    out Structs.PROCESS_INFORMATION lpProcessInformation);

        //[UnmanagedFunctionPointer(CallingConvention.StdCall)]
        //public delegate bool DeleteProcThreadAttributeList(
        //    IntPtr lpAttributeList);



        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr OpenProcess(
            uint dwDesiredAccess,
            bool bInheritHandle,
            uint dwProcessId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            uint flAllocationType,
            uint flProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [MarshalAs(UnmanagedType.AsAny)] object lpBuffer,
            uint nSize,
            ref uint lpNumberOfBytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            ref uint lpThreadId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint WaitForSingleObject(
            IntPtr hHandle,
            uint dwMilliseconds);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool CloseHandle(
            IntPtr hObject);

        #region DLL Injection
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr GetModuleHandleA(
            string lpModuleName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr GetProcAddress(
            IntPtr hModule,
            string procName);
        #endregion DLL Injection

        #region Process Hollowing
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int ZwCreateSection(
            ref IntPtr section,
            uint desiredAccess,
            IntPtr pAttrs,
            ref Structs.LARGE_INTEGER pMaxSize,
            uint pageProt,
            uint allocationAttribs,
            IntPtr hFile);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void GetSystemInfo(
            ref Structs.SYSTEM_INFO lpSysInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int ZwMapViewOfSection(
            IntPtr section, 
            IntPtr process, 
            ref IntPtr baseAddr, 
            IntPtr zeroBits, 
            IntPtr commitSize, 
            IntPtr stuff, 
            ref IntPtr viewSize, 
            int inheritDispo, 
            uint alloctype, 
            uint prot);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr GetCurrentProcess();

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int ZwQueryInformationProcess(
            IntPtr hProcess, 
            int procInformationClass, 
            ref Structs.PROCESS_BASIC_INFORMATION procInformation, 
            uint ProcInfoLen, 
            ref uint retlen);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool ReadProcessMemory(
            IntPtr hProcess, 
            IntPtr lpBaseAddress, 
            [Out] byte[] lpBuffer, 
            int dwSize, 
            out IntPtr lpNumberOfBytesRead);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool WriteProcessMemoryPH(
            IntPtr hProcess, 
            IntPtr lpBaseAddress, 
            IntPtr lpBuffer, 
            IntPtr nSize, 
            out IntPtr lpNumWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint ResumeThread(
            IntPtr hThread);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int ZwUnmapViewOfSection(
            IntPtr hSection, 
            IntPtr address);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool CreateProcessPH(
            IntPtr lpApplicationName, 
            string lpCommandLine, 
            IntPtr lpProcAttribs, 
            IntPtr lpThreadAttribs, 
            bool bInheritHandles, 
            uint dwCreateFlags, 
            IntPtr lpEnvironment, 
            IntPtr lpCurrentDir, 
            [In] ref Structs.STARTUPINFO lpStartinfo, 
            out Structs.PROCESS_INFORMATION lpProcInformation);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint GetLastError();
        #endregion Process Hollowing


        #region Parent PID Spoofing
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            ref Structs.SECURITY_ATTRIBUTES lpProcessAttributes,
            ref Structs.SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            Enum.CreationFlags dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref Structs.STARTUPINFOEX lpStartupInfo,
            out Structs.PROCESS_INFORMATION lpProcessInformation);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList, 
            uint dwFlags, 
            IntPtr Attribute, 
            IntPtr lpValue, 
            IntPtr cbSize, 
            IntPtr lpPreviousValue, 
            IntPtr lpReturnSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList, 
            int dwAttributeCount, 
            int dwFlags, 
            ref IntPtr lpSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool SetHandleInformation(
            IntPtr hObject, 
            Structs.HANDLE_FLAGS dwMask, 
            Structs.HANDLE_FLAGS dwFlags);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool DuplicateHandle(
            IntPtr hSourceProcessHandle, 
            IntPtr hSourceHandle, 
            IntPtr hTargetProcessHandle, 
            ref IntPtr lpTargetHandle, 
            uint dwDesiredAccess, 
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, 
            uint dwOptions);
        #endregion Parent PID Spoofing

        #region APC Injection
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr OpenThread(
            Enum.ThreadAccess dwDesiredAccess, 
            bool bInheritHandle, 
            uint dwThreadId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr QueueUserAPC(
            IntPtr pfnAPC, 
            IntPtr hThread, 
            IntPtr dwData);

        #endregion APC Injection
    }






}
