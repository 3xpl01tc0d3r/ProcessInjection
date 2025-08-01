using System;
using System.Runtime.InteropServices;
using static ProcessInjection.Native.Enum;
using static ProcessInjection.Native.Structs;

namespace ProcessInjection.Native
{
    public static class Win32API
    {
        [DllImport("Kernel32", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("Kernel32", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("Kernel32", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [MarshalAs(UnmanagedType.AsAny)] object lpBuffer, uint nSize, ref uint lpNumberOfBytesWritten);

        [DllImport("Kernel32", SetLastError = true)]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, ref uint lpThreadId);

        [DllImport("Kernel32", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("Kernel32", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        #region DLL Injection
        [DllImport("kernel32", SetLastError = true)]
        public static extern IntPtr GetModuleHandleA(string lpModuleName);

        [DllImport("kernel32", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        #endregion DLL Injection

        #region Process Hollowing
        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern int ZwCreateSection(ref IntPtr section, uint desiredAccess, IntPtr pAttrs, ref LARGE_INTEGER pMaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile);

        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern void GetSystemInfo(ref SYSTEM_INFO lpSysInfo);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern int ZwMapViewOfSection(IntPtr section, IntPtr process, ref IntPtr baseAddr, IntPtr zeroBits, IntPtr commitSize, IntPtr stuff, ref IntPtr viewSize, int inheritDispo, uint alloctype, uint prot);

        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, IntPtr nSize, out IntPtr lpNumWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint ResumeThread(IntPtr hThread);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern int ZwUnmapViewOfSection(IntPtr hSection, IntPtr address);

        [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        public static extern bool CreateProcess(IntPtr lpApplicationName, string lpCommandLine, IntPtr lpProcAttribs, IntPtr lpThreadAttribs, bool bInheritHandles, uint dwCreateFlags, IntPtr lpEnvironment, IntPtr lpCurrentDir, [In] ref STARTUPINFO lpStartinfo, out PROCESS_INFORMATION lpProcInformation);

        [DllImport("kernel32.dll")]
        public static extern uint GetLastError();
        #endregion Process Hollowing


        #region Parent PID Spoofing
        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetHandleInformation(IntPtr hObject, HANDLE_FLAGS dwMask, HANDLE_FLAGS dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle, ref IntPtr lpTargetHandle, uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);
        #endregion Parent PID Spoofing

        #region APC Injection
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

        #endregion APC Injection


        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        #region KernelCallBackTableInjection
        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern NTSTATUS NtQueryInformationProcess(IntPtr ProcessHandle, int ProcessInformationClass, IntPtr ProcessInformation, int ProcessInformationLength, out int ReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, int nSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint dwFreeType);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, ref COPYDATASTRUCT lParam);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint WaitForInputIdle(IntPtr hProcess, uint dwMilliseconds);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

        public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        #endregion KernelCallBackTableInjection

        [DllImport("kernel32", SetLastError = true)]
        public static extern IntPtr LoadLibraryA(string lpFileName);

    }


}
