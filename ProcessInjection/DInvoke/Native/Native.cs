using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace ProcessInjection.DInvoke.Native
{
    public static class Native
    {
        public static Enum.NTSTATUS NtCreateThreadEx(ref IntPtr threadHandle, Enum.ACCESS_MASK desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool createSuspended, int stackZeroBits, int sizeOfStack, int maximumStackSize, IntPtr attributeList)
        {
            object[] funcargs =
            {
            threadHandle, desiredAccess, objectAttributes, processHandle, startAddress, parameter, createSuspended, stackZeroBits,
            sizeOfStack, maximumStackSize, attributeList
        };

            var retValue = (Enum.NTSTATUS)DynamicInvoke.DynamicApiInvoke("ntdll.dll", "NtCreateThreadEx",
                typeof(Delegates.NtCreateThreadEx), ref funcargs);

            threadHandle = (IntPtr)funcargs[0];
            return retValue;
        }

        public static Enum.NTSTATUS NtCreateSection(ref IntPtr sectionHandle, uint desiredAccess, IntPtr objectAttributes, ref ulong maximumSize, uint sectionPageProtection, uint allocationAttributes, IntPtr fileHandle)
        {
            object[] funcargs =
            {
            sectionHandle, desiredAccess, objectAttributes, maximumSize, sectionPageProtection, allocationAttributes, fileHandle
        };

            var retValue = (Enum.NTSTATUS)DynamicInvoke.DynamicApiInvoke("ntdll.dll", "NtCreateSection", typeof(Delegates.NtCreateSection), ref funcargs);

            if (retValue != Enum.NTSTATUS.Success)
                throw new InvalidOperationException("Unable to create section, " + retValue);

            sectionHandle = (IntPtr)funcargs[0];
            maximumSize = (ulong)funcargs[3];

            return retValue;
        }

        public static Enum.NTSTATUS NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr)
        {
            object[] funcargs =
            {
            hProc, baseAddr
        };

            var result = (Enum.NTSTATUS)DynamicInvoke.DynamicApiInvoke("ntdll.dll", "NtUnmapViewOfSection", typeof(Delegates.NtUnmapViewOfSection), ref funcargs);

            return result;
        }

        public static Enum.NTSTATUS NtMapViewOfSection(IntPtr sectionHandle, IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, IntPtr commitSize, IntPtr sectionOffset, ref ulong viewSize, uint inheritDisposition, uint allocationType, uint win32Protect)
        {
            object[] funcargs =
            {
            sectionHandle, processHandle, baseAddress, zeroBits, commitSize, sectionOffset, viewSize, inheritDisposition, allocationType,
            win32Protect
        };

            var retValue = (Enum.NTSTATUS)DynamicInvoke.DynamicApiInvoke("ntdll.dll", "NtMapViewOfSection", typeof(Delegates.NtMapViewOfSection), ref funcargs);

            if (retValue != Enum.NTSTATUS.Success && retValue != Enum.NTSTATUS.ImageNotAtBase)
                throw new InvalidOperationException("Unable to map view of section, " + retValue);

            baseAddress = (IntPtr)funcargs[2];
            viewSize = (ulong)funcargs[6];

            return retValue;
        }

        public static void RtlInitUnicodeString(ref Structs.UNICODE_STRING destinationString, [MarshalAs(UnmanagedType.LPWStr)] string sourceString)
        {
            object[] funcargs =
            {
            destinationString, sourceString
        };

            DynamicInvoke.DynamicApiInvoke("ntdll.dll", "RtlInitUnicodeString", typeof(Delegates.RtlInitUnicodeString), ref funcargs);

            destinationString = (Structs.UNICODE_STRING)funcargs[0];
        }

        public static Enum.NTSTATUS LdrLoadDll(IntPtr pathToFile, uint dwFlags, ref Structs.UNICODE_STRING moduleFileName, ref IntPtr moduleHandle)
        {
            object[] funcargs =
            {
            pathToFile, dwFlags, moduleFileName, moduleHandle
        };

            var retValue = (Enum.NTSTATUS)DynamicInvoke.DynamicApiInvoke("ntdll.dll", "LdrLoadDll", typeof(Delegates.LdrLoadDll), ref funcargs);

            moduleHandle = (IntPtr)funcargs[3];

            return retValue;
        }

        public static void RtlZeroMemory(IntPtr destination, int length)
        {
            object[] funcargs =
            {
            destination, length
        };

            DynamicInvoke.DynamicApiInvoke("ntdll.dll", "RtlZeroMemory", typeof(Delegates.RtlZeroMemory), ref funcargs);
        }

        public static Enum.NTSTATUS NtQueryInformationProcess(IntPtr hProcess, Enum.PROCESSINFOCLASS processInfoClass, out IntPtr pProcInfo)
        {
            int processInformationLength;
            uint retLen = 0;

            switch (processInfoClass)
            {
                case Enum.PROCESSINFOCLASS.ProcessWow64Information:
                    pProcInfo = Marshal.AllocHGlobal(IntPtr.Size);
                    RtlZeroMemory(pProcInfo, IntPtr.Size);
                    processInformationLength = IntPtr.Size;
                    break;

                case Enum.PROCESSINFOCLASS.ProcessBasicInformation:
                    var pbi = new Structs.PROCESS_BASIC_INFORMATION();
                    pProcInfo = Marshal.AllocHGlobal(Marshal.SizeOf(pbi));
                    RtlZeroMemory(pProcInfo, Marshal.SizeOf(pbi));
                    Marshal.StructureToPtr(pbi, pProcInfo, true);
                    processInformationLength = Marshal.SizeOf(pbi);
                    break;

                default:
                    throw new InvalidOperationException($"Invalid ProcessInfoClass: {processInfoClass}");
            }

            object[] funcargs =
            {
            hProcess, processInfoClass, pProcInfo, processInformationLength, retLen
        };

            var retValue = (Enum.NTSTATUS)DynamicInvoke.DynamicApiInvoke("ntdll.dll", "NtQueryInformationProcess", typeof(Delegates.NtQueryInformationProcess), ref funcargs);

            if (retValue != Enum.NTSTATUS.Success)
                throw new UnauthorizedAccessException("Access is denied.");

            pProcInfo = (IntPtr)funcargs[2];

            return retValue;
        }

        public static bool NtQueryInformationProcessWow64Information(IntPtr hProcess)
        {
            var retValue = NtQueryInformationProcess(hProcess, Enum.PROCESSINFOCLASS.ProcessWow64Information, out var pProcInfo);

            if (retValue != Enum.NTSTATUS.Success)
                throw new UnauthorizedAccessException("Access is denied.");

            return Marshal.ReadIntPtr(pProcInfo) != IntPtr.Zero;
        }

        public static Structs.PROCESS_BASIC_INFORMATION NtQueryInformationProcessBasicInformation(IntPtr hProcess)
        {
            var retValue = NtQueryInformationProcess(hProcess, Enum.PROCESSINFOCLASS.ProcessBasicInformation, out var pProcInfo);

            if (retValue != Enum.NTSTATUS.Success)
                throw new UnauthorizedAccessException("Access is denied.");

            return (Structs.PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(pProcInfo, typeof(Structs.PROCESS_BASIC_INFORMATION));
        }

        public static IntPtr NtAllocateVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, ref IntPtr regionSize, uint allocationType, uint protect)
        {
            object[] funcargs =
            {
            processHandle, baseAddress, zeroBits, regionSize, allocationType, protect
        };

            var retValue = (Enum.NTSTATUS)DynamicInvoke.DynamicApiInvoke("ntdll.dll", "NtAllocateVirtualMemory", typeof(Delegates.NtAllocateVirtualMemory), ref funcargs);

            switch (retValue)
            {
                case Enum.NTSTATUS.AccessDenied:
                    throw new UnauthorizedAccessException("Access is denied.");
                case Enum.NTSTATUS.AlreadyCommitted:
                    throw new InvalidOperationException("The specified address range is already committed.");
                case Enum.NTSTATUS.CommitmentLimit:
                    throw new InvalidOperationException("Your system is low on virtual memory.");
                case Enum.NTSTATUS.ConflictingAddresses:
                    throw new InvalidOperationException("The specified address range conflicts with the address space.");
                case Enum.NTSTATUS.InsufficientResources:
                    throw new InvalidOperationException("Insufficient system resources exist to complete the API call.");
                case Enum.NTSTATUS.InvalidHandle:
                    throw new InvalidOperationException("An invalid HANDLE was specified.");
                case Enum.NTSTATUS.InvalidPageProtection:
                    throw new InvalidOperationException("The specified page protection was not valid.");
                case Enum.NTSTATUS.NoMemory:
                    throw new InvalidOperationException("Not enough virtual memory or paging file quota is available to complete the specified operation.");
                case Enum.NTSTATUS.ObjectTypeMismatch:
                    throw new InvalidOperationException("There is a mismatch between the type of object that is required by the requested operation and the type of object that is specified in the request.");
            }

            if (retValue != Enum.NTSTATUS.Success)
                throw new InvalidOperationException("An attempt was made to duplicate an object handle into or out of an exiting process.");

            baseAddress = (IntPtr)funcargs[1];
            return baseAddress;
        }

        public static void NtFreeVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize, uint freeType)
        {
            object[] funcargs =
            {
            processHandle, baseAddress, regionSize, freeType
        };

            var retValue = (Enum.NTSTATUS)DynamicInvoke.DynamicApiInvoke("ntdll.dll", "NtFreeVirtualMemory", typeof(Delegates.NtFreeVirtualMemory), ref funcargs);

            switch (retValue)
            {
                case Enum.NTSTATUS.AccessDenied:
                    throw new UnauthorizedAccessException("Access is denied.");
                case Enum.NTSTATUS.InvalidHandle:
                    throw new InvalidOperationException("An invalid HANDLE was specified.");
            }

            if (retValue != Enum.NTSTATUS.Success)
                throw new InvalidOperationException("There is a mismatch between the type of object that is required by the requested operation and the type of object that is specified in the request.");
        }

        public static uint NtProtectVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize, uint newProtect)
        {
            uint oldProtect = 0;
            object[] funcargs =
            {
            processHandle, baseAddress, regionSize, newProtect, oldProtect
        };

            var retValue = (Enum.NTSTATUS)DynamicInvoke.DynamicApiInvoke("ntdll.dll", "NtProtectVirtualMemory", typeof(Delegates.NtProtectVirtualMemory), ref funcargs);

            if (retValue != Enum.NTSTATUS.Success)
                throw new InvalidOperationException("Failed to change memory protection, " + retValue);

            oldProtect = (uint)funcargs[4];
            return oldProtect;
        }

        public static uint NtWriteVirtualMemory(IntPtr processHandle, IntPtr baseAddress, IntPtr buffer, uint bufferLength)
        {
            uint bytesWritten = 0;
            object[] funcargs =
            {
            processHandle, baseAddress, buffer, bufferLength, bytesWritten
        };

            var retValue = (Enum.NTSTATUS)DynamicInvoke.DynamicApiInvoke("ntdll.dll", "NtWriteVirtualMemory", typeof(Delegates.NtWriteVirtualMemory), ref funcargs);

            if (retValue != Enum.NTSTATUS.Success)
                throw new InvalidOperationException("Failed to write memory, " + retValue);

            bytesWritten = (uint)funcargs[4];
            return bytesWritten;
        }

        public static IntPtr LdrGetProcedureAddress(IntPtr hModule, IntPtr functionName, IntPtr ordinal, ref IntPtr functionAddress)
        {
            object[] funcargs =
            {
            hModule, functionName, ordinal, functionAddress
        };

            var retValue = (Enum.NTSTATUS)DynamicInvoke.DynamicApiInvoke("ntdll.dll", "LdrGetProcedureAddress", typeof(Delegates.LdrGetProcedureAddress), ref funcargs);

            if (retValue != Enum.NTSTATUS.Success)
                throw new InvalidOperationException("Failed get procedure address, " + retValue);

            functionAddress = (IntPtr)funcargs[3];
            return functionAddress;
        }

        public static void RtlGetVersion(ref Structs.OSVERSIONINFOEX versionInformation)
        {
            object[] funcargs =
            {
            versionInformation
        };

            var retValue = (Enum.NTSTATUS)DynamicInvoke.DynamicApiInvoke("ntdll.dll", "RtlGetVersion", typeof(Delegates.RtlGetVersion), ref funcargs);

            if (retValue != Enum.NTSTATUS.Success)
                throw new InvalidOperationException("Failed get procedure address, " + retValue);

            versionInformation = (Structs.OSVERSIONINFOEX)funcargs[0];
        }

        public static IntPtr NtOpenFile(ref IntPtr fileHandle, Enum.FileAccessFlags desiredAccess, ref Structs.OBJECT_ATTRIBUTES objectAttributes, ref Structs.IO_STATUS_BLOCK ioStatusBlock, Enum.FileShareFlags shareAccess, Enum.FileOpenFlags openOptions)
        {
            object[] funcargs =
            {
            fileHandle, desiredAccess, objectAttributes, ioStatusBlock, shareAccess, openOptions
        };

            var retValue = (Enum.NTSTATUS)DynamicInvoke.DynamicApiInvoke(@"ntdll.dll", @"NtOpenFile", typeof(Delegates.NtOpenFile), ref funcargs);

            if (retValue != Enum.NTSTATUS.Success)
                throw new InvalidOperationException("Failed to open file, " + retValue);

            fileHandle = (IntPtr)funcargs[0];
            return fileHandle;
        }
    }
}
