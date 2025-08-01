using ProcessInjection.Native;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static ProcessInjection.Native.Enum;
using static ProcessInjection.Utils.Utils;
using static ProcessInjection.DInvoke.Native;

namespace ProcessInjection.DInvoke
{
    public class DynamicInvoke
    {
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate IntPtr ReadGs();

        private static byte[] _x64SyscallStub =
        {
        0x49, 0x89, 0xCA,                // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00,    // mov eax, ssn
        0x0F, 0x05,                      // syscall
        0xC3                             // ret
    };

        /// <summary>
        /// Dynamically invoke an arbitrary function from a DLL, providing its name, function prototype, and arguments.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="dllName">Name of the DLL.</param>
        /// <param name="functionName">Name of the function.</param>
        /// <param name="functionDelegateType">Prototype for the function, represented as a Delegate object.</param>
        /// <param name="parameters">Parameters to pass to the function. Can be modified if function uses call by reference.</param>
        /// <param name="canLoadFromDisk">Whether the DLL may be loaded from disk if it is not already loaded. Default is false.</param>
        /// <param name="resolveForwards">Whether or not to resolve export forwards. Default is true.</param>
        /// <returns>Object returned by the function. Must be unmarshalled by the caller.</returns>
        public static object DynamicApiInvoke(string dllName, string functionName, Type functionDelegateType, ref object[] parameters, bool canLoadFromDisk = false, bool resolveForwards = true)
        {
            var pFunction = GetLibraryAddress(dllName, functionName, canLoadFromDisk, resolveForwards);
            return DynamicFunctionInvoke(pFunction, functionDelegateType, ref parameters);
        }

        /// <summary>
        /// Dynamically invokes an arbitrary function from a pointer. Useful for manually mapped modules or loading/invoking unmanaged code from memory.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="functionPointer">A pointer to the unmanaged function.</param>
        /// <param name="functionDelegateType">Prototype for the function, represented as a Delegate object.</param>
        /// <param name="parameters">Arbitrary set of parameters to pass to the function. Can be modified if function uses call by reference.</param>
        /// <returns>Object returned by the function. Must be unmarshalled by the caller.</returns>
        public static object DynamicFunctionInvoke(IntPtr functionPointer, Type functionDelegateType, ref object[] parameters)
        {
            var funcDelegate = Marshal.GetDelegateForFunctionPointer(functionPointer, functionDelegateType);
            return funcDelegate.DynamicInvoke(parameters);
        }

        public static object DynamicAsmInvoke(byte[] asmStub, Type functionDelegateType, ref object[] parameters)
        {
            unsafe
            {
                fixed (byte* buffer = asmStub)
                {
                    var ptr = (IntPtr)buffer;
                    var size = new IntPtr(asmStub.Length);

                    var oldProtect = NtProtectVirtualMemory(new IntPtr(-1), ref ptr,
                        ref size, Constants.PAGE_EXECUTE_READWRITE);

                    var result = DynamicFunctionInvoke(ptr, functionDelegateType, ref parameters);

                    NtProtectVirtualMemory(new IntPtr(-1), ref ptr,
                        ref size, oldProtect);

                    return result;
                }
            }
        }

        /// <summary>
        /// Resolves LdrLoadDll and uses that function to load a DLL from disk.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="dllPath">The path to the DLL on disk. Uses the LoadLibrary convention.</param>
        /// <returns>IntPtr base address of the loaded module or IntPtr.Zero if the module was not loaded successfully.</returns>
        public static IntPtr LoadModuleFromDisk(string dllPath)
        {
            var uModuleName = new Structs.UNICODE_STRING();
            Native.RtlInitUnicodeString(ref uModuleName, dllPath);

            var hModule = IntPtr.Zero;
            var callResult = Native.LdrLoadDll(IntPtr.Zero, 0, ref uModuleName, ref hModule);

            if (callResult != NTSTATUS.Success || hModule == IntPtr.Zero)
                return IntPtr.Zero;

            return hModule;
        }

        /// <summary>
        /// Helper for getting the pointer to a function from a DLL loaded by the process.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="dllName">The name of the DLL (e.g. "ntdll.dll" or "C:\Windows\System32\ntdll.dll").</param>
        /// <param name="functionName">Name of the exported procedure.</param>
        /// <param name="canLoadFromDisk">Optional, indicates if the function can try to load the DLL from disk if it is not found in the loaded module list.</param>
        /// <param name="resolveForwards">Whether or not to resolve export forwards. Default is true.</param>
        /// <returns>IntPtr for the desired function.</returns>
        public static IntPtr GetLibraryAddress(string dllName, string functionName, bool canLoadFromDisk = false, bool resolveForwards = true)
        {
            var hModule = GetLoadedModuleAddress(dllName);

            if (hModule == IntPtr.Zero && canLoadFromDisk)
            {
                hModule = LoadModuleFromDisk(dllName);

                if (hModule == IntPtr.Zero)
                    throw new FileNotFoundException(dllName + ", unable to find the specified file.");
            }
            else if (hModule == IntPtr.Zero)
            {
                throw new DllNotFoundException(dllName + ", Dll was not found.");
            }

            return GetExportAddress(hModule, functionName, resolveForwards);
        }

        /// <summary>
        /// Helper for getting the pointer to a function from a DLL loaded by the process.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="dllName">The name of the DLL (e.g. "ntdll.dll" or "C:\Windows\System32\ntdll.dll").</param>
        /// <param name="ordinal">Ordinal of the exported procedure.</param>
        /// <param name="canLoadFromDisk">Optional, indicates if the function can try to load the DLL from disk if it is not found in the loaded module list.</param>
        /// <param name="resolveForwards">Whether or not to resolve export forwards. Default is true.</param>
        /// <returns>IntPtr for the desired function.</returns>
        public static IntPtr GetLibraryAddress(string dllName, short ordinal, bool canLoadFromDisk = false, bool resolveForwards = true)
        {
            var hModule = GetLoadedModuleAddress(dllName);

            if (hModule == IntPtr.Zero && canLoadFromDisk)
            {
                hModule = LoadModuleFromDisk(dllName);

                if (hModule == IntPtr.Zero)
                    throw new FileNotFoundException(dllName + ", unable to find the specified file.");
            }
            else if (hModule == IntPtr.Zero)
            {
                throw new DllNotFoundException(dllName + ", Dll was not found.");
            }

            return GetExportAddress(hModule, ordinal, resolveForwards);
        }

        /// <summary>
        /// Helper for getting the pointer to a function from a DLL loaded by the process.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="dllName">The name of the DLL (e.g. "ntdll.dll" or "C:\Windows\System32\ntdll.dll").</param>
        /// <param name="functionHash">Hash of the exported procedure.</param>
        /// <param name="key">64-bit integer to initialize the keyed hash object (e.g. 0xabc or 0x1122334455667788).</param>
        /// <param name="canLoadFromDisk">Optional, indicates if the function can try to load the DLL from disk if it is not found in the loaded module list.</param>
        /// <param name="resolveForwards">Whether or not to resolve export forwards. Default is true.</param>
        /// <returns>IntPtr for the desired function.</returns>
        public static IntPtr GetLibraryAddress(string dllName, string functionHash, long key, bool canLoadFromDisk = false, bool resolveForwards = true)
        {
            var hModule = GetLoadedModuleAddress(dllName);

            if (hModule == IntPtr.Zero && canLoadFromDisk)
            {
                hModule = LoadModuleFromDisk(dllName);

                if (hModule == IntPtr.Zero)
                    throw new FileNotFoundException(dllName + ", unable to find the specified file.");
            }
            else if (hModule == IntPtr.Zero)
            {
                throw new DllNotFoundException(dllName + ", Dll was not found.");
            }

            return GetExportAddress(hModule, functionHash, key, resolveForwards);
        }

        /// <summary>
        /// Helper for getting the base address of a module loaded by the current process. This base
        /// address could be passed to GetProcAddress/LdrGetProcedureAddress or it could be used for
        /// manual export parsing. This function uses the .NET System.Diagnostics.Process class.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="dllName">The name of the DLL (e.g. "ntdll.dll").</param>
        /// <returns>IntPtr base address of the loaded module or IntPtr.Zero if the module is not found.</returns>
        public static IntPtr GetLoadedModuleAddress(string dllName)
        {
            var process = Process.GetCurrentProcess();

            foreach (ProcessModule module in process.Modules)
            {
                if (module.ModuleName.Equals(dllName, StringComparison.OrdinalIgnoreCase))
                    return module.BaseAddress;
            }

            return IntPtr.Zero;
        }

        /// <summary>
        /// Helper for getting the base address of a module loaded by the current process. This base
        /// address could be passed to GetProcAddress/LdrGetProcedureAddress or it could be used for
        /// manual export parsing. This function uses the .NET System.Diagnostics.Process class.
        /// </summary>
        /// <param name="hashedDllName">Hash of the DLL name.</param>
        /// <param name="key">64-bit integer to initialize the keyed hash object (e.g. 0xabc or 0x1122334455667788).</param>
        /// <returns>IntPtr base address of the loaded module or IntPtr.Zero if the module is not found.</returns>
        public static IntPtr GetLoadedModuleAddress(string hashedDllName, long key)
        {
            var process = Process.GetCurrentProcess();

            foreach (ProcessModule module in process.Modules)
            {
                var hashedName = GetApiHash(module.ModuleName, key);

                if (hashedName.Equals(hashedDllName))
                    return module.BaseAddress;
            }

            return IntPtr.Zero;
        }

        /// <summary>
        /// This function uses dynamic assembly invocation to obtain a pointer to the PEB.
        /// __readgsqword(0x60) or __readfsdword(0x30)
        /// </summary>
        /// <returns>Base address of the PEB as an IntPtr.</returns>
        public static IntPtr GetPebAddress()
        {
            byte[] stub;

            if (IntPtr.Size == 8)
            {
                stub = new byte[]
                {
                0x65, 0x48, 0x8B, 0x04, 0x25, 0x60,     // mov rax, qword ptr gs:[0x60]
                0x00, 0x00, 0x00,
                0xc3                                    // ret
                };
            }
            else
            {
                stub = new byte[]
                {
                0x64, 0xA1, 0x30, 0x00, 0x00, 0x00,     // mov eax,dword ptr fs:[30]
                0xC3                                    // ret
                };
            }

            var parameters = Array.Empty<object>();

            return (IntPtr)DynamicAsmInvoke(
                stub,
                typeof(ReadGs),
                ref parameters);
        }

        /// <summary>
        /// Helper for getting the base address of a module loaded by the current process. This base
        /// address could be passed to GetProcAddress/LdrGetProcedureAddress or it could be used for
        /// manual export parsing. This function parses the _PEB_LDR_DATA structure.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="dllName">The name of the DLL (e.g. "ntdll.dll").</param>
        /// <returns>IntPtr base address of the loaded module or IntPtr.Zero if the module is not found.</returns>
        public static IntPtr GetPebLdrModuleEntry(string dllName)
        {
            // Set function variables
            uint ldrDataOffset;
            uint inLoadOrderModuleListOffset;

            if (IntPtr.Size == 4)
            {
                ldrDataOffset = 0xc;
                inLoadOrderModuleListOffset = 0xC;
            }
            else
            {
                ldrDataOffset = 0x18;
                inLoadOrderModuleListOffset = 0x10;
            }

            // Get _PEB pointer
            var pPeb = GetPebAddress();

            // Get module InLoadOrderModuleList -> _LIST_ENTRY
            var pebLdrData = Marshal.ReadIntPtr((IntPtr)((ulong)pPeb + ldrDataOffset));
            var pInLoadOrderModuleList = (IntPtr)((ulong)pebLdrData + inLoadOrderModuleListOffset);
            var le = (Structs.LIST_ENTRY)Marshal.PtrToStructure(pInLoadOrderModuleList, typeof(Structs.LIST_ENTRY));

            // Loop entries
            var flink = le.Flink;
            var hModule = IntPtr.Zero;
            var dte = (PE.LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(flink, typeof(PE.LDR_DATA_TABLE_ENTRY));
            while (dte.InLoadOrderLinks.Flink != le.Blink)
            {
                // Match module name
                var moduleName = Marshal.PtrToStringUni(dte.BaseDllName.Buffer);
                if (!string.IsNullOrWhiteSpace(moduleName) && moduleName.Equals(dllName, StringComparison.OrdinalIgnoreCase))
                {
                    hModule = dte.DllBase;
                    break;
                }

                // Move Ptr
                flink = dte.InLoadOrderLinks.Flink;
                dte = (PE.LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(flink, typeof(PE.LDR_DATA_TABLE_ENTRY));
            }

            return hModule;
        }

        /// <summary>
        /// Get a syscall stub for the given Nt* API by walking the PEB to find the correct SSN.
        /// The stub can be executed using DynamicAsmInvoke.
        /// x64 only.
        /// </summary>
        /// <param name="pPeb">A pointer to the PEB.</param>
        /// <param name="functionName">The function name to get the stub for (e.g. NtOpenProcess).</param>
        /// <returns>A byte[] containing the stub.</returns>
        public static byte[] GetSyscallStub(IntPtr pPeb, string functionName)
        {
            // x64 only
            if (IntPtr.Size == 4)
                return Array.Empty<byte>();

            const uint ldrDataOffset = 0x18;
            const uint inLoadOrderModuleListOffset = 0x10;

            var pebLdrData = Marshal.ReadIntPtr((IntPtr)((ulong)pPeb + ldrDataOffset));
            var pInLoadOrderModuleList = (IntPtr)((ulong)pebLdrData + inLoadOrderModuleListOffset);
            var le = Marshal.PtrToStructure<Structs.LIST_ENTRY>(pInLoadOrderModuleList);

            // loop modules
            var flink = le.Flink;

            var dte = Marshal.PtrToStructure<PE.LDR_DATA_TABLE_ENTRY>(flink);
            while (dte.InLoadOrderLinks.Flink != le.Blink)
            {
                // match module name
                var moduleName = Marshal.PtrToStringUni(dte.BaseDllName.Buffer);
                if (!string.IsNullOrWhiteSpace(moduleName) && moduleName.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase))
                {
                    var export = GetExportAddress(dte.DllBase, functionName);
                    var ssn = Marshal.ReadByte(export + 4);

                    var stub = _x64SyscallStub;
                    stub[4] = ssn;

                    return stub;
                }

                // increment ptr
                flink = dte.InLoadOrderLinks.Flink;
                dte = Marshal.PtrToStructure<PE.LDR_DATA_TABLE_ENTRY>(flink);
            }

            return Array.Empty<byte>();
        }

        /// <summary>
        /// Get a syscall stub for the given Nt* API by walking the PEB to find the correct SSN.
        /// The stub can be executed using DynamicAsmInvoke.
        /// x64 only.
        /// </summary>
        /// <param name="pPeb">A pointer to the PEB.</param>
        /// <param name="hashedFunctionName">The hashed function name to get the stub for.</param>
        /// <param name="key">64-bit integer to initialize the keyed hash object (e.g. 0xabc or 0x1122334455667788).</param>
        /// <returns>A byte[] containing the stub.</returns>
        public static byte[] GetSyscallStub(IntPtr pPeb, string hashedFunctionName, long key)
        {
            // x64 only
            if (IntPtr.Size == 4)
                return Array.Empty<byte>();

            const uint ldrDataOffset = 0x18;
            const uint inLoadOrderModuleListOffset = 0x10;

            var pebLdrData = Marshal.ReadIntPtr((IntPtr)((ulong)pPeb + ldrDataOffset));
            var pInLoadOrderModuleList = (IntPtr)((ulong)pebLdrData + inLoadOrderModuleListOffset);
            var le = Marshal.PtrToStructure<Structs.LIST_ENTRY>(pInLoadOrderModuleList);

            // loop modules
            var flink = le.Flink;

            var dte = Marshal.PtrToStructure<PE.LDR_DATA_TABLE_ENTRY>(flink);
            while (dte.InLoadOrderLinks.Flink != le.Blink)
            {
                // match module name
                var moduleName = Marshal.PtrToStringUni(dte.BaseDllName.Buffer);
                if (!string.IsNullOrWhiteSpace(moduleName) && moduleName.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase))
                {
                    var export = GetExportAddress(dte.DllBase, hashedFunctionName, key);
                    var ssn = Marshal.ReadByte(export + 4);

                    var stub = _x64SyscallStub;
                    stub[4] = ssn;

                    return stub;
                }

                // increment ptr
                flink = dte.InLoadOrderLinks.Flink;
                dte = Marshal.PtrToStructure<PE.LDR_DATA_TABLE_ENTRY>(flink);
            }

            return Array.Empty<byte>();
        }

        /// <summary>
        /// Given a module base address, resolve the address of a function by manually walking the module export table.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="moduleBase">A pointer to the base address where the module is loaded in the current process.</param>
        /// <param name="exportName">The name of the export to search for (e.g. "NtAlertResumeThread").</param>
        /// <param name="resolveForwards">Whether or not to resolve export forwards. Default is true.</param>
        /// <returns>IntPtr for the desired function.</returns>
        public static IntPtr GetExportAddress(IntPtr moduleBase, string exportName, bool resolveForwards = true)
        {
            var functionPtr = IntPtr.Zero;

            try
            {
                // Traverse the PE header in memory
                var peHeader = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + 0x3C));
                var optHeader = moduleBase.ToInt64() + peHeader + 0x18;
                var magic = Marshal.ReadInt16((IntPtr)optHeader);
                long pExport;

                if (magic == 0x010b) pExport = optHeader + 0x60;
                else pExport = optHeader + 0x70;

                var exportRva = Marshal.ReadInt32((IntPtr)pExport);
                var ordinalBase = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x10));
                var numberOfNames = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x18));
                var functionsRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x1C));
                var namesRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x20));
                var ordinalsRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x24));

                for (var i = 0; i < numberOfNames; i++)
                {
                    var functionName = Marshal.PtrToStringAnsi((IntPtr)(moduleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + namesRva + i * 4))));
                    if (string.IsNullOrWhiteSpace(functionName)) continue;
                    if (!functionName.Equals(exportName, StringComparison.OrdinalIgnoreCase)) continue;

                    var functionOrdinal = Marshal.ReadInt16((IntPtr)(moduleBase.ToInt64() + ordinalsRva + i * 2)) + ordinalBase;

                    var functionRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + functionsRva + 4 * (functionOrdinal - ordinalBase)));
                    functionPtr = (IntPtr)((long)moduleBase + functionRva);

                    if (resolveForwards)
                        functionPtr = GetForwardAddress(functionPtr);

                    break;
                }
            }
            catch
            {
                throw new InvalidOperationException("Failed to parse module exports.");
            }

            if (functionPtr == IntPtr.Zero)
                throw new MissingMethodException(exportName + ", export not found.");

            return functionPtr;
        }

        /// <summary>
        /// Given a module base address, resolve the address of a function by manually walking the module export table.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="moduleBase">A pointer to the base address where the module is loaded in the current process.</param>
        /// <param name="ordinal">The ordinal number to search for (e.g. 0x136 -> ntdll!NtCreateThreadEx).</param>
        /// <param name="resolveForwards">Whether or not to resolve export forwards. Default is true.</param>
        /// <returns>IntPtr for the desired function.</returns>
        public static IntPtr GetExportAddress(IntPtr moduleBase, short ordinal, bool resolveForwards = true)
        {
            var functionPtr = IntPtr.Zero;

            try
            {
                var peHeader = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + 0x3C));
                var optHeader = moduleBase.ToInt64() + peHeader + 0x18;
                var magic = Marshal.ReadInt16((IntPtr)optHeader);
                long pExport;

                if (magic == 0x010b) pExport = optHeader + 0x60;
                else pExport = optHeader + 0x70;

                var exportRva = Marshal.ReadInt32((IntPtr)pExport);
                var ordinalBase = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x10));
                var numberOfNames = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x18));
                var functionsRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x1C));
                var ordinalsRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x24));

                for (var i = 0; i < numberOfNames; i++)
                {
                    var functionOrdinal = Marshal.ReadInt16((IntPtr)(moduleBase.ToInt64() + ordinalsRva + i * 2)) + ordinalBase;

                    if (functionOrdinal != ordinal) continue;

                    var functionRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + functionsRva + 4 * (functionOrdinal - ordinalBase)));
                    functionPtr = (IntPtr)((long)moduleBase + functionRva);

                    if (resolveForwards)
                        functionPtr = GetForwardAddress(functionPtr);

                    break;
                }
            }
            catch
            {
                throw new InvalidOperationException("Failed to parse module exports.");
            }

            if (functionPtr == IntPtr.Zero)
                throw new MissingMethodException(ordinal + ", ordinal not found.");

            return functionPtr;
        }

        /// <summary>
        /// Given a module base address, resolve the address of a function by manually walking the module export table.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="moduleBase">A pointer to the base address where the module is loaded in the current process.</param>
        /// <param name="functionHash">Hash of the exported procedure.</param>
        /// <param name="key">64-bit integer to initialize the keyed hash object (e.g. 0xabc or 0x1122334455667788).</param>
        /// <param name="resolveForwards">Whether or not to resolve export forwards. Default is true.</param>
        /// <returns>IntPtr for the desired function.</returns>
        public static IntPtr GetExportAddress(IntPtr moduleBase, string functionHash, long key, bool resolveForwards = true)
        {
            var functionPtr = IntPtr.Zero;

            try
            {
                var peHeader = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + 0x3C));
                var optHeader = moduleBase.ToInt64() + peHeader + 0x18;
                var magic = Marshal.ReadInt16((IntPtr)optHeader);
                long pExport;

                if (magic == 0x010b) pExport = optHeader + 0x60;
                else pExport = optHeader + 0x70;

                var exportRva = Marshal.ReadInt32((IntPtr)pExport);
                var ordinalBase = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x10));
                var numberOfNames = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x18));
                var functionsRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x1C));
                var namesRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x20));
                var ordinalsRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x24));

                for (var i = 0; i < numberOfNames; i++)
                {
                    var functionName = Marshal.PtrToStringAnsi((IntPtr)(moduleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + namesRva + i * 4))));
                    if (string.IsNullOrWhiteSpace(functionName)) continue;
                    if (!GetApiHash(functionName, key).Equals(functionHash, StringComparison.OrdinalIgnoreCase)) continue;

                    var functionOrdinal = Marshal.ReadInt16((IntPtr)(moduleBase.ToInt64() + ordinalsRva + i * 2)) + ordinalBase;

                    var functionRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + functionsRva + 4 * (functionOrdinal - ordinalBase)));
                    functionPtr = (IntPtr)((long)moduleBase + functionRva);

                    if (resolveForwards)
                        functionPtr = GetForwardAddress(functionPtr);

                    break;
                }
            }
            catch
            {
                throw new InvalidOperationException("Failed to parse module exports.");
            }

            if (functionPtr == IntPtr.Zero)
                throw new MissingMethodException(functionHash + ", export hash not found.");

            return functionPtr;
        }

        /// <summary>
        /// Check if an address to an exported function should be resolved to a forward. If so, return the address of the forward.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="exportAddress">Function of an exported address, found by parsing a PE file's export table.</param>
        /// <param name="canLoadFromDisk">Optional, indicates if the function can try to load the DLL from disk if it is not found in the loaded module list.</param>
        /// <returns>IntPtr for the forward. If the function is not forwarded, return the original pointer.</returns>
        public static IntPtr GetForwardAddress(IntPtr exportAddress, bool canLoadFromDisk = false)
        {
            var functionPtr = exportAddress;

            try
            {
                var forwardNames = Marshal.PtrToStringAnsi(functionPtr);
                if (string.IsNullOrWhiteSpace(forwardNames)) return functionPtr;

                var values = forwardNames.Split('.');

                if (values.Length > 1)
                {
                    var forwardModuleName = values[0];
                    var forwardExportName = values[1];

                    var apiSet = GetApiSetMapping();
                    var lookupKey = forwardModuleName.Substring(0, forwardModuleName.Length - 2) + ".dll";

                    if (apiSet.ContainsKey(lookupKey))
                        forwardModuleName = apiSet[lookupKey];
                    else
                        forwardModuleName = forwardModuleName + ".dll";

                    var hModule = GetPebLdrModuleEntry(forwardModuleName);

                    if (hModule == IntPtr.Zero && canLoadFromDisk)
                        hModule = LoadModuleFromDisk(forwardModuleName);

                    if (hModule != IntPtr.Zero)
                        functionPtr = GetExportAddress(hModule, forwardExportName);
                }
            }
            catch
            {
                // Do nothing, it was not a forward
            }

            return functionPtr;
        }

        /// <summary>
        /// Given a module base address, resolve the address of a function by calling LdrGetProcedureAddress.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="moduleBase">A pointer to the base address where the module is loaded in the current process.</param>
        /// <param name="exportName">The name of the export to search for (e.g. "NtAlertResumeThread").</param>
        /// <returns>IntPtr for the desired function.</returns>
        public static IntPtr GetNativeExportAddress(IntPtr moduleBase, string exportName)
        {
            var aFunc = new Structs.ANSI_STRING
            {
                Length = (ushort)exportName.Length,
                MaximumLength = (ushort)(exportName.Length + 2),
                Buffer = Marshal.StringToCoTaskMemAnsi(exportName)
            };

            var pAFunc = Marshal.AllocHGlobal(Marshal.SizeOf(aFunc));
            Marshal.StructureToPtr(aFunc, pAFunc, true);

            var pFuncAddr = IntPtr.Zero;
            Native.LdrGetProcedureAddress(moduleBase, pAFunc, IntPtr.Zero, ref pFuncAddr);

            Marshal.FreeHGlobal(pAFunc);

            return pFuncAddr;
        }

        /// <summary>
        /// Given a module base address, resolve the address of a function by calling LdrGetProcedureAddress.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="moduleBase">A pointer to the base address where the module is loaded in the current process.</param>
        /// <param name="ordinal">The ordinal number to search for (e.g. 0x136 -> ntdll!NtCreateThreadEx).</param>
        /// <returns>IntPtr for the desired function.</returns>
        public static IntPtr GetNativeExportAddress(IntPtr moduleBase, short ordinal)
        {
            var pFuncAddr = IntPtr.Zero;
            var pOrd = (IntPtr)ordinal;

            Native.LdrGetProcedureAddress(moduleBase, IntPtr.Zero, pOrd, ref pFuncAddr);

            return pFuncAddr;
        }

        /// <summary>
        /// Retrieve PE header information from the module base pointer.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="pModule">Pointer to the module base.</param>
        /// <returns>PE.PE_META_DATA</returns>
        public static PE.PE_META_DATA GetPeMetaData(IntPtr pModule)
        {
            var peMetaData = new PE.PE_META_DATA();

            try
            {
                var e_lfanew = (uint)Marshal.ReadInt32((IntPtr)((ulong)pModule + 0x3c));
                peMetaData.Pe = (uint)Marshal.ReadInt32((IntPtr)((ulong)pModule + e_lfanew));

                if (peMetaData.Pe != 0x4550)
                    throw new InvalidOperationException("Invalid PE signature.");

                peMetaData.ImageFileHeader = (PE.IMAGE_FILE_HEADER)Marshal.PtrToStructure((IntPtr)((ulong)pModule + e_lfanew + 0x4), typeof(PE.IMAGE_FILE_HEADER));

                var optHeader = (IntPtr)((ulong)pModule + e_lfanew + 0x18);
                var peArch = (ushort)Marshal.ReadInt16(optHeader);

                switch (peArch)
                {
                    case 0x010b:
                        peMetaData.Is32Bit = true;
                        peMetaData.OptHeader32 =
                            (PE.IMAGE_OPTIONAL_HEADER32)Marshal.PtrToStructure(optHeader,
                                typeof(PE.IMAGE_OPTIONAL_HEADER32));
                        break;

                    case 0x020b:
                        peMetaData.Is32Bit = false;
                        peMetaData.OptHeader64 =
                            (PE.IMAGE_OPTIONAL_HEADER64)Marshal.PtrToStructure(optHeader,
                                typeof(PE.IMAGE_OPTIONAL_HEADER64));
                        break;

                    default:
                        throw new InvalidOperationException("Invalid magic value (PE32/PE32+).");
                }

                var sectionArray = new PE.IMAGE_SECTION_HEADER[peMetaData.ImageFileHeader.NumberOfSections];

                for (var i = 0; i < peMetaData.ImageFileHeader.NumberOfSections; i++)
                {
                    var sectionPtr = (IntPtr)((ulong)optHeader + peMetaData.ImageFileHeader.SizeOfOptionalHeader + (uint)(i * 0x28));
                    sectionArray[i] = Marshal.PtrToStructure<PE.IMAGE_SECTION_HEADER>(sectionPtr);
                }

                peMetaData.Sections = sectionArray;
            }
            catch
            {
                throw new InvalidOperationException("Invalid module base specified.");
            }

            return peMetaData;
        }


        /// <summary>
        /// Resolve host DLL for API Set DLL.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec), The Wover (@TheRealWover)</author>
        /// <returns>Dictionary, a combination of Key:APISetDLL and Val:HostDLL.</returns>
        public static Dictionary<string, string> GetApiSetMapping()
        {
            var pbi = Native.NtQueryInformationProcessBasicInformation((IntPtr)(-1));
            var apiSetMapOffset = IntPtr.Size == 4 ? (uint)0x38 : 0x68;
            var apiSetDict = new Dictionary<string, string>();

            var pApiSetNamespace = Marshal.ReadIntPtr((IntPtr)((ulong)pbi.PebBaseAddress + apiSetMapOffset));
            var apiSetNamespace = (PE.ApiSetNamespace)Marshal.PtrToStructure(pApiSetNamespace, typeof(PE.ApiSetNamespace));

            for (var i = 0; i < apiSetNamespace.Count; i++)
            {
                var setEntry = new PE.ApiSetNamespaceEntry();

                var pSetEntry = (IntPtr)((ulong)pApiSetNamespace + (ulong)apiSetNamespace.EntryOffset + (ulong)(i * Marshal.SizeOf(setEntry)));
                setEntry = (PE.ApiSetNamespaceEntry)Marshal.PtrToStructure(pSetEntry, typeof(PE.ApiSetNamespaceEntry));

                var apiSetEntryName = Marshal.PtrToStringUni((IntPtr)((ulong)pApiSetNamespace + (ulong)setEntry.NameOffset), setEntry.NameLength / 2);
                var apiSetEntryKey = apiSetEntryName.Substring(0, apiSetEntryName.Length - 2) + ".dll"; // Remove the patch number and add .dll

                var valueEntry = new PE.ApiSetValueEntry();
                var pSetValue = IntPtr.Zero;

                switch (setEntry.ValueLength)
                {
                    case 1:
                        pSetValue = (IntPtr)((ulong)pApiSetNamespace + (ulong)setEntry.ValueOffset);
                        break;

                    default:
                        {
                            for (var j = 0; j < setEntry.ValueLength; j++)
                            {
                                var host = (IntPtr)((ulong)pApiSetNamespace + (ulong)setEntry.ValueOffset + (ulong)Marshal.SizeOf(valueEntry) * (ulong)j);
                                if (Marshal.PtrToStringUni(host) != apiSetEntryName)
                                    pSetValue = (IntPtr)((ulong)pApiSetNamespace + (ulong)setEntry.ValueOffset + (ulong)Marshal.SizeOf(valueEntry) * (ulong)j);
                            }

                            if (pSetValue == IntPtr.Zero)
                                pSetValue = (IntPtr)((ulong)pApiSetNamespace + (ulong)setEntry.ValueOffset);

                            break;
                        }
                }

                valueEntry = (PE.ApiSetValueEntry)Marshal.PtrToStructure(pSetValue, typeof(PE.ApiSetValueEntry));

                var apiSetValue = string.Empty;
                if (valueEntry.ValueCount != 0)
                {
                    var pValue = (IntPtr)((ulong)pApiSetNamespace + (ulong)valueEntry.ValueOffset);
                    apiSetValue = Marshal.PtrToStringUni(pValue, valueEntry.ValueCount / 2);
                }

                apiSetDict.Add(apiSetEntryKey, apiSetValue);
            }

            return apiSetDict;
        }

        /// <summary>
        /// Call a manually mapped PE by its EntryPoint.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="peInfo">Module meta data struct (PE.PE_META_DATA).</param>
        /// <param name="moduleMemoryBase">Base address of the module in memory.</param>
        /// <returns>void</returns>
        public static void CallMappedPEModule(PE.PE_META_DATA peInfo, IntPtr moduleMemoryBase)
        {
            var hRemoteThread = IntPtr.Zero;
            var lpStartAddress = peInfo.Is32Bit ? (IntPtr)((ulong)moduleMemoryBase + peInfo.OptHeader32.AddressOfEntryPoint) :
                (IntPtr)((ulong)moduleMemoryBase + peInfo.OptHeader64.AddressOfEntryPoint);

            Native.NtCreateThreadEx(
                ref hRemoteThread,
                ACCESS_MASK.STANDARD_RIGHTS_ALL,
                IntPtr.Zero, (IntPtr)(-1),
                lpStartAddress, IntPtr.Zero,
                false, 0, 0, 0, IntPtr.Zero
            );
        }

        /// <summary>
        /// Call a manually mapped DLL by DllMain -> DLL_PROCESS_ATTACH.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec), TheWover (@TheRealWover)</author>
        /// <param name="peInfo">Module meta data struct (PE.PE_META_DATA).</param>
        /// <param name="moduleMemoryBase">Base address of the module in memory.</param>
        /// <returns>void</returns>
        public static void CallMappedDLLModule(PE.PE_META_DATA peInfo, IntPtr moduleMemoryBase)
        {
            var lpEntryPoint = peInfo.Is32Bit ? (IntPtr)((ulong)moduleMemoryBase + peInfo.OptHeader32.AddressOfEntryPoint) :
                (IntPtr)((ulong)moduleMemoryBase + peInfo.OptHeader64.AddressOfEntryPoint);

            if (lpEntryPoint == moduleMemoryBase)
                return;

            var fDllMain = (PE.DllMain)Marshal.GetDelegateForFunctionPointer(lpEntryPoint, typeof(PE.DllMain));

            try
            {
                var result = fDllMain(moduleMemoryBase, PE.DLL_PROCESS_ATTACH, IntPtr.Zero);

                if (!result)
                    throw new InvalidOperationException("Call to entry point failed -> DLL_PROCESS_ATTACH");
            }
            catch
            {
                throw new InvalidOperationException("Invalid entry point -> DLL_PROCESS_ATTACH");
            }
        }

        /// <summary>
        /// Call a manually mapped DLL by Export.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="peInfo">Module meta data struct (PE.PE_META_DATA).</param>
        /// <param name="moduleMemoryBase">Base address of the module in memory.</param>
        /// <param name="exportName">The name of the export to search for (e.g. "NtAlertResumeThread").</param>
        /// <param name="functionDelegateType">Prototype for the function, represented as a Delegate object.</param>
        /// <param name="parameters">Arbitrary set of parameters to pass to the function. Can be modified if function uses call by reference.</param>
        /// <param name="callEntry">Specify whether to invoke the module's entry point.</param>
        /// <returns>void</returns>
        public static object CallMappedDLLModuleExport(PE.PE_META_DATA peInfo, IntPtr moduleMemoryBase, string exportName, Type functionDelegateType, object[] parameters, bool callEntry = true)
        {
            if (callEntry)
                CallMappedDLLModule(peInfo, moduleMemoryBase);

            var pFunc = GetExportAddress(moduleMemoryBase, exportName);
            return DynamicFunctionInvoke(pFunc, functionDelegateType, ref parameters);
        }

        /// <summary>
        /// Call a manually mapped DLL by Export.
        /// </summary>
        /// <author>The Wover (@TheRealWover), Ruben Boonen (@FuzzySec)</author>
        /// <param name="peInfo">Module meta data struct (PE.PE_META_DATA).</param>
        /// <param name="moduleMemoryBase">Base address of the module in memory.</param>
        /// <param name="ordinal">The number of the ordinal to search for (e.g. 0x07).</param>
        /// <param name="functionDelegateType">Prototype for the function, represented as a Delegate object.</param>
        /// <param name="parameters">Arbitrary set of parameters to pass to the function. Can be modified if function uses call by reference.</param>
        /// <param name="callEntry">Specify whether to invoke the module's entry point.</param>
        /// <returns>void</returns>
        public static object CallMappedDLLModuleExport(PE.PE_META_DATA peInfo, IntPtr moduleMemoryBase, short ordinal, Type functionDelegateType, object[] parameters, bool callEntry = true)
        {
            if (callEntry)
                CallMappedDLLModule(peInfo, moduleMemoryBase);

            var pFunc = GetExportAddress(moduleMemoryBase, ordinal);
            return DynamicFunctionInvoke(pFunc, functionDelegateType, ref parameters);
        }

        /// <summary>
        /// Call a manually mapped DLL by Export.
        /// </summary>
        /// <author>The Wover (@TheRealWover), Ruben Boonen (@FuzzySec)</author>
        /// <param name="peInfo">Module meta data struct (PE.PE_META_DATA).</param>
        /// <param name="moduleMemoryBase">Base address of the module in memory.</param>
        /// <param name="functionHash">Hash of the exported procedure.</param>
        /// <param name="key">64-bit integer to initialize the keyed hash object (e.g. 0xabc or 0x1122334455667788).</param>
        /// <param name="functionDelegateType">Prototype for the function, represented as a Delegate object.</param>
        /// <param name="parameters">Arbitrary set of parameters to pass to the function. Can be modified if function uses call by reference.</param>
        /// <param name="callEntry">Specify whether to invoke the module's entry point.</param>
        /// <returns>void</returns>
        public static object CallMappedDLLModuleExport(PE.PE_META_DATA peInfo, IntPtr moduleMemoryBase, string functionHash, long key, Type functionDelegateType, object[] parameters, bool callEntry = true)
        {
            if (callEntry)
                CallMappedDLLModule(peInfo, moduleMemoryBase);

            var pFunc = GetExportAddress(moduleMemoryBase, functionHash, key);
            return DynamicFunctionInvoke(pFunc, functionDelegateType, ref parameters);
        }
    }
}
