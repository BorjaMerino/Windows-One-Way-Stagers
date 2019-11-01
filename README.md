# One-Way shellcodes for Windows
Shellcodes for Windows that allow to reuse/rebind sockets. This is really useful for evading restrictive environments where it is not possible to obtain a reverse shell by creating a new connection. The idea of this repository is to collect functional POCs and/or new innovative techniques (apart from the [old-school techniques](http://phrack.org/issues/62/7.html): findtag, getpeername, etc.). Feel free to contribute.

* **One-Way shellcode based on socket's lifetime:** take advantage of the service timeout to extend the lifetime of the connection to make it distinguishable from others sockets. After that idle time we can use the getsockopt API along with SO_CONNECT_TIME (SOL_SOCKET option) to go through all the handles and identify the socket whose lifetime exceeds X seconds. NAT inmmune. More information: https://www.shelliscoming.com/2018/06/windows-reuse-shellcode-based-on.html

* **One-Way shellcode using Out Of Band data:** it sends Out-of-Band data (just one byte is needed) in some packet/packets just before the Stager starts to run. To find the handle the Stager would only need to bruteforce the list of posible sockets looking for the one with OOB pending to be read (by using recv with the MSG_OOB flag). NAT inmmune. More information: https://www.shelliscoming.com/2019/03/one-way-shellcode-for-firewall-evasion.html

* **Findsock (51 bytes, harcoded IAT for recv)**
Remote exploit developed by HD Moore in Veritas Backup software. Due to the space restrictions to execute code (about 50 bytes), the payload gets the recv() address from the IAT and use it to stage the rest of the payload. 
https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/backupexec/name_service.rb

* **Stealing the socket on IIS by using the built in ISAPI handler calls**
The shellcode walks up the stack looking for a valid EXTENSION_CONTROL_BLOCK structure (used by IIS and the ISAPI extension to exchange information) and from there steal the client socket.
https://cybersecpolitics.blogspot.com/2018/04/stealing-socket-for-policy-and-profit.html

# Presentations / Talks / Papers
* ** Macro-Reliability in Win32 Exploits (Black-Hat Europe, 2007)**
https://www.blackhat.com/presentations/bh-europe-07/Kortchinsky/Presentation/bh-eu-07-kortchinsky.pdf

* ** Advances in Windows Shellcode (Phrack 62, 2004)**
http://phrack.org/issues/62/7.html

* ** Win32 Assembly Components (LSD-PL, 2002)**
https://web.archive.org/web/20161107193740/http://www.lsd-pl.net/winasm-slides.pdf

* ** Win32 One-Way Shellcode (Black-Hat Asia, 2003)**
https://www.blackhat.com/presentations/bh-asia-03/bh-asia-03-chong.pdf
