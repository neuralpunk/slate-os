# SPDX-License-Identifier: MIT OR Apache-2.0
# less on a pseudo-terminal (ADR 0149): keys typed, the prompt read back.
# Run by `cargo xtask check`: python3 -I pty.py LESS WORKDIR. The prompt
# (-P) shows the top and bottom lines, so each check reads where less is.
import os, pty, re, select, struct, sys, termios, fcntl, time

LESS, WORK = os.path.abspath(sys.argv[1]), sys.argv[2]
os.chdir(WORK)
with open('nums', 'w') as f:
    f.write(''.join(f'{i}\n' for i in range(1, 201)))
with open('prog.c', 'w') as f:
    f.write('int helper(void)\n{\n}\nint main(void)\n{\n  return 0;\n}\n')
with open('tags', 'w') as f:
    f.write('main\tprog.c\t/^int main(void)$/;"\tf\nhelper\tprog.c\t1;"\tf\n')

ENV = {k: v for k, v in os.environ.items() if not k.startswith('LESS')}
ENV.update(TERM='xterm', LANG='C', HOME=WORK)


def run(args, keys, wait=0.25, env=None, shell=None):
    pid, fd = pty.fork()
    if pid == 0:
        try:
            e = dict(ENV, **(env or {}))
            if shell:
                os.execve('/bin/sh', ['sh', '-c', shell.replace('LESS', LESS)], e)
            os.execve(LESS, [LESS] + args, e)
        finally:
            os._exit(127)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
    out = b''

    def drain(t):
        nonlocal out
        end = time.time() + t
        while time.time() < end:
            r, _, _ = select.select([fd], [], [], 0.05)
            if r:
                try:
                    out += os.read(fd, 65536)
                except OSError:
                    return
    drain(wait)
    for k in keys:
        if callable(k):
            k()
        else:
            os.write(fd, k.encode())
        drain(wait)
    os.kill(pid, 9)
    os.waitpid(pid, 0)
    return out.decode('latin1')


def prompt(o):
    last = re.split(r'\x1b\[24;1H', o)[-1]
    return re.sub(r'\x1b\[[0-9;?]*[A-Za-z]', '', last).strip()


P = ['-Pstop=%lt bot=%lb']
checks = []


def check(name, got, want):
    checks.append((name, got == want))
    print(f"{'ok' if got == want else 'FAILED'}: {name}" + ('' if got == want else f' (got {got!r}, want {want!r})'))


check('jump target -j5', prompt(run(['-j5'] + P + ['nums'], ['50g'])), 'top=46 bot=68')
check('window -z10', prompt(run(['-z10'] + P + ['nums'], [' ', ' '])), 'top=21 bot=43')
check('search lands on the target', prompt(run(['-j5'] + P + ['nums'], ['/^60$\r'])), 'top=56 bot=78')
check('tag -t', prompt(run(['-t', 'main'] + P, [])), 'top=4 bot=7')
check('lesskey binding', prompt(run(['--lesskey-content=x goto-end'] + P + ['nums'], ['x'])), 'top=178 bot=200')
check('lesskey #stop', prompt(run(['--lesskey-content=x goto-end;#stop'] + P + ['nums'], ['G'])), 'top=1 bot=23')
run(P + ['nums'], ['!echo hi > shell.out\r', '\r'])
check('! shell command', open('shell.out').read() if os.path.exists('shell.out') else '', 'hi\n')
run(P + ['nums'], ['5g', 'mx', '10g', '|x', 'wc -l > pipe.out\r', '\r'])
check('| pipe to a mark', open('pipe.out').read().strip() if os.path.exists('pipe.out') else '', '6')
check('= message', prompt(run(['nums'], ['='])), 'nums lines 1-23/200 byte 60/692 9%')
check('-M prompt', prompt(run(['-M', 'nums'], [' '])), 'nums lines 24-46/200 19%')
check('end prompt', prompt(run(['nums', 'tags'], ['G'])), '(END) - Next: tags')


def grow():
    with open('nums', 'a') as f:
        f.write('NEWLINE-201\n')


check('F sees what is appended', 'NEWLINE-201' in run(['nums'], ['F', grow], wait=0.6), True)


def row(o, n):
    """The text written last to screen row n (1-based)."""
    last = re.split(r'\x1b\[%d;1H' % n, o)[-1]
    last = re.split(r'\x1b\[\d+;1H', last)[0]
    return re.sub(r'\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x1b\x07]*(\x1b\\\\|\x07)', '', last).strip()


# ADR 0164.
with open('nums', 'w') as f:
    f.write(''.join(f'{i}\n' for i in range(1, 201)))
check('& filter', prompt(run(P + ['nums'], ['&5\r'])), '&top=5 bot=135')
check('&! filter', prompt(run(P + ['nums'], ['&!5\r'])), '&top=1 bot=26')
check('& cleared, staying put', prompt(run(P + ['nums'], ['&5\r', '&\r'])), 'top=5 bot=27')
with open('br', 'w') as f:
    f.write('{\n' + 'x\n' * 50 + '}\n' + 'y\n' * 50)
check('{ to the matching }', prompt(run(P + ['br'], ['{'])), 'top=30 bot=52')
check('} back to {', prompt(run(P + ['br'], ['{', '}'])), 'top=1 bot=23')
with open('wide', 'w') as f:
    f.write('abcdefghijklmnopqrstuvwxyz' * 10 + '\n')
check('right arrow scrolls half a screen', row(run(['wide'], ['\x1b[C']), 1)[:6], 'opqrst')
check('ESC-{ back to the first column', row(run(['wide'], ['\x1b[C', '\x1b{']), 1)[:6], 'abcdef')
check('_ shows an option', prompt(run(['nums'], ['_N'])), 'Line numbers off')
hist = os.path.join(os.getcwd(), 'hist')
run(P + ['nums'], ['/^60$\r', 'q'], env={'LESSHISTFILE': hist})
check('history written', '.search\n"^60$' in (open(hist).read() if os.path.exists(hist) else ''), True)
check('history recalled with UP', prompt(run(P + ['nums'], ['/', '\x1b[A', '\r'], env={'LESSHISTFILE': hist})), 'top=60 bot=82')
check('editing keys: Home, typing', prompt(run(P + ['nums'], ['/', '0$', '\x1b[H', '^6', '\r'])), 'top=60 bot=82')
run([], ['s', 'saved.txt\r', 'q'], shell='seq 1 50 | LESS')
check('s saves a pipe', open('saved.txt').read() if os.path.exists('saved.txt') else '', ''.join(f'{i}\n' for i in range(1, 51)))
run([], ['G', 'q'], shell='seq 1 30 | LESS -O logged.txt')
check('-O logs a pipe', open('logged.txt').read() if os.path.exists('logged.txt') else '', ''.join(f'{i}\n' for i in range(1, 31)))
with open('links', 'w') as f:
    f.write('see \x1b]8;;file:///x\x1b\\here\x1b]8;;\x1b\\ now\n')
osc = {'LESS_OSC8_OPEN_file': '\x10-sh -c \'echo "$0" > osc.out\''}
run(['-R', 'links'], ['\x0f\x0e', '\x0f\x0f'], env=osc)
check('^O^N ^O^O opens a link', open('osc.out').read() if os.path.exists('osc.out') else '', 'file:///x\n')
o = run([], ['G', 'g'], shell='seq 1 100000 | LESS -B -b 1', wait=0.5)
check('-B keeps only the newest', row(o, 1), '?')
sys.exit(0 if all(ok for _, ok in checks) else 1)
