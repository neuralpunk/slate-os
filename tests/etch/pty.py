# SPDX-License-Identifier: MIT OR Apache-2.0
# etch on a pseudo-terminal (g214): several files, justify, backups, a
# command's output, the settings file, the mouse, syntax colours, wide
# characters and redrawing only what changed. Run by `cargo xtask check`:
# python3 -I pty.py ETCH WORKDIR. Most checks read the files etch saved.
import os, pty, select, struct, sys, termios, fcntl, time

ETCH, WORK = os.path.abspath(sys.argv[1]), sys.argv[2]
os.chdir(WORK)
ENV = {'TERM': 'xterm', 'LANG': 'C.UTF-8', 'HOME': WORK, 'PATH': '/usr/bin:/bin'}


def write(name, text):
    with open(name, 'w', encoding='utf-8') as f:
        f.write(text)


def read(name):
    try:
        with open(name, encoding='utf-8') as f:
            return f.read()
    except OSError:
        return None


def run(args, keys, wait=0.25):
    """Type `keys` into etch ARGS; what it wrote, and what it wrote after
    each key (a list)."""
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.execve(ETCH, [ETCH] + args, ENV)
        finally:
            os._exit(127)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
    out, parts = b'', []

    def drain(t):
        nonlocal out
        got = b''
        end = time.time() + t
        while time.time() < end:
            r, _, _ = select.select([fd], [], [], 0.05)
            if r:
                try:
                    got += os.read(fd, 65536)
                except OSError:
                    break
        out += got
        return got
    drain(wait)
    for k in keys:
        os.write(fd, k.encode())
        parts.append(drain(wait).decode('utf-8', 'replace'))
    try:
        os.kill(pid, 9)
    except ProcessLookupError:
        pass
    os.waitpid(pid, 0)
    return out.decode('utf-8', 'replace'), parts


checks = []


def check(name, got, want):
    checks.append(got == want)
    print(f"{'ok' if got == want else 'FAILED'}: {name}" + ('' if got == want else f' (got {got!r}, want {want!r})'))


SAVE, EXIT = '\x0f\r', '\x18'

# Two files: the second shown with M->, changed, saved and closed; the
# first is shown again.
write('a.txt', 'first\n')
write('b.txt', 'second\n')
out, parts = run(['a.txt', 'b.txt'], ['\x1b>', 'B', SAVE, EXIT, 'A', SAVE, EXIT])
check('two files: the title counts them', '[1/2]' in out, True)
check('two files: M-> switches', 'Switched to b.txt' in parts[0], True)
check('two files: the second edited', read('b.txt'), 'Bsecond\n')
check('two files: closing one shows the other', read('a.txt'), 'Afirst\n')

# ^R with M-F: a file into a new buffer.
write('c.txt', 'third\n')
run(['a.txt'], ['\x12', '\x1bf', 'c.txt\r', 'C', SAVE, EXIT, EXIT])
check('^R M-F: into a new buffer', (read('c.txt'), read('a.txt')), ('Cthird\n', 'Afirst\n'))

# ^J justifies the paragraph to the screen's width less 8 (72).
words = ' '.join(f'word{i}' for i in range(40))
write('para.txt', words + '\n\nnext\n')
run(['para.txt'], ['\x0a', SAVE, EXIT])
text = read('para.txt') or ''
lines = text.split('\n\n')[0].split('\n')
check('^J: lines fit', max(len(l) for l in lines) <= 72 and len(lines) > 2, True)
check('^J: the words kept', ' '.join(lines), words)
check('^J: the next paragraph kept', text.endswith('\n\nnext\n'), True)

# -B: the old file kept as FILE~.
write('d.txt', 'old\n')
run(['-B', 'd.txt'], ['N', SAVE, EXIT])
check('-B: backup', (read('d.txt'), read('d.txt~')), ('Nold\n', 'old\n'))

# ^T: a command's output inserted.
write('e.txt', '')
run(['e.txt'], ['\x14', 'echo from-a-command\r', SAVE, EXIT])
check('^T: output inserted', read('e.txt'), 'from-a-command\n')

# The settings file: what it can't read is said.
os.makedirs('.config/etch', exist_ok=True)
write('.config/etch/etchrc', 'set linenumbers\nset bogus\n')
out, _ = run(['a.txt'], [EXIT])
check('etchrc: an unknown setting said', 'Unknown setting in etchrc, line 2: set bogus' in out, True)
check('etchrc: line numbers on', '1 Afirst' in out, True)
os.remove('.config/etch/etchrc')

# -m: a click puts the cursor; the wheel needs no answer.
write('f.txt', 'one\ntwo\nthree\n')
out, _ = run(['-m', 'f.txt'], ['\x1b[<0;1;3M', '\x1b[<0;1;3m', 'Z', '\x1b[<65;1;2M', SAVE, EXIT])
check('-m: mouse reporting on', '\x1b[?1000h' in out, True)
check('-m: a click places the cursor', read('f.txt'), 'one\nZtwo\nthree\n')

# Syntax colours: a shell script's keywords.
write('g.sh', 'if true; then echo hi; fi # done\n')
out, _ = run(['g.sh'], [EXIT])
check('syntax: a keyword coloured', '\x1b[32mif' in out, True)
check('syntax: a comment coloured', '\x1b[36m# done' in out, True)
out, _ = run(['-Y', 'g.sh'], [EXIT])
check('syntax: -Y turns them off', '\x1b[32m' in out, False)

# A wide character takes two columns: End puts the cursor after them.
write('h.txt', '漢字x\n')
out, parts = run(['h.txt'], ['\x1b[F'])
check('wide characters: the cursor after them', '\x1b[2;6H' in parts[0], True)

# Typing redraws the line, not the shortcuts.
_, parts = run(['h.txt'], ['q'])
check('one key: the shortcuts not redrawn', 'Write Out' in parts[0], False)
check('one key: the line redrawn', 'q漢字x' in parts[0], True)

sys.exit(0 if all(checks) else 1)
