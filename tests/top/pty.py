# SPDX-License-Identifier: MIT OR Apache-2.0
# top on a pseudo-terminal (ADR 0152): keys typed, the screen read back.
# Run by `cargo xtask check`: python3 -I pty.py COREUTILS WORKDIR, with
# COREUTILS the multicall binary (run as `top`).
import os, pty, re, select, struct, sys, termios, fcntl, time

TOOL, WORK = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
os.chdir(WORK)
CONF = os.path.join(WORK, 'slate', 'toprc')
if os.path.exists(CONF):
    os.remove(CONF)
ENV = dict(TERM='xterm', LANG='C', HOME=WORK, XDG_CONFIG_HOME=WORK, PATH=os.environ.get('PATH', '/usr/bin:/bin'))


def run(args, keys, wait=0.4):
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.execve(TOOL, ['top'] + args, ENV)
        finally:
            os._exit(127)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', 30, 120, 0, 0))
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
    screens = []
    for k in keys:
        os.write(fd, k.encode())
        drain(wait)
        screens.append(plain(out.decode('latin1').split('\x1b[H')[-1]))
    exited = False
    for _ in range(20):
        p, status = os.waitpid(pid, os.WNOHANG)
        if p:
            exited = os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
            break
        time.sleep(0.05)
    else:
        os.kill(pid, 9)
        os.waitpid(pid, 0)
    return screens, exited


def plain(s):
    return re.sub(r'\x1b\[[0-9;?]*[A-Za-z]', '', s)


failed = []


def check(name, ok):
    print(('ok: ' if ok else 'FAILED: ') + name)
    if not ok:
        failed.append(name)


UP, DOWN, RIGHT = '\x1b[A', '\x1b[B', '\x1b[C'
# The fields screen opens at the sort field (%CPU); nine up is nTH.
screens, exited = run(['-d', '0.3'], ['f', UP * 9, ' ', 'q', 'H', 'W', 'q'])
check('the fields screen', 'Fields Management' in screens[0] and 'current sort field is %CPU' in screens[0])
check('a field shown from it', '* nTH' in screens[2])
check('the new field in the header', re.search(r'NI +nTH +VIRT', screens[3]) is not None)
check('threads with H', 'Threads:' in screens[4] and 'Show threads On' in screens[4])
check('settings written with W', 'Wrote configuration to' in screens[5] and os.path.exists(CONF))
check('q quits', exited)
text = open(CONF).read() if os.path.exists(CONF) else ''
check('the file holds them', 'nTH' in text and 'threads=1' in text)
# A new top starts from the file; R and -o change the order's direction.
screens, exited = run(['-d', '0.3', '-o', '-PID'], ['h', 'x', 'q'])
check('read back at the start', 'Threads:' in screens[0] or 'Threads:' in screens[1])
check('the help screen', 'Help for Interactive Commands' in screens[0])
check('back from help', 'nTH' in screens[1] and exited)
# ADR 0163: the four windows, the forest, a filter, the summary's unit,
# a field moved on the fields screen, and secure mode.
os.remove(CONF)
# A long delay: messages last until the next refresh.
screens, exited = run(['-d', '2'], ['A', 'V', 'o', 'COMMAND=top\n', '\x0f', 'E', 'f', RIGHT + DOWN + '\r', 'q', 'q'])
check('all four windows', all(w in screens[0] for w in ('1:Def', '2:Job', '3:Mem', '4:Usr')))
check('the forest view', 'Forest mode On' in screens[1])
check('a filter', 'Active filters: COMMAND=top' in screens[4])
check('the summary in GiB', 'GiB Mem' in screens[5])
check('%CPU moved below %MEM', re.search(r'\* %MEM .*\n.*\* %CPU', screens[7]) is not None)
check('and in the header', re.search(r'%MEM +%CPU', screens[8]) is not None and exited)
screens, exited = run(['-d', '2', '-s'], ['k', 'q'])
check('secure mode', 'Unavailable in secure mode' in screens[0] and exited)
sys.exit(1 if failed else 0)
