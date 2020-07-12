import argparse
import pathlib
import os
import pty
import subprocess
import fcntl
import threading
import time

from core.pseudo_serial import SocketSerial


def set_nonblocking(fd):
    """Make a file_handle non-blocking."""
    global OFLAGS
    OFLAGS = fcntl.fcntl(fd, fcntl.F_GETFL)
    nflags = OFLAGS | os.O_NONBLOCK
    fcntl.fcntl(fd, fcntl.F_SETFL, nflags)


def disable_local_echo(fd):
    import termios
    new = termios.tcgetattr(fd)  # [iflag, oflag, cflag, lflag, ispeed, ospeed, cc]
    new[3] = new[3] & ~termios.ECHO  # Disable Echo lflags
    new[3] = new[3] & ~termios.ICANON  # Disable line buffer lflags
    termios.tcsetattr(fd, termios.TCSADRAIN, new)


def connect_socks(ser, fd):
    def _connect_socks():
        set_nonblocking(fd)
        disable_local_echo(fd)
        while ser.isOpen():
            if ser.isOpen():
                data0 = ser.read(100, timeout=.1)
                if len(data0):
                    os.write(fd, data0)

            try:
                # return 1-n bytes or exception if no bytes
                time.sleep(.1)
                data1 = os.read(fd, 1024)
                if len(data1):
                    ser.write(data1)
            except BlockingIOError:
                pass

    t = threading.Thread(target=_connect_socks, daemon=True)
    t.start()
    return t


def emulate(binary_path, debug=False):
    cmd = ['qemu-system-arm', '-M', 'lm3s6965evb', '-nographic', '-kernel', binary_path]
    if debug:
        cmd.extend(['-s', '-S'])
    ports = []
    for idx, port in enumerate([13337, 13338, 13339]):
        cmd.extend(['-serial', f'tcp:0.0.0.0:{port},server'])
        name = f'/embsec/UART{idx}'
        ports.append((port, name))

    subprocess.call(['pkill', 'qemu'])
    subprocess.Popen(cmd)

    ts = []
    for port, name in ports:
        master, slave = pty.openpty()
        s_name = os.ttyname(slave)
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass
        os.symlink(s_name, name)

        ts.append(connect_socks(SocketSerial(name, port, log=False), master))
        print(f'{name} is open')

    [t.join() for t in ts]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Stellaris Emulator')
    parser.add_argument("--boot-path", help="Path to the the bootloader binary.", default=None)
    parser.add_argument("--debug", help="Start GDB server and break on first instruction", action='store_true')
    args = parser.parse_args()
    if args.boot_path is None:
        binary_path = pathlib.Path(__file__).parent / '..' / 'bootloader' / 'gcc' / 'main.axf'
    else:
        binary_path = pathlib.Path(args.boot_path)

    emulate(binary_path.resolve(), debug=args.debug)
