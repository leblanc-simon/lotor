#!/usr/bin/env python3
"""Lance une commande sous pseudo-terminal et répond aux écrans debconf : quand la sortie reste
au repos, envoie la réponse suivante de TTY_ANSWERS (séparées par « | »), puis Entrée.
Usage : test-package-tty.py <journal> <commande> [arguments]."""
import fcntl
import os
import pty
import select
import struct
import sys
import termios
import time

IDLE_SECONDS = 3
TIMEOUT_SECONDS = 600


def main(log_path, *command):
    answers = [a for a in os.environ.get("TTY_ANSWERS", "").split("|") if a]
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(command[0], command)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 160, 0, 0))
    deadline = time.time() + TIMEOUT_SECONDS
    last_output = time.time()
    with open(log_path, "wb") as log:
        while time.time() < deadline:
            ready, _, _ = select.select([fd], [], [], 1)
            if ready:
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                log.write(chunk)
                log.flush()
                last_output = time.time()
            elif time.time() - last_output >= IDLE_SECONDS:
                answer = answers.pop(0) if answers else ""
                os.write(fd, answer.encode() + b"\r")
                last_output = time.time()
    _, status = os.waitpid(pid, 0)
    sys.exit(os.waitstatus_to_exitcode(status))


if __name__ == "__main__":
    main(*sys.argv[1:])
