"""For `test_linux_review3_regressions.mojo` (not a test file itself): opens
the file `argv[2]` beneath the directory `argv[1]` with `open_beneath`, and
`argv[1]/argv[2]` with `read_file` when `argv[3]` is "read", then prints
field 7 of /proc/self/stat (tty_nr: 0 when the process has no controlling
terminal). Run as a session leader with no terminal (setsid), it shows
whether opening a terminal device made it the controlling one."""

from std.sys import argv

from linux.fs import open_beneath, open_dir, read_file


def main() raises:
    var dir = String(argv()[1])
    var name = String(argv()[2])
    if len(argv()) > 3 and String(argv()[3]) == "read":
        try:
            _ = read_file(String(dir, "/", name), "read", max_bytes=1)
        except:
            pass  # (a terminal with no input: what matters is the open)
    else:
        var d = open_dir(dir)
        var f = open_beneath(d, name)
        _ = f^
    var stat = String(from_utf8_lossy=Span(read_file("/proc/self/stat", "stat")))
    var fields = stat.split(") ")[1].split(" ")
    print("TTY", fields[4])  # (state ppid pgrp session tty_nr: tty_nr is the 5th after the name)
