#!/usr/bin/env python

import os
import select
import subprocess

import click

@click.command()
@click.option('-1', '--cmd1', help="first test program")
@click.option('-2', '--cmd2', help="second test program")
def run_test(cmd1, cmd2):
    proc1 = subprocess.Popen(cmd1, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    proc2 = subprocess.Popen(cmd2, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

    poller = select.poll()
    poller.register(proc1.stdout, select.POLLIN)
    poller.register(proc2.stdout, select.POLLIN)

    n = 2

    proc1_raw_handle = proc1.stdout.fileno()
    
    while n and (not proc1.poll()) and (not proc2.poll()):
        ready = poller.poll(1000)
        if len(ready) == 0:
            print(".",end='')
        else:
            for fd, event in ready:
                if event & select.POLLHUP:
                    print("{} disconnected".format("A" if fd == proc1_raw_handle else "B"))
                    poller.unregister(fd)
                    n -= 1
                    continue
                if fd == proc1_raw_handle:
                    line = proc1.stdout.readline()
                    print("A: {}".format(line.strip()))
                    proc2.stdin.write(line)
                    proc2.stdin.flush()
                else:
                    line = proc2.stdout.readline()
                    print("B: {}".format(line.strip()))
                    proc1.stdin.write(line)
                    proc1.stdin.flush()

if __name__ == "__main__":
    run_test()

