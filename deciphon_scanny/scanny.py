import asyncio
import sys
from asyncio import create_subprocess_exec
from asyncio.subprocess import PIPE
from contextlib import asynccontextmanager
from enum import Enum

from deciphon_scanny.scanny_file import scanny_file


class State(Enum):
    INIT = 0
    RUN = 1
    DONE = 2
    FAIL = 3
    QUIT = 4


class Result(Enum):
    SUCCEED = 0
    TIMEDOUT = 1
    CANCELLED = 2
    FAILED = 3


class Scanny:
    def __init__(
        self,
        proc,
        scan_file: str,
        db_file: str,
        multi_hits: bool,
        hmmer3_compat: bool,
        no_stderr: bool,
    ):
        self._proc = proc
        self._scan_file = scan_file
        self._db_file = db_file
        self._multi_hits = multi_hits
        self._hmmer3_compat = hmmer3_compat
        self._state: State = State.INIT
        self._result: Result = Result.FAILED
        self._no_stderr = no_stderr

    @property
    def result(self):
        return self._result

    async def write_stdin(self, stdin):
        while self._state != State.QUIT:

            if self._state == State.INIT:
                self._state = State.RUN
                multi_hits_opt = 1 if self._multi_hits else 0
                hmmer3_compat_opt = 1 if self._hmmer3_compat else 0
                cmd = f"scan {self._scan_file} {self._db_file}"
                cmd += f" {multi_hits_opt} {hmmer3_compat_opt}"
                stdin.write((cmd + " | {1} _ _\n").encode())
                await stdin.drain()

            elif self._state == State.RUN:
                stdin.write(b"state | {1} {2} {3}\n")
                await stdin.drain()
                await asyncio.sleep(1)

            elif self._state == State.DONE or self._state == State.FAIL:
                self._state = State.QUIT
                stdin.write(b"quit\n")
                print("Quitting")
                try:
                    await stdin.drain()
                except (BrokenPipeError, ConnectionResetError):
                    pass

    async def read_stdout(self, stdout):
        while self._state != State.QUIT:

            buf = await stdout.readline()
            if not buf:
                break

            line = buf.decode().strip()
            result, state, progress = line.split(" ", 2)
            if result == "fail":
                self._state = State.FAIL
                self._result = Result.FAILED
            elif result == "ok" and state == "run":
                print(progress)

            if self._state == State.INIT:
                if state == "run" or state == "done":
                    self._state = State.RUN

            elif self._state == State.RUN:
                if state == "done":
                    self._state = State.DONE
                    self._result = Result.SUCCEED

                if state == "fail":
                    self._state = State.FAIL
                    self._result = Result.FAILED

    async def read_stderr(self, stderr):
        if self._no_stderr:
            return
        while self._state != State.QUIT:
            buf = await stderr.readline()
            if not buf:
                break
            print(buf.decode().strip(), file=sys.stderr)

    async def wait(self):
        await asyncio.gather(
            self.write_stdin(self._proc.stdin),
            self.read_stderr(self._proc.stderr),
            self.read_stdout(self._proc.stdout),
        )


@asynccontextmanager
async def create_scanny(scan_file, db_file, multi_hits, hmmer3_compat):
    try:
        with scanny_file() as file:
            proc = await create_subprocess_exec(
                file, stdin=PIPE, stdout=PIPE, stderr=PIPE
            )
            yield Scanny(proc, scan_file, db_file, multi_hits, hmmer3_compat, False)
    finally:
        await proc.wait()
