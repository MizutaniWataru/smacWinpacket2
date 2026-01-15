import asyncio
import os

class TryLock:
    def __init__(self, lock, timeout=0):
        self.lock = lock
        self.timeout = timeout
        self.acquired = False

    async def __aenter__(self):
        try:
            await asyncio.wait_for(self.lock.acquire(), timeout=self.timeout)
            self.acquired = True
        except asyncio.TimeoutError:
            self.acquired = False
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.acquired:
            self.lock.release()
            self.acquired = False

    def locked(self):
        return self.acquired


class AsyncSocket:
    def __init__(self, path, mode="client", on_receive=None, read_bytes=10000):
        self.path = path
        self.mode = mode
        self.reader = None
        self.writer = None
        self.server = None
        self.read = True
        self.rb = read_bytes
        self.on_receive = on_receive or (lambda data, self: print("received", data))
        self.lock = asyncio.Lock()

    async def connect(self):
        async with TryLock(self.lock, timeout=1) as l:
            if not l.locked():
                print("could not acquire lock")
                return
            if self.writer is None:
                try:
                    self.reader, self.writer = await asyncio.open_unix_connection(self.path)
                    print("connected")
                except:
                    self.reader = None
                    self.writer = None
                    raise

    async def send(self, message):
        if self.writer is None:
            print("writer is none")
            raise
        async with TryLock(self.lock, timeout=1) as l:
            if not l.locked():
                print("could not acquire lock")
                return
            try:
                self.writer.write(message)
                await self.writer.drain()
            except:
                raise

    async def close(self):
        self.read = False
        if self.writer:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except BrokenPipeError:
                print("already closed")
        self.reader = None
        self.writer = None
        print("socket closed")

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        try:
            while self.read:
                data = await reader.read(self.rb)
                if not data:
                    break
                message = data.decode()
                if asyncio.iscoroutinefunction(self.on_receive):
                    await self.on_receive(message, writer)
                else:
                    self.on_receive(message, writer)
        except asyncio.exceptions.CancelledError:
            print("read cancel")
        except:
            import traceback
            err = traceback.format_exc()
            print(err)
        finally:
            writer.close()
            await writer.wait_closed()

    async def start_server(self):
        if os.path.exists(self.path):
            os.remove(self.path)
        self.server = await asyncio.start_unix_server(self.handle_client, path=self.path)
        os.chmod(self.path, 0o777)
        async with self.server:
            print("server start")
            await self.server.serve_forever()

    async def start(self):
        if self.mode == "server":
            await self.start_server()
        elif self.mode == "client":
            await self.connect()
