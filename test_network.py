#!/usr/bin/env python3
"""Local integration smoke test of Stage 8A network E2EE (NOT DH ratchet integration)."""
import os, pty, select, subprocess, tempfile, time, signal, pathlib, sys
ROOT=pathlib.Path(__file__).resolve().parent
class Terminal:
    def __init__(self,argv,cwd):
        self.master, slave=pty.openpty()
        self.proc=subprocess.Popen(argv,cwd=cwd,stdin=slave,stdout=slave,stderr=slave,start_new_session=True)
        os.close(slave)
        self.log=b''
    def send(self,s): os.write(self.master,(s+'\n').encode())
    def until(self,needle,timeout=8):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            if needle.encode() in self.log:return
            ready,_,_=select.select([self.master],[],[],0.1)
            if ready:
                try: data=os.read(self.master,65536)
                except OSError: break
                if not data: break
                self.log+=data
        raise AssertionError(f'Missing {needle!r}. Output: {self.log.decode(errors="replace")[-3000:]}')
    def close(self):
        if self.proc.poll() is None:
            os.killpg(self.proc.pid,signal.SIGTERM)
            try:self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:os.killpg(self.proc.pid,signal.SIGKILL);self.proc.wait()
        os.close(self.master)

def run(debug=False, initiator="alice"):
    with tempfile.TemporaryDirectory(prefix='messenger-test-') as tmp:
        subprocess.run(['sh',str(ROOT/'make-certs.sh')],cwd=tmp,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        subprocess.run(['sh',str(ROOT/'make-identities.sh')],cwd=tmp,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        server=subprocess.Popen([str(ROOT/'server'),'server.crt','server.key','alice.pub','bob.pub'],cwd=tmp,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,start_new_session=True)
        clients=[]
        try:
            time.sleep(0.3)
            if server.poll() is not None: raise AssertionError('Server exited early: '+server.stderr.read().decode())
            for who in ('alice','bob'):
                c=Terminal([str(ROOT/'client')]+(['-d'] if debug else [])+['localhost',who,who+'.key','ca.crt','alice.pub','bob.pub'],tmp)
                clients.append(c)
                c.until('OK Logged in as '+who)
            alice,bob=clients
            # No manual /key: the first outgoing message initiates the handshake.
            first,second=(alice,bob) if initiator=='alice' else (bob,alice)
            first_name,second_name=('Alice','Bob') if initiator=='alice' else ('Bob','Alice')
            first.send(('bob ' if first is alice else 'alice ')+first_name+'1')
            second.until(first_name+'1')
            # The responder can now send without any user-visible ratchet setup.
            second.send(('bob ' if second is alice else 'alice ')+second_name+'1')
            first.until(second_name+'1')
            if debug:
                first.until('[DEBUG /key]')
                second.until('[DEBUG /rekey]')
            for who,src,dst in [('Alice2',alice,bob),('Bob2',bob,alice),('Bob3',bob,alice),('Alice3',alice,bob)]:
                src.send(('bob ' if src is alice else 'alice ')+who)
                dst.until(who)
            # UTF-8 backspace regression: delete the complete multibyte character.
            # Send ş then i, backspace twice, then hi; peer must see exactly hi.
            os.write(alice.master, 'bob ş'.encode('utf-8') + b'\x7futf8fixed\n')
            bob.until('[E2EE VERIFIED alice]')
            bob.until(' utf8fixed')
            # Neither client should print ambiguous SENT acknowledgements in normal mode.
            if not debug:
                for terminal in (alice,bob):
                    if b'\nSENT\r\n' in terminal.log:
                        raise AssertionError('Unhelpful SENT line was displayed')
            # Verify the debug option separately in an additional test below.
            print('PASS: automatic session, immediate responder send, alternating messages'+(' and -d logging' if debug else ''))
        finally:
            for c in clients:c.close()
            if server.poll() is None:
                os.killpg(server.pid,signal.SIGTERM)
            try:server.wait(timeout=3)
            except subprocess.TimeoutExpired:os.killpg(server.pid,signal.SIGKILL);server.wait()
if __name__=='__main__':
    try:
        run()
        run(debug=True,initiator="bob")
    except Exception as exc:
        print('FAIL:',exc,file=sys.stderr)
        sys.exit(1)
