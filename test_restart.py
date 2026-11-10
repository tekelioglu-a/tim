#!/usr/bin/env python3
"""Regression: peer restart must trigger authenticated recovery without resending old plaintext."""
import os, subprocess, tempfile, time, signal
from test_network import ROOT, Terminal

def run(debug=False, restarted_initiates=False):
    with tempfile.TemporaryDirectory(prefix='tim-restart-') as tmp:
        for script in ('make-certs.sh','make-identities.sh'):
            subprocess.run(['sh',str(ROOT/script)],cwd=tmp,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        server=subprocess.Popen([str(ROOT/'server'),'server.crt','server.key','alice.pub','bob.pub'],cwd=tmp,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,start_new_session=True)
        clients=[]
        try:
            time.sleep(.3)
            args=lambda who:[str(ROOT/'client')]+(['-d'] if debug else [])+['localhost',who,who+'.key','ca.crt','alice.pub','bob.pub']
            alice=Terminal(args('alice'),tmp);clients.append(alice);alice.until('OK Logged in as alice')
            bob=Terminal(args('bob'),tmp);clients.append(bob);bob.until('OK Logged in as bob')
            alice.send('bob initial');bob.until('\ninitial');alice.until('[DELIVERED]' if debug else '|**|')
            bob.send('QUIT');bob.proc.wait(timeout=3);bob.close();clients.remove(bob)
            bob=Terminal(args('bob'),tmp);clients.append(bob);bob.until('OK Logged in as bob')
            if restarted_initiates:
                bob.send('alice pending-before-reset')
                # The pending message is sent only after the new authenticated session.
                alice.until('\npending-before-reset',timeout=10)
            else:
                alice.send('bob stale-payload');bob.until('[REJECTED no active session]')
                alice.until('peer offline' if debug else '|*é|')
            alice.send('bob fresh-payload');bob.until('\nfresh-payload')
            alice.until('Session established' if debug else '|**|')
            if b'\nstale-payload\r\n' in bob.log:raise AssertionError('Stale plaintext was replayed')
            bob.send('alice reply-after-restart');alice.until('\nreply-after-restart')
            print('PASS: restart recovery'+(' restarted-initiates' if restarted_initiates else ' old-receipt-failure')+(' debug' if debug else ''))
        finally:
            for c in clients:c.close()
            if server.poll() is None:os.killpg(server.pid,signal.SIGTERM)
            try:server.wait(timeout=3)
            except subprocess.TimeoutExpired:os.killpg(server.pid,signal.SIGKILL);server.wait()
if __name__=='__main__':
    run();run(True);run(restarted_initiates=True)
