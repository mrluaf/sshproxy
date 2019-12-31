# https://pypi.org/project/wexpect/

import wexpect 
import time

def OpenSSH(host, user, pwd, port=1080, bg_run=False, timeout=30):
  try:
    options = '-q -oStrictHostKeyChecking=no -oPubkeyAuthentication=no'
    if bg_run:                                                                                                                                                         
      options += ' -f'
    child = wexpect.spawn('ssh %s -D %s -N %s@%s' % (options, str(port), str(user), str(host)), timeout=timeout)
    child.expect('Password:')
    child.sendline(pwd)
    return child
    # print(child.before)
    # time.sleep(60)
    # child.sendline('exit')
  except Exception as identifier:
    raise

myssh = OpenSSH(
  '14.161.1.99',
  'admin',
  'P@ssw0rd',
  1080
)
print('SSH is Opened', myssh)
time.sleep(60)
myssh.close()
print('SSH closed')
time.sleep(60)

