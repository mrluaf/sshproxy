import sshproxy
import time


myssh = sshproxy.start(
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

