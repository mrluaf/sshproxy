import sshproxy
import time


myssh = sshproxy.start(
  '123.20.183.218',
  'admin',
  '0l0ctyQh243O63uD',
  1080
)
print('SSH is Opened', myssh)
time.sleep(60)
myssh.close()
print('SSH closed')
time.sleep(60)

