#!/usr/pkg/etc/pkgin/hello.py

pwd = map(pkt.PwDecrypt,pkt['Password'])                    
print('User: %s Pass: %s' %(pkt['User-Name'],pwd))

pwd = pkt.PwDecrypt(pkt['Password'][0])
print('User: %s Pass: %s' %(pkt['User-Name'],pwd))

