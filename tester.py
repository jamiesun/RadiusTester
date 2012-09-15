#!/usr/bin/env python
#coding:utf-8

'''radius test client tools'''
from gevent import monkey
monkey.patch_all()
import argparse,sys
import socket
from pyrad import packet
from pyrad.dictionary import Dictionary
from pyrad.packet import AuthPacket
from pyrad.packet import AccessRequest
import ConfigParser
import gevent
import time
import hashlib

import six
md5_constructor = hashlib.md5

status_vars = {'start':1,'stop':2,'update':3,'on':7,'off':8}

class NewConfig(ConfigParser.ConfigParser):
    def __init__(self,filename):
        ConfigParser.ConfigParser.__init__(self)
        self.filename=filename
        self.read(filename)

    def optionxform(self,optionstr):
        return optionstr


parser = argparse.ArgumentParser()

parser.add_argument('--auth', 
    type=bool, 
    nargs='?',
    const =True, 
    help='radius auth test ')
parser.add_argument('--acct', 
    type=str, 
    choices=('start','stop','update','on','off'), 
    help='radius acct test ')
parser.add_argument('-u','--username', 
    type=str,
    dest='username',
    default='test001', 
    help='radius auth username')
parser.add_argument('-p','--password',
    type=str,
    dest='password',
    default='888888', 
    help='radius auth password')
parser.add_argument('-e','--encrypt',
    type=str,
    dest='encrypt',
    choices=('pap','chap'),  
    default='pap',
    help='radius auth password encrypt type')
parser.add_argument('-n','--requests', 
    type=int,
    dest='requests', 
    default=1, 
    help='request number')

parser.add_argument('-d','--debug', 
    type=bool, 
    dest='debug',
    nargs='?',
    const =True, 
    help='is debug ')

parser.add_argument('-o','--timeout', 
    type=int, 
    dest='timeout',
    default=5, 
    help='socket timeout')


class TestClient():
    def __init__(self,argvals):
        self.argvals = argvals
        self.config = NewConfig('tester.cfg')
        self.dict=Dictionary("dictionary")
        self.server = self.config.get('server','host','127.0.0.1')
        self.authport = self.config.getint('server','authport')
        self.acctport = self.config.getint('server','acctport')
        self.authsecret = self.config.get('server','authsecret','secret')
        self.acctsecret = self.config.get('server','acctsecret','secret')
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,10240000)
        self.sock.settimeout(self.argvals.timeout)

    def start(self):
        self.starttime = time.time()
        self.reply = 0
        self.lasttime = 0    
        gevent.spawn(self.recv)   
        try:
            if self.argvals.auth:
                for _ in xrange(self.argvals.requests):
                    gevent.spawn(self.sendauth)
            elif self.argvals.acct:
                for _ in xrange(self.argvals.requests):
                    gevent.spawn(self.sendacct)                
        except Exception, e:
            print "test error"%str(e)

    def recv(self):
        while True:
            try:
                msg, addr = self.sock.recvfrom(8192)
                self.lasttime = time.time()
                if msg:
                    self.reply += 1
                    if self.argvals.debug:
                        try:
                            resp = packet.Packet(packet=msg,dict=self.dict)
                            attr_keys = resp.keys()
                            print ("\nReceived an response:")
                            print "id:%s" % resp.id
                            print "code:%s" % resp.code
                            print ("Attributes: ")        
                            for attr in attr_keys:
                                print ( "%s: %s" % (attr, resp[attr][0]))
                        except Exception as e:
                            print 'error %s'%str(e)
            except socket.timeout:
                self.sock.close()
                break
        times = self.lasttime - self.starttime
        percount = self.reply /times
        print 
        print ("Total time (sec):%s"%round(times,4))
        print ("response total:%s"%self.reply)
        print ("request per second:%s"%percount)
        
    def sendauth(self):
        req = AuthPacket2(secret=self.authsecret,dict=self.dict)
        req['User-Name'] = self.argvals.username
        if self.argvals.encrypt == 'chap':
            req["CHAP-Password"] = req.ChapEcrypt(self.argvals.password)
        else:
            req["User-Password"] = req.PwCrypt(self.argvals.password)
        for _key in  self.config.options("auth_attrs"):
            req[_key] = self._get_val('auth_attrs',_key)

        if self.argvals.debug:
            attr_keys = req.keys()
            print ("send an authentication request")
            print ("Attributes: ")        
            for attr in attr_keys:
                print ( u"%s: %s" % (attr, req[attr]))    

        self.sock.sendto(req.RequestPacket(),(self.server,self.authport)) 
    

    def sendacct(self):
        req = packet.AcctPacket(dict=self.dict,secret=self.acctsecret)
        req['User-Name'] = self.argvals.username
        req['Acct-Status-Type'] = status_vars[self.argvals.acct]

        for _key in  self.config.options("acct_attrs"):
            req[_key] = self._get_val('acct_attrs',_key)

        _attrs_key = "acct_attrs_%s"%self.argvals.acct
        for _key in  self.config.options(_attrs_key):
            req[_key] = self._get_val(_attrs_key,_key)

        if self.argvals.debug:
            attr_keys = req.keys()
            print ("send an accounting request")
            print ("Attributes: ")        
            for attr in attr_keys:
                print ( u"%s: %s" % (attr, req[attr]))            
        
        self.sock.sendto(req.RequestPacket(),(self.server,self.acctport)) 


    def _get_val(self,opts,key):
        if self.dict.has_key(key):
            typ = self.dict[key].type
            val = self.config.get(opts,key) 
            if typ == 'integer':
                val = int(val)
            return val      


class AuthPacket2(AuthPacket):
    def __init__(self, code=AccessRequest, id=None, secret=six.b(''),
            authenticator=None, **attributes):
        AuthPacket.__init__(self, code, id, secret, authenticator, **attributes)   

    def ChapEcrypt(self,password):
        if not self.authenticator:
            self.authenticator = self.CreateAuthenticator()
        if not self.id:
            self.id = self.CreateID()
        if isinstance(password, six.text_type):
            password = password.encode('utf-8')
        return md5_constructor("%s%s%s"%(self.id,password,self.authenticator)).digest()




if __name__ == '__main__':
    args =  parser.parse_args(sys.argv[1:])
    print args
    if  args.auth or args.acct:
        client = TestClient(args)
        client.start()
        gevent.run()




