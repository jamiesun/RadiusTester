#coding:utf-8
import sys
from gevent import monkey
monkey.patch_all()
from PyQt4 import QtCore, QtGui,uic
# from PyQt4.QtCore import QSettings,QVariant

from gevent import socket
from gevent.queue import Queue
from pyrad import packet,tools
from pyrad.dictionary import Dictionary
from pyrad.packet import AuthPacket
from pyrad.packet import AccessRequest
import time
import hashlib
import six
import gevent
import binascii
import pprint
import uuid
import random
import logging

from gevent.pool import Pool

pool = Pool(100)

md5_constructor = hashlib.md5

status_vars = {'start':1,'stop':2,'update':3,'on':7,'off':8}


ipaddrs = []
for i in range(255):
    ipaddrs += ["192.169.%s.%s"% (i, ip) for ip in range(1,255) ]

ipset = set(ipaddrs)

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
            password = password.strip().encode('utf-8')

        chapid = self.authenticator[0]
        self['CHAP-Challenge'] = self.authenticator
        return '%s%s' % (chapid,md5_constructor("%s%s%s"%(chapid,password,self.authenticator)).digest())




app_running = True

app = QtGui.QApplication(sys.argv)
form_class, base_class = uic.loadUiType('tester.ui')
QtGui.QApplication.setStyle(QtGui.QStyleFactory.create("Cleanlooks"))

def mainloop(app):
    while app_running:
        app.processEvents()
        while app.hasPendingEvents():
            app.processEvents()
            gevent.sleep()
        gevent.sleep()


class TesterWin(QtGui.QMainWindow,form_class):
    def __init__(self, *args):
        super(TesterWin, self).__init__(*args)
        self.running = False
        self.random_running = False
        self.testusers = {}
        self.setupUi(self)
        self.dict=Dictionary("./dict/dictionary")
        self.init_testusers()
        self.settings = QtCore.QSettings( 'ToughRADIUS', 'tester' )
        self.init_config()
        self.ooline_ips = set()
        
    def init_testusers(self):
        with open("testusers.txt") as ufs:
            for line in ufs:
                if  not line or not line.strip():
                    continue
                _props = line.split(",")
                _user = dict(user_name=_props[0].strip(),passwd=_props[1].strip())
                self.testusers[_props[0]] = _user

    def get_udp_client(self):
        rsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rsock.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,819200)
        rsock.settimeout(self.timeout.value())
        # rsock.setblocking( 0 )
        return rsock

    def init_config(self):
        self.server_addr.setText( self.settings.value( 'server' ).toString() or "127.0.0.1" )
        self.auth_port.setText( self.settings.value( 'auth_port' ).toString() or "1812")
        self.acct_port.setText( self.settings.value( 'acct_port' ).toString() or "1813")
        self.auth_secret.setText( self.settings.value( 'auth_secret' ).toString() or "secret")
        self.acct_secret.setText( self.settings.value( 'acct_secret' ).toString() or "secret")

    @property
    def server(self):
        return self.server_addr.text()

    @property
    def authport(self):
        return int(self.auth_port.text() or 1812)

    @property
    def acctport(self):
        return int(self.acct_port.text() or 1813)
    @property
    def authsecret(self):
        return six.b(str(self.auth_secret.text() or 'secret'))
    
    @property
    def acctsecret(self):
        return six.b(str(self.acct_secret.text() or 'secret'))

    def encode_attr(self,key,val):
        if self.dict.has_key(key):
            typ = self.dict[key].type
            if typ == 'integer' or typ == 'date':
                val = int(val)
            else:
                val = str(val)
            return val     
        else:
            self.logger("unknow attr %s"%key)                 

    def decode_attr(self,key,value):
        if self.dict.has_key(key):
            typ = self.dict[key].type
            if typ == 'string':
                return value
            return value
        else:
            self.logger("unknow attr %s"%key)              

    def logger(self,msg):
        self.log_view.append(msg)
        
    def log_packet(self,pkt):
        # self.logger(repr(pkt))
        attr_keys = pkt.keys()
        self.logger("\nRadius Packet:")
        self.logger("id:%s" % pkt.id)
        self.logger("code:%s" % pkt.code)
        self.logger("Attributes: ")        
        for attr in attr_keys:
            self.logger( ":::: %s: %s" % (attr, self.decode_attr(attr,pkt[attr][0])))      

    def get_acct_type(self):
        if self.acct_start.isChecked():
            return status_vars['start']
        elif self.acct_stop.isChecked():
            return status_vars['stop']
        elif self.acct_update.isChecked():
            return status_vars['update']    
        elif self.acct_on.isChecked():
            return status_vars['on']
        elif self.acct_off.isChecked():
            return status_vars['off']

    def build_auth_request(self):
        req = AuthPacket2(secret=self.authsecret,dict=self.dict)
        for _row in range(self.auth_attr_table.rowCount()):
            attr_name_item = self.auth_attr_table.item(_row,0)
            attr_val_item = self.auth_attr_table.item(_row,1)
            flag_item =  self.auth_attr_table.item(_row,2)
            attr_name = attr_name_item and str(attr_name_item.text())
            attr_val = attr_val_item and str(attr_val_item.text())
            flag = flag_item and flag_item.text()
            if attr_name and attr_val and flag == '1':
                val = self.encode_attr(attr_name,attr_val)
                if not val:
                    continue
                if attr_name == 'CHAP-Password':
                    req["CHAP-Password"] = req.ChapEcrypt(val)
                elif  attr_name == 'User-Password':
                    req["User-Password"] = req.PwCrypt(val)   
                else:
                    req[attr_name] = val
        return req

    def build_acct_request(self):
        req = packet.AcctPacket(dict=self.dict,secret=self.acctsecret)
        for _row in range(self.acct_attr_table.rowCount()):
            attr_name_item = self.acct_attr_table.item(_row,0)
            attr_val_item = self.acct_attr_table.item(_row,1)
            flag_item =  self.acct_attr_table.item(_row,2)
            attr_name = attr_name_item and str(attr_name_item.text())
            attr_val = attr_val_item and str(attr_val_item.text())
            flag = flag_item and flag_item.text()
            if attr_name and attr_val and flag == '1':
                val = self.encode_attr(attr_name,attr_val)
                if val :
                    req[attr_name] = val
        return req

    def sendauth(self,req, que):
        if self.is_debug.isChecked():
            self.logger(u"\nsend an authentication request to %s"%self.server)
            self.log_packet(req)

        while self.running:
            sock = self.get_udp_client()
            try:
                gevent.socket.wait_write(sock.fileno(), timeout=self.timeout.value())
                sock.sendto(req.RequestPacket(), (self.server, self.authport))
                que.put_nowait('sendreq')
                gevent.socket.wait_read(sock.fileno(), timeout=self.timeout.value())
                msg, addr = sock.recvfrom(8192)
                if msg:
                    que.put_nowait(msg)
                    # gevent.sleep(0)
                    break
            except Exception as err:
                que.put_nowait(err)
                logging.error(err)
                # gevent.sleep(1)
            finally:
                try:
                    sock.close()
                except Exception as err:
                    self.logger("auth socket close error %s" % repr(err))

    def sendacct(self, que):
        req = self.build_acct_request()
        req['Acct-Status-Type'] = self.get_acct_type()
        if self.is_debug.isChecked():
            self.logger("\nsend an accounting request")
            self.log_packet(req)
        while self.running:
            sock = self.get_udp_client()
            try:
                gevent.socket.wait_write(sock.fileno(), timeout=0.9)
                sock.sendto(req.RequestPacket(), (self.server, self.acctport))
                que.put('sendreq')
                gevent.socket.wait_read(sock.fileno(), timeout=self.timeout.value())
                msg, addr = sock.recvfrom(8192)
                if msg:
                    que.put_nowait(msg)
                    # gevent.sleep(0)
                    break
            except Exception as err:
                que.put_nowait(err)
                logging.error("err")
            finally:
                try:
                    sock.close()
                except Exception as err:
                    self.logger("auth socket close error %s" % repr(err))

    def random_onoff(self,rsock):
        while self.random_running:
            try:
                user  = self.testusers[random.choice(self.testusers.keys())]
                if not user.get("is_online"):
                    authreq = self.build_auth_request()
                    authreq["User-Name"] = user['user_name']
                    authreq["User-Password"] = authreq.PwCrypt(user['passwd'])
                    if self.is_debug.isChecked():
                        self.logger(u"\nsend an authentication request to %s"%self.server)
                        self.log_packet(authreq)
                    gevent.socket.wait_write( rsock.fileno(), timeout=0.9 )
                    rsock.sendto(authreq.RequestPacket(),(self.server,self.authport))

                    ips = ipset.difference(self.ooline_ips)
                    if not ips:
                        gevent.sleep(1)
                        continue

                    _session_id = uuid.uuid4().hex
                    user["session_id"] = _session_id
                    user["ipaddr"] = random.choice(list(ips))
                    self.ooline_ips.add(user["ipaddr"])
                    acctreq = self.build_acct_request()
                    acctreq["User-Name"] = user['user_name']
                    acctreq["Acct-Status-Type"] = status_vars['start']
                    acctreq["Acct-Session-Id"] = _session_id
                    acctreq["Acct-Session-Time"] = random.randint(1000,9999)
                    acctreq["Framed-IP-Address"] = user["ipaddr"]
                    if  self.is_debug.isChecked():
                        self.logger("\nsend an accounting start request")
                        self.log_packet(acctreq)
                    gevent.socket.wait_write( rsock.fileno(), timeout=0.9 )
                    rsock.sendto(acctreq.RequestPacket(),(self.server,self.acctport))
                    user["is_online"] = True
                else:
                    acctreq = self.build_acct_request()
                    acctreq["User-Name"] = user['user_name']
                    acctreq["Acct-Status-Type"] = status_vars['stop']
                    acctreq["Acct-Session-Id"] = user.get("session_id")
                    acctreq["Framed-IP-Address"] = user.get("ipaddr")
                    if  self.is_debug.isChecked():
                        self.logger("\nsend an accounting stop request")
                        self.log_packet(acctreq)
                    gevent.socket.wait_write( rsock.fileno(), timeout=0.9 )
                    rsock.sendto(acctreq.RequestPacket(),(self.server,self.acctport))
                    user["is_online"] = False
                    self.ooline_ips.remove(user.get("ipaddr"))
                gevent.sleep( 0 )
            except Exception as err:
                self.logger( "\nsend radius error %s" % repr(err) )
                gevent.sleep( 0 )
            finally:
                gevent.sleep(random.choice((0.1,0.2,0.3,0.4,0.5,0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8,0.0,1,2,3,4,5,6,7,8,9)))


    def on_random_recv(self,rsock):
        timeout = self.timeout.value()
        gevent.sleep( 0.5)
        while self.random_running:
            try:
                gevent.socket.wait_read( rsock.fileno(), timeout=timeout )
                msg, addr = rsock.recvfrom(8192)
                if msg:
                    if self.is_debug.isChecked():
                        try:
                            resp = packet.Packet(packet=msg,dict=self.dict)
                            attr_keys = resp.keys()
                            self.logger("\nReceived an response:")
                            self.logger("id:%s" % resp.id)
                            self.logger("code:%s" % resp.code)
                            self.logger("Attributes: ")
                            for attr in attr_keys:
                                self.logger( ":::: %s: %s" % (attr, self.decode_attr(attr,resp[attr][0])))
                        except Exception as e:
                            logging.exception( "parse packet error %s"%repr(e) )
                            self.logger('\nerror %s'%repr(e))
                gevent.sleep( 0 )
            except Exception as err:
                logging.exception("recv random error ")
                self.logger( "recv random error %s"% repr(err))
                gevent.sleep( 0 )
                continue

        try:
            rsock.close()
        except Exception as err:
            self.logger("random socket close error %s" % repr(err))


    def on_stat(self,que,times):
        _init_time = time.time()
        starttime = _init_time
        stat_time = _init_time
        lasttime = _init_time
        reply = 0
        _sendreqs = 0
        _errors = 0
        _timeouts = 0
        while self.running:
            try:
                if reply == times:
                    break
                msg = que.get()
                is_radius_reply = False
                if isinstance(msg, socket.timeout):
                    _timeouts += 1
                elif isinstance(msg,Exception):
                    _errors += 1
                elif msg == 'sendreq':
                    _sendreqs += 1
                else:
                    is_radius_reply = True
                    reply += 1

                lasttime = time.time()
                if lasttime - stat_time >= 3:
                    stat_time = lasttime
                    sectimes = lasttime - starttime
                    percount = reply / sectimes
                    self.logger("\n\nCast time total (sec):%s" % round(sectimes, 4))
                    self.logger("Send requests total:%s" % _sendreqs)
                    self.logger("Received response total:%s" % reply)
                    self.logger("Send timeouts:%s" % _timeouts)
                    self.logger("Send errors:%s" % _errors)
                    self.logger("Request per second:%s" % int(percount))

                # print logging
                try:
                    if self.is_debug.isChecked() and is_radius_reply:
                        resp = packet.Packet( packet=msg, dict=self.dict)
                        attr_keys = resp.keys()
                        self.logger( "\nReceived an response:" )
                        self.logger( "id:%s" % resp.id )
                        self.logger( "code:%s" % resp.code )
                        self.logger( "Attributes: " )
                        for attr in attr_keys:
                            self.logger( ":::: %s: %s" % (attr, self.decode_attr( attr, resp[attr][0] )) )
                except Exception as e:
                    self.logger( '\nparse resp error %s' % repr( e ) )
            except Exception as err:
                _errors += 1
                self.logger( '\nstat error %s' % repr( err ) )

            gevent.sleep( 0 )


        sectimes = lasttime - starttime
        if times > 1:
            percount = reply / sectimes
            self.logger("\n\nCast time total (sec):%s" % round(sectimes, 4))
            self.logger("Send requests total:%s" % _sendreqs)
            self.logger("Received response total:%s" % reply)
            self.logger("Send timeouts:%s" % _timeouts)
            self.logger("Send errors:%s" % _errors)
            self.logger("Request per second:%s" % int(percount))

        self.stop()

    def run(self,statque,times):
        if self.running:
            return

        if times > 1:
            self.is_debug.setChecked(False)
            self.logger("\nTotal request:%s"%times)

        self.send_auth_cmd.setEnabled(False) 
        self.send_acct_cmd.setEnabled(False)               
        self.running = True
        pool.spawn(self.on_stat,statque,times)

    def stop(self):
        self.running = False     
        self.send_auth_cmd.setEnabled(True) 
        self.send_acct_cmd.setEnabled(True)
        self.logger("\n\nStop Testing\n\n")


    @QtCore.pyqtSlot()
    def on_stop_auth_clicked(self):
        self.stop()

    @QtCore.pyqtSlot()
    def on_stop_acct_clicked(self):
        self.stop()

    @QtCore.pyqtSlot()
    def on_save_cmd_clicked(self):
        self.settings.setValue('server',self.server)
        self.settings.setValue('auth_port',self.authport)
        self.settings.setValue('acct_port',self.acctport)
        self.settings.setValue('auth_secret',self.authsecret)
        self.settings.setValue('acct_secret',self.acctsecret)
        self.settings.sync()


    @QtCore.pyqtSlot()
    def on_send_auth_cmd_clicked(self):
        from itertools import cycle
        times = self.auth_times.value()
        statque = Queue()
        self.run(statque,times)
        req = self.build_auth_request()
        for _ in xrange(times):
            app.processEvents()
            if not self.running:
                break
            pool.spawn(self.sendauth, req, statque)


    @QtCore.pyqtSlot()
    def on_send_acct_cmd_clicked(self):
        from itertools import cycle
        times = self.acct_times.value()
        statque = Queue()
        self.run(statque,times)
        for _ in xrange(times):
            app.processEvents()
            if not self.running:
                break
            pool.spawn(self.sendacct, statque)

    @QtCore.pyqtSlot()
    def on_random_test_start_clicked(self):
        rand_nums = self.random_nums.value()
        if not self.random_running:
            self.log_view.clear()
            self.logger(u"即将开始随机测试")      
            self.random_running = True
            for _ in range(rand_nums):
                rsock = self.get_udp_client()
                gevent.spawn(self.random_onoff,rsock)
                gevent.spawn(self.on_random_recv,rsock)
        self.random_test_start.setEnabled(False)
        self.random_test_end.setEnabled(True) 


    @QtCore.pyqtSlot()
    def on_random_test_end_clicked(self):
        self.random_running = False  
        self.random_test_start.setEnabled(True)  
        self.random_test_end.setEnabled(False)          

    @QtCore.pyqtSlot()
    def on_clearlog_cmd_clicked(self):
        self.log_view.clear()

    def closeEvent(self, event):
        global app_running
        app_running = False
        try:
            gevent.killall(timeout=2)
        except:
            pass
        event.accept()


if __name__ == "__main__":
    form = TesterWin()
    form.show()
    gevent.joinall([gevent.spawn(mainloop, app)])