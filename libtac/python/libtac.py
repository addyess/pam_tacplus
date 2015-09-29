import ctypes
from collections import namedtuple
import socket
import struct

libtac = ctypes.CDLL('libtac.so')

def __net_class(name):
    # struct sockaddr from sys/socket.h
    class In4Addr(ctypes.Structure):
        _fields_ = [('s_addr', ctypes.c_uint32)]
        def __repr__(self):
            '''Print the fields'''
            #s_addr is in network byte order unpacked
            h_byte_order_unpacked = socket.ntohl(self.s_addr)
            n_byte_order_packed   = struct.pack('!L', h_byte_order_unpacked)
            #inet_ntoa takes packed in network byte order
            return socket.inet_ntoa(n_byte_order_packed)

    class SockAddrIn4(ctypes.Structure):
        _fields_ = [('sin_family',   ctypes.c_uint16),
                    ('sin_port',     ctypes.c_uint16),
                    ('sin_addr',     In4Addr),
                    ('sin_zero',     ctypes.c_char * 8)]
        def interp (self, field_id, value):
            switcher = { 0 : lambda x : 'v4' if (x == socket.AF_INET ) else 'v6',
                         1 : lambda x : socket.ntohs(x) 
                       }
            return switcher[field_id](value) if field_id in switcher else repr(value)
    
        def __repr__(self):
            '''Print the fields'''
            res = []
            for idx, field in enumerate(self._fields_):
                res.append('{}={}'.format(field[0], self.interp(idx, getattr(self, field[0]) ) ) )
            return self.__class__.__name__ + '(' + ','.join(res) + ')'

    # struct sockaddr_in6 from sys/socket.h
    class In6Addr(ctypes.Structure):
        _fields_ = [('s6_addr', ctypes.c_ubyte * 16)]

    class SockAddrIn6(ctypes.Structure):
        _fields_ = [('sin6_family',   ctypes.c_uint16),
                    ('sin6_port',     ctypes.c_uint16),
                    ('sin6_flowinfo', ctypes.c_uint32),
                    ('sin6_addr',     In6Addr),
                    ('sin6_scope_id', ctypes.c_uint32)]
    
    # struct addrinfo from netdb.h
    class AddrInfo(ctypes.Structure):
        _fields_ = [('ai_flags',     ctypes.c_int),
                    ('ai_family',    ctypes.c_int),
                    ('ai_socktype',  ctypes.c_int),
                    ('ai_protocol',  ctypes.c_int),
                    ('ai_addrlen',   ctypes.c_size_t),
                    ('ai_addr',      ctypes.c_void_p),
                    ('ai_canonname', ctypes.c_char_p),
                    ('ai_next',      ctypes.c_void_p)]
    
        def interp (self, field_id, value):
            switcher = { 1 : lambda x : 'v4'     if (x == socket.AF_INET )    else
                                        'v6'     if (x == socket.AF_INET6)    else 'unknown',
                         2 : lambda x : 'dgram'  if (x == socket.SOCK_DGRAM)  else 
                                        'stream' if (x == socket.SOCK_STREAM) else
                                        'raw'    if (x == socket.SOCK_RAW)    else 'unknown',
                         3 : lambda x : 'auto' if (x == 0) else 
                                        'tcp'  if (x == socket.IPPROTO_TCP)   else
                                        'udp'  if (x == socket.IPPROTO_UDP)   else 'unknown',
                         5 : lambda x : (ctypes.cast(x,ctypes.POINTER(SockAddrIn4)) if self.ai_family == socket.AF_INET else
                                         ctypes.cast(x,ctypes.POINTER(SockAddrIn6)) ).contents }
            return switcher[field_id](value) if field_id in switcher else repr(value)
        
        def __repr__(self):
            '''Print the fields'''
            res = []
            for idx, field in enumerate(self._fields_):
                res.append('%s=%s' % (field[0], self.interp(idx, getattr(self, field[0]) ) ) )
            return self.__class__.__name__ + '(' + ','.join(res) + ')'
    
    return {'AddrInfo':AddrInfo,
            'SockAddrIn4': SockAddrIn4,
            'SockAddrIn6': SockAddrIn6 }[name]
    
PORT          = 49
READ_TIMEOUT  = 180
WRITE_TIMEOUT = 180

# struct tac_attrib from libtac.h
class Attrib(ctypes.Structure):
    _fields_ = [("attr",     ctypes.c_char_p), 
                ("attr_len", ctypes.c_ubyte),
                ("next",     ctypes.c_void_p) ]
    def __init__(self, name, value):
        '''free attributes objects'''
        self.attr = ''
        self.attr_len = 0
        self.next = None
        self.add(name,value)

    def add(self, name, value = None):
        '''Add a TACACS attribute'''
        p_addr  = ctypes.pointer(self)
        pp_addr = ctypes.pointer(p_addr) 
        p_value = None
        try:
            p_value = ctypes.c_char_p(str(value))
        except TypeError:
            pass
        libtac.tac_add_attrib(pp_addr, ctypes.c_char_p(name), p_value)

    def __del__(self):
        '''free attributes objects'''
        if self.next:
            p_addr  = ctypes.cast(self.next, ctypes.POINTER(Attrib))
            pp_addr = ctypes.pointer(p_addr) 
            libtac.tac_free_attrib(pp_addr)
            self.next = 0

    def __repr__(self):
        '''Print the fields'''
        res = [self.attr]
        if self.next :
            next = ctypes.cast(self.next, ctypes.POINTER(Attrib)).contents
            res.append(repr(next))
        return '->'.join(res)

def version():
    '''Print the version of libtac'''
    M = ctypes.c_int.in_dll(libtac, 'tac_ver_major').value
    m = ctypes.c_int.in_dll(libtac, 'tac_ver_minor').value
    p = ctypes.c_int.in_dll(libtac, 'tac_ver_patch').value
    return 'libtac-' + '.'.join(map(str,[M,m,p]))

def session_id():
    return ctypes.c_int.in_dll(libtac,'session_id').value 

def tac_priv_lvl():
    return ctypes.c_int.in_dll(libtac,'tac_priv_lvl').value

def tac_authen_method():
    return ctypes.c_int.in_dll(libtac,'tac_authen_method').value

def tac_authen_service():
    return ctypes.c_int.in_dll(libtac,'tac_authen_service').value

def tac_readtimeout_enable():
    return ctypes.c_int.in_dll(libtac,'tac_readtimeout_enable').value

def tac_timeout():
    return ctypes.c_int.in_dll(libtac,'tac_timeout').value

ServerParameter     = namedtuple('ServerParameter',     ['hostname','port'])
ConnectionParameter = namedtuple('ConnectionParameter', ['server','key'])

class TacError(Exception):
    def __init__(self, k):
        errors = { -9: 'Connection Error',   # -9
                   -8: 'Connection Timeout', # -8
                   -7: 'Short Body',         # -7
                   -6: 'Short Header',       # -6
                   -5: 'Write Error',        # -5
                   -4: 'Write Timeout',      # -4
                   -3: 'Read Timeout',       # -3
                   -2: 'Protocol Error',     # -2
                   -1: 'Assembly Error',     # -1
                 }
        
        super(TacError, self).__init__( errors[k] if k in errors else 'Unknown Error')
        
class AccountingFlags():
    more     = 1
    start    = 2
    stop     = 4
    watchdog = 8
    
class Connection():
    # struct areply from libtac.h
    @staticmethod
    def __construct_reply():
        class _Reply(ctypes.Structure):
            _fields_ = [('attr',    ctypes.POINTER(Attrib)),
                        ('msg',     ctypes.c_char_p),
                        ('status',  ctypes.c_int)]
            def interp (self, field_id, value):
                '''interpret the field value'''
                switcher = { 0 : lambda x : repr(x.contents) if x else None }
                return switcher[field_id](value) if field_id in switcher else repr(value)
            def __repr__(self):
                '''Print the fields'''
                res = []
                for idx, field in enumerate(self._fields_):
                    res.append('%s=%s' % (field[0], self.interp(idx, getattr(self, field[0]) ) ) )
                return self.__class__.__name__ + '(' + ','.join(res) + ')'
        return _Reply()
    
    def __init__(self, socket_fd):
        if type(socket_fd).__name__ != 'socket':
            raise TypeError("socket_fd not an socket object")
        self.socket = socket_fd;

    def close(self):
        self.socket.close()
        
    def continue_send(self, passwd):
        ''' this function sends a continue packet do TACACS+ server, asking
            for validation of given password'''
        e = libtac.tac_cont_send(ctypes.c_int(self.socket.fileno()),
                                 ctypes.c_char_p(passwd))
        if e < 0:
            raise TacError(e)
        return True
    
    def authen_send(self, user, passwd, tty, hostname = socket.gethostname() ):
        e = libtac.tac_authen_send(ctypes.c_int(self.socket.fileno()),
                                   ctypes.c_char_p(user),
                                   ctypes.c_char_p(passwd),
                                   ctypes.c_char_p(tty),
                                   ctypes.c_char_p(hostname))
        if e < 0:
            raise TacError(e)
        return True

    def author_send(self, user, tty, attr, hostname = socket.gethostname()):
        attr_pointer = None
        if type(attr) == Attrib:
            attr_pointer = ctypes.pointer(attr)

        e = libtac.tac_author_send(ctypes.c_int(self.socket.fileno()),
                                   ctypes.c_char_p(user),
                                   ctypes.c_char_p(tty),
                                   ctypes.c_char_p(hostname),
                                   attr_pointer)
        if e < 0:
            raise TacError(e)
        return True
    
    def acct_send(self, flag, user, tty, attr, hostname = socket.gethostname()):
        if flag < 1 or flag > 8:
            raise ValueError("type parameter must be int 1-8")
        
        attr_pointer = None
        if type(attr) == Attrib:
            attr_pointer = ctypes.pointer(attr)

        e = libtac.tac_acct_send(ctypes.c_int(self.socket.fileno()),
                                 ctypes.c_int(flag),
                                 ctypes.c_char_p(user),
                                 ctypes.c_char_p(tty),
                                 ctypes.c_char_p(hostname),
                                 attr_pointer)
        if e < 0:
            raise TacError(e)
        return True
        
    def authen_recv(self):
        e = libtac.tac_authen_read(ctypes.c_int(self.socket.fileno()))
        if e < 0:
            raise TacError(e)

        reply = {1 : 'Pass',     # 1
                 2 : 'Fail',     # 2
                 3 : 'Get Data', # 3
                 4 : 'Get User', # 4
                 5 : 'Get Pass', # 5
                 6 : 'Restart',  # 6
                 7 : 'Error',    # 7
               0x21: 'Follow'}

        return (e, reply[e] if e in reply else 'Unknown Authentication Reply')

    def author_recv(self):
        reply_msg = Connection.__construct_reply()
        e = libtac.tac_author_read(ctypes.c_int(self.socket.fileno()),
                                   ctypes.pointer(reply_msg)) 
        if e < 0:
            raise TacError(e)

        reply = {1 : 'Pass Add',     # 1
                 2 : 'Pass Repl',    # 2
               0x10: 'Fail',         # 16
               0x11: 'Error',        # 17
               0x21: 'Follow'        # 33
                }

        return (reply_msg, reply[e] if e in reply else 'Unknown Authorization Reply')
    
    def acct_recv(self):
        reply_msg = Connection.__construct_reply()
        e = libtac.tac_acct_read(ctypes.c_int(self.socket.fileno()),
                                   ctypes.pointer(reply_msg)) 
        if e < 0:
            raise TacError(e)

        reply = {1 : 'Success',     # 1
                 2 : 'Error',       # 2
               0x21: 'Follow'       # 33
                }

        return (reply_msg, reply[e] if e in reply else 'Unknown Accounting Reply')

def   connect(connection, login_type = None):
    class login():
        def __init__(self, x):
            self.value = x 
    
        @property
        def value(self):
            return (ctypes.c_char * 64).in_dll(libtac, 'tac_login')
        
        @value.setter
        def value(self,x):
            if x == None:
                (ctypes.c_char * 64).in_dll(libtac, 'tac_login').value = ''
            elif type(x) == str :
                (ctypes.c_char * 64).in_dll(libtac, 'tac_login').value = x[:64]
            else :
                raise TypeError("String Required")
    
    login(login_type)
    
    rval = -9
    if type(connection) == list:
        for conn in connection:
            try:
                return connect(conn)
            except TacError:
                pass
        raise TacError(rval)
    elif type(connection) != ConnectionParameter:
        raise TypeError("not a Connection tuple")
    elif type(connection.key) != str:
        raise TypeError("key must be a string")
    elif type(connection.server) != ServerParameter:
        raise TypeError("server must be a Server Parameter")
    elif type(connection.server.hostname) != str:
        raise TypeError("server.hostname must be a string")
    _info = socket.getaddrinfo(connection.server.hostname, connection.server.port)
    _addrinfo = __net_class('AddrInfo')()
    
    for ai in _info:
        if ai[1] != socket.SOCK_STREAM:
            continue
        
        _key      = ctypes.c_char_p(connection.key)
        _addrinfo.ai_family    = ai[0]
        _addrinfo.ai_socktype  = ai[1]
        _addrinfo.ai_protocol  = ai[2]
        _addrinfo.ai_canonname = ai[3]
        
        if len(ai[4]) is socket.AF_INET:
            v4addr = __net_class('SockAddrIn4')()
            v4addr.sin_family      = ai[0]
            v4addr.sin_port        = socket.htons(ai[4][1])
            n_byte_order_packed    = socket.inet_aton(ai[4][0])
            n_byte_order_unpacked  = socket.htonl(struct.unpack("!L", n_byte_order_packed)[0])
            v4addr.sin_addr.s_addr = n_byte_order_unpacked 
            _addrinfo.ai_addrlen   = ctypes.sizeof(v4addr)
            _addrinfo.ai_addr      = ctypes.cast(ctypes.pointer(v4addr), ctypes.c_void_p)
        
        rVal = libtac.tac_connect_single(ctypes.pointer(_addrinfo), _key, None)
        if rVal >= 0:
            return Connection(socket.fromfd(rVal,ai[0],ai[1],ai[2]))
    
    raise TacError(rval)
