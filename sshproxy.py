#
# Windows only.
#
import sys
if sys.platform != 'win32': # pragma: no cover
    raise ImportError (str(e) + """
sys.platform != 'win32': SSHProxy supports only Windows.""")

#
# Import built in modules
#
import warnings
import logging
import os
import time
import re
import select
import shutil
import struct
import types
import errno
import traceback
import signal
import pkg_resources 
from io import StringIO

try:
    from ctypes import windll
    import pywintypes
    from win32com.shell.shellcon import CSIDL_APPDATA
    from win32com.shell.shell import SHGetSpecialFolderPath
    import win32console
    import win32process
    import win32con
    import win32gui
    import win32api
    import win32file
    import winerror
except ImportError as e: # pragma: no cover
    raise ImportError(str(e) + "\nThis package requires the win32 python packages.\r\nInstall with pip install pywin32")

# 
# System-wide constants
#    
screenbufferfillchar = '\4'
maxconsoleY = 8000

warnings.simplefilter("always", category=DeprecationWarning)
deprecation_warning = '''
################################## WARNING ##################################
{} is deprecated, and will be removed soon.
Please contact me and report it at https://gitlab.com/mrluaf/sshproxy if you use it.
################################## WARNING ##################################
'''

# The version is handled by the package: pbr, which derives the version from the git tags.
try:
    __version__ = pkg_resources.require("sshproxy")[0].version
except: # pragma: no cover
    __version__ = '0.0.1'

__all__ = ['ExceptionPexpect', 'EOF', 'TIMEOUT', 'spawn', 'run', 'which',
    'split_command_line', '__version__', 'start']

#
# Create logger: We write logs only to file. Printing out logs are dangerous, because of the deep
# console manipulation.
#
logger = logging.getLogger('sshproxy')
if 'dev' in __version__ :
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)
fh = logging.FileHandler('sshproxy.log', 'w', 'utf-8')
formatter = logging.Formatter('%(asctime)s - %(filename)s::%(funcName)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)

# Test the logger
logger.info('sshproxy imported; logger working')

####################################################################################################
#
#        Exceptions
#
####################################################################################################

class ExceptionPexpect(Exception):
    """Base class for all exceptions raised by this module.
    """

    def __init__(self, value):

        self.value = value

    def __str__(self):

        return str(self.value)

    def get_trace(self):
        """This returns an abbreviated stack trace with lines that only concern
        the caller. In other words, the stack trace inside the sshproxy module
        is not included. """

        tblist = traceback.extract_tb(sys.exc_info()[2])
        tblist = [item for item in tblist if self.__filter_not_wexpect(item)]
        tblist = traceback.format_list(tblist)
        return ''.join(tblist)

    def __filter_not_wexpect(self, trace_list_item):

        if trace_list_item[0].find('sshproxy.py') == -1:
            return True
        else:
            return False


class EOF(ExceptionPexpect):
    """Raised when EOF is read from a child. This usually means the child has exited.
    The user can wait to EOF, which means he waits the end of the execution of the child process."""

class TIMEOUT(ExceptionPexpect):
    """Raised when a read time exceeds the timeout. """


def run (command, timeout=-1, withexitstatus=False, events=None, extra_args=None, logfile=None, cwd=None, env=None):
    if timeout == -1:
        child = spawn(command, maxread=2000, logfile=logfile, cwd=cwd, env=env)
    else:
        child = spawn(command, timeout=timeout, maxread=2000, logfile=logfile, cwd=cwd, env=env)
    if events is not None:
        patterns = list(events.keys())
        responses = list(events.values())
    else:
        patterns=None # We assume that EOF or TIMEOUT will save us.
        responses=None
    child_result_list = []
    event_count = 0
    while 1:
        try:
            index = child.expect (patterns)
            if type(child.after) in (str,):
                child_result_list.append(child.before + child.after)
            else: # child.after may have been a TIMEOUT or EOF, so don't cat those.
                child_result_list.append(child.before)
            if type(responses[index]) in (str,):
                child.send(responses[index])
            elif type(responses[index]) is types.FunctionType:
                callback_result = responses[index](locals())
                sys.stdout.flush()
                if type(callback_result) in (str,):
                    child.send(callback_result)
                elif callback_result:
                    break
            else:
                raise TypeError ('The callback must be a string or function type.')
            event_count = event_count + 1
        except TIMEOUT as e:
            child_result_list.append(child.before)
            break
        except EOF as e:
            child_result_list.append(child.before)
            break
    child_result = ''.join(child_result_list)
    if withexitstatus:
        child.close()
        return (child_result, child.exitstatus)
    else:
        return child_result

def spawn(command, args=[], timeout=30, maxread=2000, searchwindowsize=None, logfile=None, cwd=None, env=None,
          codepage=None):

    log('=' * 80)
    log('Buffer size: %s' % maxread)
    if searchwindowsize:
        log('Search window size: %s' % searchwindowsize)
    log('Timeout: %ss' % timeout)
    if env:
        log('Environment:')
        for name in env:
            log('\t%s=%s' % (name, env[name]))
    if cwd:
        log('Working directory: %s' % cwd)
        
    return spawn_windows(command, args, timeout, maxread, searchwindowsize, logfile, cwd, env,
                             codepage)        

class spawn_windows ():
    def __init__(self, command, args=[], timeout=30, maxread=60000, searchwindowsize=None, logfile=None, cwd=None, env=None,
                 codepage=None):
        """ The spawn_windows constructor. Do not call it directly. Use spawn(), or run() instead.
        """
        self.codepage = codepage
        
        self.stdin = sys.stdin
        self.stdout = sys.stdout
        self.stderr = sys.stderr

        self.searcher = None
        self.ignorecase = False
        self.before = None
        self.after = None
        self.match = None
        self.match_index = None
        self.terminated = True
        self.exitstatus = None
        self.signalstatus = None
        self.status = None # status returned by os.waitpid
        self.flag_eof = False
        self.pid = None
        self.child_fd = -1 # initially closed
        self.timeout = timeout
        self.delimiter = EOF
        self.logfile = logfile
        self.logfile_read = None # input from child (read_nonblocking)
        self.logfile_send = None # output to send (send, sendline)
        self.maxread = maxread # max bytes to read at one time into buffer
        self.buffer = '' # This is the read buffer. See maxread.
        self.searchwindowsize = searchwindowsize # Anything before searchwindowsize point is preserved, but not searched.
        self.delaybeforesend = 0.05 # Sets sleep time used just before sending data to child. Time in seconds.
        self.delayafterclose = 0.1 # Sets delay in close() method to allow kernel time to update process status. Time in seconds.
        self.delayafterterminate = 0.1 # Sets delay in terminate() method to allow kernel time to update process status. Time in seconds.
        self.softspace = False # File-like object.
        self.name = '<' + repr(self) + '>' # File-like object.
        self.encoding = None # File-like object.
        self.closed = True # File-like object.
        self.ocwd = os.getcwd()
        self.cwd = cwd
        self.env = env
        
        # allow dummy instances for subclasses that may not use command or args.
        if command is None:
            self.command = None
            self.args = None
            self.name = '<sshproxy factory incomplete>'
        else:
            self._spawn (command, args)

    def __del__(self):
        """This makes sure that no system resources are left open. Python only
        garbage collects Python objects, not the child console."""
        
        try:
            self.wtty.terminate_child()
        except:
            pass
           
    def __str__(self):

        """This returns a human-readable string that represents the state of
        the object. """

        s = []
        s.append(repr(self))
        s.append('version: ' + __version__)
        s.append('command: ' + str(self.command))
        s.append('args: ' + str(self.args))
        s.append('searcher: ' + str(self.searcher))
        s.append('buffer (last 100 chars): ' + str(self.buffer)[-100:])
        s.append('before (last 100 chars): ' + str(self.before)[-100:])
        s.append('after: ' + str(self.after))
        s.append('match: ' + str(self.match))
        s.append('match_index: ' + str(self.match_index))
        s.append('exitstatus: ' + str(self.exitstatus))
        s.append('flag_eof: ' + str(self.flag_eof))
        s.append('pid: ' + str(self.pid))
        s.append('child_fd: ' + str(self.child_fd))
        s.append('closed: ' + str(self.closed))
        s.append('timeout: ' + str(self.timeout))
        s.append('delimiter: ' + str(self.delimiter))
        s.append('logfile: ' + str(self.logfile))
        s.append('logfile_read: ' + str(self.logfile_read))
        s.append('logfile_send: ' + str(self.logfile_send))
        s.append('maxread: ' + str(self.maxread))
        s.append('ignorecase: ' + str(self.ignorecase))
        s.append('searchwindowsize: ' + str(self.searchwindowsize))
        s.append('delaybeforesend: ' + str(self.delaybeforesend))
        s.append('delayafterclose: ' + str(self.delayafterclose))
        s.append('delayafterterminate: ' + str(self.delayafterterminate))
        return '\n'.join(s)
 
    def _spawn(self,command,args=[]):

        # If command is an int type then it may represent a file descriptor.
        if type(command) == type(0):
            raise ExceptionPexpect ('Command is an int type. If this is a file descriptor then maybe you want to use fdpexpect.fdspawn which takes an existing file descriptor instead of a command string.')

        if type (args) != type([]):
            raise TypeError ('The argument, args, must be a list.')
   
        if args == []:
            self.args = split_command_line(command)
            self.command = self.args[0]
        else:
            self.args = args[:] # work with a copy
            self.args.insert (0, command)
            self.command = command    
            
        command_with_path = shutil.which(self.command)
        if command_with_path is None:
           raise ExceptionPexpect ('The command was not found or was not executable: %s.' % self.command)
        self.command = command_with_path
        self.args[0] = self.command

        self.name = '<' + ' '.join (self.args) + '>'

        #assert self.pid is None, 'The pid member should be None.'
        #assert self.command is not None, 'The command member should not be None.'

        self.wtty = Wtty(codepage=self.codepage)        
    
        if self.cwd is not None:
            os.chdir(self.cwd)
        
        self.child_fd = self.wtty.spawn(self.command, self.args, self.env)
        
        if self.cwd is not None:
            # Restore the original working dir
            os.chdir(self.ocwd)
            
        self.terminated = False
        self.closed = False
        self.pid = self.wtty.pid
        

    def fileno (self):   # File-like object.
        """There is no child fd."""
        
        return 0

    def close(self, force=True):   # File-like object.
        """ Closes the child console."""
        
        self.closed = self.terminate(force)
        if not self.closed:
            raise ExceptionPexpect ('close() could not terminate the child using terminate()')
        self.closed = True

    def isatty(self):   # File-like object.
        """The child is always created with a console."""
        
        return True

    def waitnoecho (self, timeout=-1): # pragma: no cover
        faulty_method_warning = '''
        ################################## WARNING ##################################
        waitnoecho() is faulty!
        Please contact me and report it at
        https://gitlab.com/mrluaf/sshproxy if you use it.
        ################################## WARNING ##################################
        '''
        warnings.warn(faulty_method_warning, DeprecationWarning)


        if timeout == -1:
            timeout = self.timeout
        if timeout is not None:
            end_time = time.time() + timeout 
        while True:
            if not self.getecho():
                return True
            if timeout < 0 and timeout is not None:
                return False
            if timeout is not None:
                timeout = end_time - time.time()
            time.sleep(0.1)

    def getecho (self): # pragma: no cover
        faulty_method_warning = '''
        ################################## WARNING ##################################
        setecho() is faulty!
        Please contact me and report it at
        https://gitlab.com/mrluaf/sshproxy if you use it.
        ################################## WARNING ##################################
        '''
        warnings.warn(faulty_method_warning, DeprecationWarning)
        """This returns the terminal echo mode. This returns True if echo is
        on or False if echo is off. Child applications that are expecting you
        to enter a password often set ECHO False. See waitnoecho()."""

        return self.wtty.getecho()

    def setecho (self, state): # pragma: no cover
        faulty_method_warning = '''
        ################################## WARNING ##################################
        setecho() is faulty!
        Please contact me and report it at
        https://gitlab.com/mrluaf/sshproxy if you use it.
        ################################## WARNING ##################################
        '''
        warnings.warn(faulty_method_warning, DeprecationWarning)

        """This sets the terminal echo mode on or off."""
        
        self.wtty.setecho(state)
        
    def read (self, size = -1):   # File-like object.

        """This reads at most "size" bytes from the file (less if the read hits
        EOF before obtaining size bytes). If the size argument is negative or
        omitted, read all data until EOF is reached. The bytes are returned as
        a string object. An empty string is returned when EOF is encountered
        immediately. """

        if size == 0:
            return ''
        if size < 0:
            self.expect (self.delimiter) # delimiter default is EOF
            return self.before

        # I could have done this more directly by not using expect(), but
        # I deliberately decided to couple read() to expect() so that
        # I would catch any bugs early and ensure consistant behavior.
        # It's a little less efficient, but there is less for me to
        # worry about if I have to later modify read() or expect().
        # Note, it's OK if size==-1 in the regex. That just means it
        # will never match anything in which case we stop only on EOF.
        cre = re.compile('.{%d}' % size, re.DOTALL)
        index = self.expect ([cre, self.delimiter]) # delimiter default is EOF
        if index == 0:
            return self.after ### self.before should be ''. Should I assert this?
        return self.before

    def readline (self, size = -1):    # File-like object.

        """This reads and returns one entire line. A trailing newline is kept
        in the string, but may be absent when a file ends with an incomplete
        line. Note: This readline() looks for a \\r\\n pair even on UNIX
        because this is what the pseudo tty device returns. So contrary to what
        you may expect you will receive the newline as \\r\\n. An empty string
        is returned when EOF is hit immediately. Currently, the size argument is
        mostly ignored, so this behavior is not standard for a file-like
        object. If size is 0 then an empty string is returned. """

        if size == 0:
            return ''
        index = self.expect (['\r\n', self.delimiter]) # delimiter default is EOF
        if index == 0:
            return self.before + '\r\n'
        else:
            return self.before

    def __iter__ (self):    # File-like object.

        """This is to support iterators over a file-like object.
        """

        return self

    def __next__ (self):    # File-like object.

        """This is to support iterators over a file-like object.
        """

        result = self.readline()
        if self.after == self.delimiter:
            raise StopIteration
        return result

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.terminate()

    def readlines (self, sizehint = -1):    # File-like object.

        """This reads until EOF using readline() and returns a list containing
        the lines thus read. The optional "sizehint" argument is ignored. """

        lines = []
        while True:
            line = self.readline()
            if not line:
                break
            lines.append(line)
        return lines

    def read_nonblocking (self, size = 1, timeout = -1):
        """This reads at most size characters from the child application. It
        includes a timeout. If the read does not complete within the timeout
        period then a TIMEOUT exception is raised. If the end of file is read
        then an EOF exception will be raised. If a log file was set using
        setlog() then all data will also be written to the log file.

        If timeout is None then the read may block indefinitely. If timeout is -1
        then the self.timeout value is used. If timeout is 0 then the child is
        polled and if there was no data immediately ready then this will raise
        a TIMEOUT exception.

        The timeout refers only to the amount of time to read at least one
        character. This is not effected by the 'size' parameter, so if you call
        read_nonblocking(size=100, timeout=30) and only one character is
        available right away then one character will be returned immediately.
        It will not wait for 30 seconds for another 99 characters to come in.

        This is a wrapper around Wtty.read(). """

        if self.closed:
            raise ValueError ('I/O operation on closed file in read_nonblocking().')
        
        if timeout == -1:
            timeout = self.timeout
         
        s = self.wtty.read_nonblocking(timeout, size)
        
        if s == '':
            if not self.wtty.isalive():
                self.flag_eof = True
                raise EOF('End Of File (EOF) in read_nonblocking().')
            if timeout is None:
                # Do not raise TIMEOUT because we might be waiting for EOF
                # sleep to keep CPU utilization down
                time.sleep(.05)
            else:
                raise TIMEOUT ('Timeout exceeded in read_nonblocking().')
        
        if self.logfile is not None:
            self.logfile.write (s)
            self.logfile.flush()
        if self.logfile_read is not None:
            self.logfile_read.write (s)
            self.logfile_read.flush()

        return s

    def write(self, s):   # File-like object.

        """This is similar to send() except that there is no return value.
        """

        self.send (s)

    def writelines (self, sequence):   # File-like object.

        """This calls write() for each element in the sequence. The sequence
        can be any iterable object producing strings, typically a list of
        strings. This does not add line separators There is no return value.
        """

        for s in sequence:
            self.write (s)

    def sendline(self, s=''):

        """This is like send(), but it adds a line feed (os.linesep). This
        returns the number of bytes written. """

        n = self.send(s)
        n = n + self.send (os.linesep)
        return n

    def sendeof(self):

        """This sends an EOF to the child. This sends a character which causes
        the pending parent output buffer to be sent to the waiting child
        program without waiting for end-of-line. If it is the first character
        of the line, the read() in the user program returns 0, which signifies
        end-of-file. This means to work as expected a sendeof() has to be
        called at the beginning of a line. This method does not send a newline.
        It is the responsibility of the caller to ensure the eof is sent at the
        beginning of a line. """

        # platform does not define VEOF so assume CTRL-D
        char = chr(4)
        self.send(char)

    def send(self, s):
        """This sends a string to the child process. This returns the number of
        bytes written. If a log file was set then the data is also written to
        the log. """
        
        (self.delaybeforesend)
        if self.logfile is not None:
            self.logfile.write (s)
            self.logfile.flush()
        if self.logfile_send is not None:
            self.logfile_send.write (s)
            self.logfile_send.flush()
        c = self.wtty.write(s)
        return c

    def sendintr(self):
        """This sends a SIGINT to the child. It does not require
        the SIGINT to be the first character on a line. """
        
        self.wtty.sendintr()

    def eof (self):

        """This returns True if the EOF exception was ever raised.
        """

        return self.flag_eof

    def terminate(self, force=False):
        """Terminate the child. Force not used. """

        if not self.isalive():
            return True
            
        self.wtty.terminate_child()
        time.sleep(self.delayafterterminate)
        if not self.isalive():
            return True
                
        return False

    def kill(self, sig):
        """Sig == sigint for ctrl-c otherwise the child is terminated."""
        
        if not self.isalive():
            return
            
        if sig == signal.SIGINT:
            self.wtty.sendintr()
        else:
            self.wtty.terminate_child()
        
    def wait(self):
        while self.isalive():
            time.sleep(.05)  # Keep CPU utilization down
        
        return self.exitstatus
        
    def isalive(self):
        """Determines if the child is still alive."""
        
        if self.terminated:
            return False
        
        if self.wtty.isalive():
            return True
        else:
            self.exitstatus = win32process.GetExitCodeProcess(self.wtty.getchild())
            self.status = (self.pid, self.exitstatus << 8)  # left-shift exit status by 8 bits like os.waitpid
            self.terminated = True
            return False

    def compile_pattern_list(self, patterns):

        if patterns is None:
            return []
        if type(patterns) is not list:
            patterns = [patterns]

        compile_flags = re.DOTALL # Allow dot to match \n
        if self.ignorecase:
            compile_flags = compile_flags | re.IGNORECASE
        compiled_pattern_list = []
        for p in patterns:
            if type(p) in (str,):
                compiled_pattern_list.append(re.compile(p, compile_flags))
            elif p is EOF:
                compiled_pattern_list.append(EOF)
            elif p is TIMEOUT:
                compiled_pattern_list.append(TIMEOUT)
            elif type(p) is type(re.compile('')):
                compiled_pattern_list.append(p)
            else:
                raise TypeError ('Argument must be one of StringTypes, EOF, TIMEOUT, SRE_Pattern, or a list of those type. %s' % str(type(p)))

        return compiled_pattern_list

    def expect(self, pattern, timeout = -1, searchwindowsize=None):
        compiled_pattern_list = self.compile_pattern_list(pattern)
        return self.expect_list(compiled_pattern_list, timeout, searchwindowsize)

    def expect_list(self, pattern_list, timeout = -1, searchwindowsize = -1):

        return self.expect_loop(searcher_re(pattern_list), timeout, searchwindowsize)

    def expect_exact(self, pattern_list, timeout = -1, searchwindowsize = -1):

        if not isinstance(pattern_list, list): 
            pattern_list = [pattern_list]
            
        for p in pattern_list:
            if type(p) not in (str,) and p not in (TIMEOUT, EOF):
                raise TypeError ('Argument must be one of StringTypes, EOF, TIMEOUT, or a list of those type. %s' % str(type(p)))
            
        return self.expect_loop(searcher_string(pattern_list), timeout, searchwindowsize)

    def expect_loop(self, searcher, timeout = -1, searchwindowsize = -1):

        self.searcher = searcher

        if timeout == -1:
            timeout = self.timeout
        if timeout is not None:
            end_time = time.time() + timeout 
        if searchwindowsize == -1:
            searchwindowsize = self.searchwindowsize

        try:
            incoming = self.buffer
            freshlen = len(incoming)
            while True: # Keep reading until exception or return.
                index = searcher.search(incoming, freshlen, searchwindowsize)
                if index >= 0:
                    self.buffer = incoming[searcher.end : ]
                    self.before = incoming[ : searcher.start]
                    self.after = incoming[searcher.start : searcher.end]
                    self.match = searcher.match
                    self.match_index = index
                    return self.match_index
                # No match at this point
                if timeout is not None and timeout < 0:
                    raise TIMEOUT ('Timeout exceeded in expect_any().')
                # Still have time left, so read more data
                c = self.read_nonblocking(self.maxread, timeout)
                freshlen = len(c)
                time.sleep (0.0001)
                incoming += c
                if timeout is not None:
                    timeout = end_time - time.time()
        except EOF as e:
            self.buffer = ''
            self.before = incoming
            self.after = EOF
            index = searcher.eof_index
            if index >= 0:
                self.match = EOF
                self.match_index = index
                return self.match_index
            else:
                self.match = None
                self.match_index = None
                raise EOF (str(e) + '\n' + str(self))
        except TIMEOUT as e:
            self.buffer = incoming
            self.before = incoming
            self.after = TIMEOUT
            index = searcher.timeout_index
            if index >= 0:
                self.match = TIMEOUT
                self.match_index = index
                return self.match_index
            else:
                self.match = None
                self.match_index = None
                raise TIMEOUT (str(e) + '\n' + str(self))
        except:
            self.before = incoming
            self.after = None
            self.match = None
            self.match_index = None
            raise

    def getwinsize(self):        
        return self.wtty.getwinsize()

    def setwinsize(self, r, c):
        """Set the size of the child screen buffer. """
    
        self.wtty.setwinsize(r, c)
      
    ### Prototype changed
    def interact(self):
        """Makes the child console visible for interaction"""
        
        self.wtty.interact()
    
    ### Prototype changed
    def stop_interact(self):
        """Hides the child console from the user."""
    
        self.wtty.stop_interact()

##############################################################################
# End of spawn_windows class
##############################################################################

class Wtty:

    def __init__(self, timeout=30, codepage=None):
        self.__buffer = StringIO()
        self.__bufferY = 0
        self.__currentReadCo = win32console.PyCOORDType(0, 0)
        self.__consSize = [80, 16000]
        self.__parentPid = 0
        self.__oproc = 0
        self.conpid = 0
        self.__otid = 0
        self.__switch = True
        self.__childProcess = None
        self.__conProcess = None
        self.codepage = codepage
        self.console = False
        self.lastRead = 0
        self.lastReadData = ""
        self.pid = None
        self.processList = []
        self.__consout = None
        # We need a timeout for connecting to the child process
        self.timeout = timeout
        self.totalRead = 0
            
    def spawn(self, command, args=[], env=None):
        """Spawns spawner.py with correct arguments."""
        
        ts = time.time()
        self.startChild(args, env)
            
        while True:
            msg = win32gui.GetMessage(0, 0, 0)
            childPid = msg[1][2]
            # Sometimes win32gui.GetMessage returns a bogus PID, so keep calling it
            # until we can successfully connect to the child or timeout is
            # reached
            if childPid:
                try:
                    self.__childProcess = win32api.OpenProcess(
                        win32con.PROCESS_TERMINATE | win32con.PROCESS_QUERY_INFORMATION, False, childPid)
                    self.__conProcess = win32api.OpenProcess(
                        win32con.PROCESS_TERMINATE | win32con.PROCESS_QUERY_INFORMATION, False, self.conpid)
                except pywintypes.error as e:
                    if time.time() > ts + self.timeout:
                        break
                else:
                    self.pid = childPid
                    break
            time.sleep(.05)
        
        if not self.__childProcess:
            raise ExceptionPexpect ('The process ' + args[0] + ' could not be started.') 
        
                                                                                                              
        
        winHandle = int(win32console.GetConsoleWindow())
        
        self.__switch = True
        
        if winHandle != 0:
            self.__parentPid = win32process.GetWindowThreadProcessId(winHandle)[1]    
            # Do we have a console attached? Do not rely on winHandle, because
            # it will also be non-zero if we didn't have a console, and then 
            # spawned a child process! Using sys.stdout.isatty() seems safe
            self.console = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
            # If the original process had a console, record a list of attached
            # processes so we can check if we need to reattach/reallocate the 
            # console later
            self.processList = win32console.GetConsoleProcessList()
        else:
            self.switchTo(False)
            self.__switch = False
   
    def startChild(self, args, env):
        si = win32process.GetStartupInfo()
        si.dwFlags = win32process.STARTF_USESHOWWINDOW
        si.wShowWindow = win32con.SW_HIDE
        # (eg. py2exe deployment), of the packed executable
        dirname = os.path.dirname(sys.executable 
                                  if getattr(sys, 'frozen', False) else 
                                  os.path.abspath(__file__))
        if getattr(sys, 'frozen', False):
            logdir = os.path.splitext(sys.executable)[0]
        else:
            logdir = dirname
        logdir = os.path.basename(logdir)
        spath = [dirname]
        pyargs = ['-c']
        if getattr(sys, 'frozen', False):
            # If we are running 'frozen', add library.zip and lib\library.zip
            # to sys.path
            # py2exe: Needs appropriate 'zipfile' option in setup script and 
            # 'bundle_files' 3
            spath.append(os.path.join(dirname, 'library.zip'))
            spath.append(os.path.join(dirname, 'library.zip', 
                                      os.path.basename(os.path.splitext(sys.executable)[0])))
            if os.path.isdir(os.path.join(dirname, 'lib')):
                dirname = os.path.join(dirname, 'lib')
                spath.append(os.path.join(dirname, 'library.zip'))
                spath.append(os.path.join(dirname, 'library.zip', 
                                          os.path.basename(os.path.splitext(sys.executable)[0])))
            pyargs.insert(0, '-S')  # skip 'import site'
        pid = win32process.GetCurrentProcessId()
        tid = win32api.GetCurrentThreadId()
        cp = self.codepage or windll.kernel32.GetACP()
        # If we are running 'frozen', expect python.exe in the same directory
        # as the packed executable.
        # py2exe: The python executable can be included via setup script by 
        # adding it to 'data_files'
        commandLine = '"%s" %s "%s"' % (os.path.join(dirname, 'python.exe') 
                                        if getattr(sys, 'frozen', False) else 
                                        os.path.join(os.path.dirname(sys.executable), 'python.exe'), 
                                        ' '.join(pyargs), 
                                        "import sys; sys.path = %r + sys.path;"
                                        "args = %r; import sshproxy;"
                                        "sshproxy.ConsoleReader(sshproxy.join_args(args), %i, %i, cp=%i, logdir=%r)" % (spath, args, pid, tid, cp, logdir))
                     
        
        self.__oproc, _, self.conpid, self.__otid = win32process.CreateProcess(None, commandLine, None, None, False, 
                                                                  win32process.CREATE_NEW_CONSOLE, env, None, si)
            
   
    def switchTo(self, attatched=True):
        """Releases from the current console and attatches
        to the childs."""
        
        if not self.__switch:
            return
        
        try:
            # No 'attached' check is needed, FreeConsole() can be called multiple times.
            win32console.FreeConsole()
            # This is the workaround for #14. The #14 will still occure if the child process
            # finishes between this `isalive()` check and `AttachConsole(self.conpid)`. (However the
            # risk is low.)
            if not self.isalive(console=True):
                # When child has finished...
                raise EOF('End Of File (EOF) in switchTo().')
            
            win32console.AttachConsole(self.conpid)
            self.__consin = win32console.GetStdHandle(win32console.STD_INPUT_HANDLE)
            self.__consout = self.getConsoleOut()
            
        except pywintypes.error as e:
            # pywintypes.error: (5, 'AttachConsole', 'Access is denied.')
            # When child has finished...
            logging.info(e)
            # In case of any error: We "switch back" (attach) our original console, then raise the
            # error.
            self.switchBack()
            raise EOF('End Of File (EOF) in switchTo().')
        except:
            # In case of any error: We "switch back" (attach) our original console, then raise the
            # error.
            self.switchBack()
            raise
            
            
    def switchBack(self):
        """Releases from the current console and attaches 
        to the parents."""

        if not self.__switch:
            return
        
        if self.console:
            # If we originally had a console, re-attach it (or allocate a new one)
            # If we didn't have a console to begin with, there's no need to
            # re-attach/allocate
            win32console.FreeConsole()
            if len(self.processList) > 1:
                # Our original console is still present, re-attach
                win32console.AttachConsole(self.__parentPid)
            else:
                # Our original console has been free'd, allocate a new one
                win32console.AllocConsole()
        
        self.__consin = None
        self.__consout = None
    
    def getConsoleOut(self):
        consout = win32file.CreateFile('CONOUT$', 
                                       win32con.GENERIC_READ | win32con.GENERIC_WRITE, 
                                       win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE, 
                                       None, 
                                       win32con.OPEN_EXISTING, 
                                       0, 
                                       0)
                                       
        return win32console.PyConsoleScreenBufferType(consout)    
    
    def getchild(self):
        """Returns a handle to the child process."""
    
        return self.__childProcess
     
    def terminate_child(self):
        """Terminate the child process."""
        win32api.TerminateProcess(self.__childProcess, 1)
        # win32api.win32process.TerminateProcess(self.__childProcess, 1)
        
    def createKeyEvent(self, char):
        """Creates a single key record corrosponding to
            the ascii character char."""
        
        evt = win32console.PyINPUT_RECORDType(win32console.KEY_EVENT)
        evt.KeyDown = True
        evt.Char = char
        evt.RepeatCount = 1
        return evt    
    
    def write(self, s):
        """Writes input into the child consoles input buffer."""
    
        if len(s) == 0:
            return 0
        self.switchTo()
        try:
            if s[-1] == '\n':
                s = s[:-1]
            records = [self.createKeyEvent(c) for c in str(s)]
            if not self.__consout:
                return ""
            consinfo = self.__consout.GetConsoleScreenBufferInfo()
            startCo = consinfo['CursorPosition']
            wrote = self.__consin.WriteConsoleInput(records)
            ts = time.time()
            while self.__consin and self.__consin.PeekConsoleInput(8) != ():
                if time.time() > ts + len(s) * .05:
                    break
                time.sleep(.05)
            if self.__consout:
                self.__consout.FillConsoleOutputCharacter(screenbufferfillchar, len(s), startCo)
        except:
            self.switchBack()
            raise
        self.switchBack()
        return wrote
    
    def getCoord(self, offset):
        """Converts an offset to a point represented as a tuple."""
        
        x = offset % self.__consSize[0]
        y = offset // self.__consSize[0]
        return win32console.PyCOORDType(x, y)
   
    def getOffset(self, coord):
        """Converts a tuple-point to an offset."""
        
        return coord.X + coord.Y * self.__consSize[0]
   
    def readConsole(self, startCo, endCo):
        """Reads the console area from startCo to endCo and returns it
        as a string."""

        buff = []
        self.lastRead = 0

        while True:
            startOff = self.getOffset(startCo)
            endOff = self.getOffset(endCo)
            readlen = endOff - startOff
            
            if readlen <= 0:
                break
            
            if readlen > 4000:
                readlen = 4000
            endPoint = self.getCoord(startOff + readlen)

            s = self.__consout.ReadConsoleOutputCharacter(readlen, startCo)
            self.lastRead += len(s)
            self.totalRead += len(s)
            buff.append(s)

            startCo = endPoint

        return ''.join(buff)
   
    def parseData(self, s):
        """Ensures that special characters are interpretted as
        newlines or blanks, depending on if there written over
        characters or screen-buffer-fill characters."""
    
        strlist = []
        for i, c in enumerate(s):
            if c == screenbufferfillchar:
                if (self.totalRead - self.lastRead + i + 1) % self.__consSize[0] == 0:
                    strlist.append('\r\n')
            else:
                strlist.append(c)

        s = ''.join(strlist)
        return s
    
    
    def readConsoleToCursor(self):
        """Reads from the current read position to the current cursor
        position and inserts the string into self.__buffer."""
        
        if not self.__consout:
            return ""
    
        consinfo = self.__consout.GetConsoleScreenBufferInfo()
        cursorPos = consinfo['CursorPosition']
        
        #log('=' * 80)
        #log('cursor: %r, current: %r' % (cursorPos, self.__currentReadCo))

        isSameX = cursorPos.X == self.__currentReadCo.X
        isSameY = cursorPos.Y == self.__currentReadCo.Y
        isSamePos = isSameX and isSameY
        
        #log('isSameY: %r' % isSameY)
        #log('isSamePos: %r' % isSamePos)
        
        if isSameY or not self.lastReadData.endswith('\r\n'):
            # Read the current slice again
            self.totalRead -= self.lastRead
            self.__currentReadCo.X = 0
            self.__currentReadCo.Y = self.__bufferY
        
        #log('cursor: %r, current: %r' % (cursorPos, self.__currentReadCo))
        
        raw = self.readConsole(self.__currentReadCo, cursorPos)
        rawlist = []
        while raw:
            rawlist.append(raw[:self.__consSize[0]])
            raw = raw[self.__consSize[0]:]
        raw = ''.join(rawlist)
        s = self.parseData(raw)
        logger.debug(s)
        for i, line in enumerate(reversed(rawlist)):
            if line.endswith(screenbufferfillchar):
                # Record the Y offset where the most recent line break was detected
                self.__bufferY += len(rawlist) - i
                break
        
        #log('lastReadData: %r' % self.lastReadData)
        #log('s: %r' % s)
        
        #isSameData = False
        if isSamePos and self.lastReadData == s:
            #isSameData = True
            s = ''
        
        #log('isSameData: %r' % isSameData)
        #log('s: %r' % s)
        
        if s:
            lastReadData = self.lastReadData
            pos = self.getOffset(self.__currentReadCo)
            self.lastReadData = s
            if isSameY or not lastReadData.endswith('\r\n'):
                # Detect changed lines
                self.__buffer.seek(pos)
                buf = self.__buffer.read()
                #log('buf: %r' % buf)
                #log('raw: %r' % raw)
                if raw.startswith(buf):
                    # Line has grown
                    rawslice = raw[len(buf):]
                    # Update last read bytes so line breaks can be detected in parseData
                    lastRead = self.lastRead
                    self.lastRead = len(rawslice)
                    s = self.parseData(rawslice)
                    self.lastRead = lastRead
                else:
                    # Cursor has been repositioned
                    s = '\r' + s        
                #log('s:   %r' % s)
            self.__buffer.seek(pos)
            self.__buffer.truncate()
            self.__buffer.write(raw)

        self.__currentReadCo.X = cursorPos.X
        self.__currentReadCo.Y = cursorPos.Y

        return s
    
    
    def read_nonblocking(self, timeout, size):
        """Reads data from the console if available, otherwise
           waits timeout seconds, and writes the string 'None'
           to the pipe if no data is available after that time.""" 
          
        try:
            self.switchTo()
            
            while True:
                #Wait for child process to be paused
                if self.__currentReadCo.Y > maxconsoleY:
                    time.sleep(.2)
            
                start = time.time()
                s = self.readConsoleToCursor()
                
                if self.__currentReadCo.Y > maxconsoleY:
                    self.refreshConsole()
                
                if len(s) != 0:
                    return s
                
                if not self.isalive() or timeout <= 0:
                    return ''
                
                time.sleep(0.001)
                end = time.time()
                timeout -= end - start
                 
        except EOF as e:
            return ''
        finally:
            self.switchBack()
            
        raise Exception('Unreachable code...') # pragma: no cover
    
    
    def refreshConsole(self):
        """Clears the console after pausing the child and
        reading all the data currently on the console."""
    
        orig = win32console.PyCOORDType(0, 0)
        self.__consout.SetConsoleCursorPosition(orig)
        self.__currentReadCo.X = 0
        self.__currentReadCo.Y = 0
        writelen = self.__consSize[0] * self.__consSize[1]
        # Use NUL as fill char because it displays as whitespace
        # (if we interact() with the child)
        self.__consout.FillConsoleOutputCharacter(screenbufferfillchar, writelen, orig)
        
        self.__bufferY = 0
        self.__buffer.truncate(0)
        #consinfo = self.__consout.GetConsoleScreenBufferInfo()
        #cursorPos = consinfo['CursorPosition']
        #log('refreshConsole: cursorPos %s' % cursorPos)
        
    
    def setecho(self, state): # pragma: no cover
        faulty_method_warning = '''
        ################################## WARNING ##################################
        setecho() is faulty!
        Please contact me and report it at
        https://gitlab.com/mrluaf/sshproxy if you use it.
        ################################## WARNING ##################################
        '''
        warnings.warn(faulty_method_warning, DeprecationWarning)

        """Sets the echo mode of the child console."""
    
        self.switchTo()
        try:
            mode = self.__consin.GetConsoleMode()
            if state:
                mode |= 0x0004
            else:
                mode &= ~0x0004
            self.__consin.SetConsoleMode(mode)
        except:
            self.switchBack()
            raise
        self.switchBack()
        
    def getecho(self): # pragma: no cover
        faulty_method_warning = '''
        ################################## WARNING ##################################
        getecho() is faulty!
        Please contact me and report it at
        https://gitlab.com/mrluaf/sshproxy if you use it.
        ################################## WARNING ##################################
        '''
        warnings.warn(faulty_method_warning, DeprecationWarning)

        """Returns the echo mode of the child console."""
        
        self.switchTo()
        try:
            mode = self.__consin.GetConsoleMode()
            ret = (mode & 0x0004) > 0
        finally:
            self.switchBack()
        return ret  
      
    def getwinsize(self):
        """Returns the size of the child console as a tuple of
        (rows, columns)."""
    
        self.switchTo()
        try:
            size = self.__consout.GetConsoleScreenBufferInfo()['Size']
        finally:
            self.switchBack()
        return (size.Y, size.X)
        
    def setwinsize(self, r, c):
        """Sets the child console screen buffer size to (r, c)."""
        
        self.switchTo()
        try:
            self.__consout.SetConsoleScreenBufferSize(win32console.PyCOORDType(c, r))
        finally:
            self.switchBack()
       
    def interact(self):
        """Displays the child console for interaction."""
    
        self.switchTo()
        try:
            win32gui.ShowWindow(win32console.GetConsoleWindow(), win32con.SW_SHOW)
        finally:
            self.switchBack()
        
    def stop_interact(self):
        """Hides the child console."""
        
        self.switchTo()
        try:
            win32gui.ShowWindow(win32console.GetConsoleWindow(), win32con.SW_HIDE)
        finally:
            self.switchBack()
    
    def isalive(self, console=False):
        """True if the child is still alive, false otherwise"""
        
        if console:
            return win32process.GetExitCodeProcess(self.__conProcess) == win32con.STILL_ACTIVE
        else:
            return win32process.GetExitCodeProcess(self.__childProcess) == win32con.STILL_ACTIVE
    
class ConsoleReader: # pragma: no cover
   
    def __init__(self, path, pid, tid, env = None, cp=None, logdir=None):
        self.logdir = logdir
        log('=' * 80, 'consolereader', logdir)
        log("OEM code page: %s" % windll.kernel32.GetOEMCP(), 'consolereader', logdir)
        log("ANSI code page: %s" % windll.kernel32.GetACP(), 'consolereader', logdir)
        log("Console output code page: %s" % windll.kernel32.GetConsoleOutputCP(), 'consolereader', logdir)
        if cp:
            log("Setting console output code page to %s" % cp, 'consolereader', logdir)
            try:
                win32console.SetConsoleOutputCP(cp)
            except Exception as e:
                log(e, 'consolereader', logdir)
            else:
                log("Console output code page: %s" % windll.kernel32.GetConsoleOutputCP(), 'consolereader', logdir)
        log('Spawning %s' % path, 'consolereader', logdir)
        try:
            try:
                consout = self.getConsoleOut()
                self.initConsole(consout)
                
                si = win32process.GetStartupInfo()
                self.__childProcess, _, childPid, self.__tid = win32process.CreateProcess(None, path, None, None, False, 
                                                                             0, None, None, si)
            except Exception as e:
                log(e, 'consolereader', logdir)
                time.sleep(.1)
                win32api.PostThreadMessage(int(tid), win32con.WM_USER, 0, 0)
                sys.exit()
            
            time.sleep(.1)
            
            win32api.PostThreadMessage(int(tid), win32con.WM_USER, childPid, 0)
            
            parent = win32api.OpenProcess(win32con.PROCESS_TERMINATE | win32con.PROCESS_QUERY_INFORMATION , 0, int(pid))
            paused = False
   
            while True:
                consinfo = consout.GetConsoleScreenBufferInfo()
                cursorPos = consinfo['CursorPosition']
                
                if win32process.GetExitCodeProcess(parent) != win32con.STILL_ACTIVE or win32process.GetExitCodeProcess(self.__childProcess) != win32con.STILL_ACTIVE:
                    time.sleep(.1)
                    try:
                        win32process.TerminateProcess(self.__childProcess, 0)
                    except pywintypes.error as e:
                        # 'Access denied' happens always? Perhaps if not 
                        # running as admin (or UAC enabled under Vista/7). 
                        # Don't log. Child process will exit regardless when 
                        # calling sys.exit
                        if e.args[0] != winerror.ERROR_ACCESS_DENIED:
                            log(e, 'consolereader', logdir)
                    sys.exit()
                
                if cursorPos.Y > maxconsoleY and not paused:
                    #log('ConsoleReader.__init__: cursorPos %s' 
                               #% cursorPos, 'consolereader', logdir)
                    #log('suspendThread', 'consolereader', logdir)
                    self.suspendThread()
                    paused = True
                    
                if cursorPos.Y <= maxconsoleY and paused:
                    #log('ConsoleReader.__init__: cursorPos %s' 
                               #% cursorPos, 'consolereader', logdir)
                    #log('resumeThread', 'consolereader', logdir)
                    self.resumeThread()
                    paused = False
                                    
                time.sleep(.1)
        except Exception as e:
            log(e, 'consolereader', logdir)
            time.sleep(.1)
        
    
    def handler(self, sig):       
        log(sig, 'consolereader', logdir)
        return False

    def getConsoleOut(self):
        consout = win32file.CreateFile('CONOUT$', 
                                       win32con.GENERIC_READ | win32con.GENERIC_WRITE, 
                                       win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE, 
                                       None, 
                                       win32con.OPEN_EXISTING, 
                                       0, 
                                       0)
                                       
        return win32console.PyConsoleScreenBufferType(consout)
        
    def initConsole(self, consout):     
        rect = win32console.PySMALL_RECTType(0, 0, 79, 24)
        consout.SetConsoleWindowInfo(True, rect)
        size = win32console.PyCOORDType(80, 16000)
        consout.SetConsoleScreenBufferSize(size)
        pos = win32console.PyCOORDType(0, 0)
        # Use NUL as fill char because it displays as whitespace
        # (if we interact() with the child)
        consout.FillConsoleOutputCharacter(screenbufferfillchar, size.X * size.Y, pos)   
    
    def suspendThread(self):
        """Pauses the main thread of the child process."""
        
        handle = windll.kernel32.OpenThread(win32con.THREAD_SUSPEND_RESUME, 0, self.__tid)
        win32process.SuspendThread(handle)
        
    def resumeThread(self):
        """Un-pauses the main thread of the child process."""
    
        handle = windll.kernel32.OpenThread(win32con.THREAD_SUSPEND_RESUME, 0, self.__tid)
        win32process.ResumeThread(handle)
   
class searcher_string (object):

    def __init__(self, strings):

        """This creates an instance of searcher_string. This argument 'strings'
        may be a list; a sequence of strings; or the EOF or TIMEOUT types. """

        self.eof_index = -1
        self.timeout_index = -1
        self._strings = []
        for n, s in zip(list(range(len(strings))), strings):
            if s is EOF:
                self.eof_index = n
                continue
            if s is TIMEOUT:
                self.timeout_index = n
                continue
            self._strings.append((n, s))

    def __str__(self):

        """This returns a human-readable string that represents the state of
        the object."""

        ss =  [ (ns[0],'    %d: "%s"' % ns) for ns in self._strings ]
        ss.append((-1,'searcher_string:'))
        if self.eof_index >= 0:
            ss.append ((self.eof_index,'    %d: EOF' % self.eof_index))
        if self.timeout_index >= 0:
            ss.append ((self.timeout_index,'    %d: TIMEOUT' % self.timeout_index))
        ss.sort()
        ss = list(zip(*ss))[1]
        return '\n'.join(ss)

    def search(self, buffer, freshlen, searchwindowsize=None):

        absurd_match = len(buffer)
        first_match = absurd_match
        
        for index, s in self._strings:
            if searchwindowsize is None:
                # the match, if any, can only be in the fresh data,
                # or at the very end of the old data
                offset = -(freshlen+len(s))
            else:
                # better obey searchwindowsize
                offset = -searchwindowsize
            n = buffer.find(s, offset)
            if n >= 0 and n < first_match:
                first_match = n
                best_index, best_match = index, s
        if first_match == absurd_match:
            return -1
        self.match = best_match
        self.start = first_match
        self.end = self.start + len(self.match)
        return best_index

class searcher_re (object):

    def __init__(self, patterns):
        self.eof_index = -1
        self.timeout_index = -1
        self._searches = []
        for n, s in zip(list(range(len(patterns))), patterns):
            if s is EOF:
                self.eof_index = n
                continue
            if s is TIMEOUT:
                self.timeout_index = n
                continue
            self._searches.append((n, s))

    def __str__(self):

        """This returns a human-readable string that represents the state of
        the object."""

        ss =  [ (n,'    %d: re.compile("%s")' % (n,str(s.pattern))) for n,s in self._searches]
        ss.append((-1,'searcher_re:'))
        if self.eof_index >= 0:
            ss.append ((self.eof_index,'    %d: EOF' % self.eof_index))
        if self.timeout_index >= 0:
            ss.append ((self.timeout_index,'    %d: TIMEOUT' % self.timeout_index))
        ss.sort()
        ss = list(zip(*ss))[1]
        return '\n'.join(ss)

    def search(self, buffer, freshlen, searchwindowsize=None):

        absurd_match = len(buffer)
        first_match = absurd_match
        # 'freshlen' doesn't help here -- we cannot predict the
        # length of a match, and the re module provides no help.
        if searchwindowsize is None:
            searchstart = 0
        else:
            searchstart = max(0, len(buffer)-searchwindowsize)
        for index, s in self._searches:
            match = s.search(buffer, searchstart)
            if match is None:
                continue
            n = match.start()
            if n < first_match:
                first_match = n
                the_match = match
                best_index = index
        if first_match == absurd_match:
            return -1
        self.start = first_match
        self.match = the_match
        self.end = self.match.end()
        return best_index

def log(e, suffix='', logdir=None):
    if isinstance(e, Exception):
        # Get the full traceback
        e = traceback.format_exc()
    #if hasattr(sys.stdout, 'isatty') and sys.stdout.isatty():
        ## Only try to print if stdout is a tty, otherwise we might get
        ## an 'invalid handle' exception
        #print e
    if not logdir:
        if getattr(sys, 'frozen', False):
            logdir = os.path.splitext(os.path.basename(sys.executable))[0]
        else:
            logdir = os.path.split(os.path.dirname(os.path.abspath(__file__)))
            if logdir[-1] == 'lib':
                logdir.pop()
            logdir = logdir[-1]
    if sys.platform == "win32":
        logdir = os.path.join(SHGetSpecialFolderPath(0, CSIDL_APPDATA), 
                              logdir, "logs")
    elif sys.platform == "darwin":
        logdir = os.path.join(os.path.expanduser("~"), "Library", "Logs", 
                              logdir)
    else:
        logdir = os.path.join(os.getenv("XDG_DATA_HOME", 
                                        os.path.expandvars("$HOME/.local/share")), 
                                        logdir, "logs")
    if not os.path.exists(logdir):
        try:
            os.makedirs(logdir)
        except (OSError, WindowsError):
            pass
    if os.path.isdir(logdir) and os.access(logdir, os.W_OK):
        logfile = os.path.join(logdir, 'sshproxy%s.log' % suffix)
        if os.path.isfile(logfile):
            try:
                logstat = os.stat(logfile)
            except Exception as exception:
                pass
            else:
                try:
                    mtime = time.localtime(logstat.st_mtime)
                except ValueError as exception:
                    # This can happen on Windows because localtime() is buggy on
                    # that platform. See:
                    # http://stackoverflow.com/questions/4434629/zipfile-module-in-python-runtime-problems
                    # http://bugs.python.org/issue1760357
                    # To overcome this problem, we ignore the real modification
                    # date and force a rollover
                    mtime = time.localtime(time() - 60 * 60 * 24)
                if time.localtime()[:3] > mtime[:3]:
                    # do rollover
                    try:
                        os.remove(logfile)
                    except Exception as exception:
                        pass
        try:
            fout = open(logfile, 'a')
        except:
            pass
        else:
            ts = time.time()
            fout.write('%s,%s %s\n' % (time.strftime("%Y-%m-%d %H:%M:%S",
                                                      time.localtime(ts)), 
                                       ('%3f' % (ts - int(ts)))[2:5], e))
            fout.close()   

def join_args(args):
    commandline = []
    for arg in args:
        if re.search('[\^!$%&()[\]{}=;\'+,`~\s]', arg):
            arg = '"%s"' % arg
        commandline.append(arg)
    return ' '.join(commandline)

def split_command_line(command_line, escape_char = '^'):

    arg_list = []
    arg = ''

    # Constants to name the states we can be in.
    state_basic = 0
    state_esc = 1
    state_singlequote = 2
    state_doublequote = 3
    state_whitespace = 4 # The state of consuming whitespace between commands.
    state = state_basic

    for c in command_line:
        if state == state_basic or state == state_whitespace:
            if c == escape_char: # Escape the next character
                state = state_esc
            elif c == r"'": # Handle single quote
                state = state_singlequote
            elif c == r'"': # Handle double quote
                state = state_doublequote
            elif c.isspace():
                # Add arg to arg_list if we aren't in the middle of whitespace.
                if state == state_whitespace:
                    None # Do nothing.
                else:
                    arg_list.append(arg)
                    arg = ''
                    state = state_whitespace
            else:
                arg = arg + c
                state = state_basic
        elif state == state_esc:
            arg = arg + c
            state = state_basic
        elif state == state_singlequote:
            if c == r"'":
                state = state_basic
            else:
                arg = arg + c
        elif state == state_doublequote:
            if c == r'"':
                state = state_basic
            else:
                arg = arg + c

    if arg != '':
        arg_list.append(arg)
    return arg_list

def start(host, user, pwd, port=1080, bg_run=False, timeout=30):
  try:
    options = '-q -oStrictHostKeyChecking=no -oPubkeyAuthentication=no'
    if bg_run:                                                                                                                                                         
      options += ' -f'
    child = spawn('ssh %s -D %s -N %s@%s' % (options, str(port), str(user), str(host)), timeout=timeout)
    try:
        child.expect('Password:', timeout = 10)
    except:
        child.expect('password:', timeout = 10)
    # child.expect('Password:')
    child.sendline(pwd)
    return child
  except Exception as identifier:
    raise