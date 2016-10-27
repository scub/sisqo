#!/usr/bin/env python
# -*- coding: utf-8 -*-
########################################################################################################################
# Copyright © 2015 Alex Forster. All rights reserved.
# This software is licensed under the 3-Clause ("New") BSD license.
# See the LICENSE file for details.
########################################################################################################################


import time
import logging
import traceback
import re
from select import select

from datetime import datetime, timedelta

from ptyprocess import PtyProcess
from pyte.streams import ByteStream
from pyte.screens import Screen

from configuration import Configuration


class NotConnectedError(Exception): pass


class AlreadyConnectedError(Exception): pass


class NotAuthenticatedError(Exception): pass


class AlreadyAuthenticatedError(Exception): pass


class BadAuthenticationError(Exception): pass


class SSH:

    SCREEN_WIDTH = 512
    SCREEN_HEIGHT = 256

    def __init__(self, username, host, port=22, sshConfigFile=None):
        """
        :type host: str
        :type port: int
        :type sshConfigFile: str|None
        """
        self._log = logging.getLogger(__name__)
        """:type: logging.Logger"""

        self._username = str(username)
        """:type: str"""
        self._host = str(host)
        """:type: str"""
        self._port = int(port)
        """:type: int"""
        self._sshConfigFile = str(sshConfigFile) if sshConfigFile else None
        """:type: str|None"""

        self._promptRegex = r'^[^\s]+[>#]\s?$'
        """:type: str"""
        self._moreRegex = r'^.*-+\s*more\s*-+.*$'
        """:type: str"""

        self._authenticated = False
        """:type: bool"""
        self._readSinceWrite = False
        """:type: bool"""

        sshConfigSpec = ['-F', self._sshConfigFile] if self._sshConfigFile else []
        portSpec = ['-p', self._port] if self._port and self._port != 22 else []
        optionsSpec = ['-oStrictHostKeyChecking=no', '-oConnectTimeout=5'] if not self._sshConfigFile else []
        userHostSpec = [(username + '@' if username else '') + self._host]

        args = ['ssh']
        args.extend(sshConfigSpec)
        args.extend(portSpec)
        args.extend(optionsSpec)
        args.extend(userHostSpec)

        self._log.info(' '.join(args))

        self._pty = PtyProcess.spawn(args, dimensions=(SSH.SCREEN_HEIGHT, SSH.SCREEN_WIDTH), env={'TERM': 'vt100'})
        """:type: ptyprocess.PtyProcess"""
        self._vt = Screen(SSH.SCREEN_WIDTH, SSH.SCREEN_HEIGHT)
        """:type: pyte.Screen"""
        self._stream = ByteStream()
        """:type: pyte.ByteStream"""

        self._stream.attach(self._vt)

    @property
    def host(self):
        """
        :rtype: str
        """
        return self._host

    @property
    def port(self):
        """
        :rtype: int
        """
        return self._port

    @property
    def promptRegex(self):

        return self._promptRegex

    @promptRegex.setter
    def promptRegex(self, value):

        self._promptRegex = value

    @property
    def moreRegex(self):

        return self._moreRegex

    @moreRegex.setter
    def moreRegex(self, value):

        self._moreRegex = value

    def __enter__(self):

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):

        self.disconnect()

    def __del__(self):

        self.disconnect()

    def disconnect(self):

        if self._pty:

            self._pty.terminate(force=True)

            self._authenticated = False

            self._pty = None
            self._stream = None
            self._vt = None

            self._readSinceWrite = False

            self._log.info('Disconnected from {}'.format(self.host))

    def read(self, timeout=10, promptRegex=None, stripPrompt=True):
        """
        :type timeout: int
        :type promptRegex: str|None
        :type stripPrompt: bool
        :rtype: str
        """

        try:

            self._assertConnectionState(connected=True)

        except Exception as ex:

            self._log.error(self._formatException(ex, 'Could not read from the remote host'))
            return ''

        if not promptRegex:

            promptRegex = self.promptRegex

        deadline = datetime.utcnow() + timedelta(seconds=timeout)

        eof = False
        self._vt.reset()

        while True:

            try:

                read = self._recv()

                if read is not None:
                    deadline = datetime.utcnow() + timedelta(seconds=timeout)
                    self._stream.feed(read)
                    if self._vt.cursor.y > self._vt.lines * 0.5:
                        self._vt.save_cursor()
                        self._vt.resize(self._vt.lines * 2, SSH.SCREEN_WIDTH)
                        self._vt.restore_cursor()
                    continue
                else:
                    time.sleep(0.01)

            except EOFError:

                eof = True
                break

            line = self._vt.buffer[self._vt.cursor.y]
            line = ''.join(map(lambda l: getattr(l, 'data'), line)).strip()

            if re.match(promptRegex, line, re.MULTILINE | re.IGNORECASE | re.UNICODE):

                break

            if re.match(self._moreRegex, line, re.MULTILINE | re.IGNORECASE | re.UNICODE):

                self._send(' ')
                continue

            if datetime.utcnow() > deadline:

                self._log.info('Read timeout; could not match prompt regex or more pagination regex.' +
                               'Last regex match attempted: {}'.format(line))
                break

        lines = []

        rstart = time.time()

        for line in [l.rstrip() for l in self._vt.display[0:self._vt.cursor.y+1]]:

            if stripPrompt and re.match(promptRegex, line, re.MULTILINE | re.IGNORECASE | re.UNICODE):

                continue

            lines.append(line)

        result = '\n'.join(lines).strip('\n')

        rend = time.time()

        if rend-rstart >= 1:
            self._log.info('Rendered {} lines ({} chars) in {:.2f}s'.format(len(lines), len(result), rend-rstart))

        self._readSinceWrite = True

        if eof:

            self.disconnect()

        return result

    def write(self, command, consumeEcho=True):
        """
        :type command: str
        :type consumeEcho: bool
        """
        try:

            self._assertConnectionState(connected=True)

        except Exception as ex:

            self._log.error(self._formatException(ex, 'Could not write to the remote host'))
            return

        command = command.replace('?', '\x16?')

        if not self._readSinceWrite:

            self.read(stripPrompt=False)

        self._readSinceWrite = False

        if not command.endswith('\n'):

            command += '\n'

        self._send(command)

        if not consumeEcho:

            return

        # consume what's echoed back

        readLen = len(command)

        while readLen > 0:

            recvd = self._recv(readLen)
            self._stream.feed(recvd)
            readLen -= len(recvd)
            time.sleep(0.01)

    def connect(self, password=None, privateKeyPassphrase=None):
        """
        :type password: str|None
        :type privateKeyPassphrase: str|None
        :rtype: bool
        """
        try:

            self._assertConnectionState(connected=True)

        except Exception as ex:

            self._log.error(self._formatException(ex, 'Could not connect to the remote host'))
            return False

        triedPassphrase = False
        triedPassword = False

        while True:

            read = self.read(promptRegex=r'.+', stripPrompt=False)

            if not triedPassphrase and 'passphrase for key' in read.lower():

                if not privateKeyPassphrase:

                    self._log.warn('Prompted for private key passphrase, but none was provided')
                    return False

                self.write(privateKeyPassphrase, consumeEcho=False)

                triedPassphrase = True

                continue

            if not triedPassword and 'password:' in read.lower():

                if not password:

                    self._log.warn('Prompted for password, but none was provided')
                    return False

                self.write(password, consumeEcho=False)

                triedPassword = True

                continue

            if 'passphrase for key' in read.lower():

                self._log.warn('Provided private key passphrase was incorrect')
                return False

            if 'password:' in read.lower():

                self._log.warn('Provided password was incorrect')
                return False

            if 'killed by signal' in read.lower():

                self._log.warn(read.lower())
                return False

            if read.lower().startswith('ssh: '):

                self._log.warn(read.lower())
                return False

            self._authenticated = True

            self._log.info('Connected to {}'.format(self.host))

            return True

    def enable(self, password):
        """
        :type password: str
        :rtype: bool
        """
        try:

            self._assertConnectionState(authenticated=True)

        except Exception as ex:

            self._log.error(self._formatException(ex, 'Could not enable on the remote host'))
            return False

        self.write('enable')

        enableResult = self.read(promptRegex=r'^Password:.*$', stripPrompt=False).lower()

        if 'password:' not in enableResult.lower():

            self._log.warn('Enable failed: remote did not prompt for a password')
            return False

        self.write(password, consumeEcho=False)

        passwordResult = self.read(stripPrompt=False).lower()

        if 'password:' in passwordResult.lower():

            self._log.error('Enable failed: incorrect password')
            return False

        self._log.info('Enabled on {}'.format(self.host))

        return True

    def showRunningConfig(self):
        """
        :rtype: Configuration
        """
        self.write('show running-config')

        result = self.read()

        return Configuration(result)

    def showStartupConfig(self):
        """
        :rtype: Configuration
        """
        self.write('show startup-config')

        result = self.read()

        return Configuration(result)

    def _send(self, value):
        """
        :type value: str
        """
        self._log.debug('SEND: ' + repr(value))
        self._pty.write(value)

    def _recv(self, nr=1024):
        """
        :type nr: int
        :rtype: str
        """
        canRead = self._pty.fd in select([self._pty.fd], [], [], 0.1)[0]
        if not canRead: return None
        result = self._pty.read(nr)
        self._log.debug('RECV: ' + repr(result))
        return result

    def _formatException(self, exception, message):
        """
        :type exception: Exception
        :type message: str
        :rtype: str
        """
        stack = traceback.extract_stack()

        exceptionMessage = traceback.format_exception_only(type(exception), exception)[0].strip()
        file = stack[-2][0]
        line = stack[-2][1]
        function = stack[-2][2]

        return '%s: %s in %s at %s:%d' % (message, exceptionMessage, function, file, line)

    def _assertConnectionState(self, connected=None, authenticated=None):
        """
        :type connected: bool|None
        :type authenticated: bool|None
        """
        if not self._pty: return

        if connected == True:

            if not self._pty.isalive():

                raise NotConnectedError('An SSH connection has not been established')

        elif connected == False:

            if self._pty.isalive():

                raise AlreadyConnectedError('This SSH connection has already been established')

        if authenticated == True:

            if not self._authenticated:

                raise NotAuthenticatedError('This SSH connection has not authenticated')

        elif authenticated == False:

            if self._authenticated:

                raise AlreadyAuthenticatedError('This SSH connection has already authenticated')
