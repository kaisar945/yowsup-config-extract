import os
import shlex
import subprocess

from yowsupx.config import NoRootException


class Device(object):

    def __init__(self, serial: str, cmdopts: str):
        self.serial = serial
        self.cmdopts = cmdopts

    def __execute(self, subcmd):
        command = f'adb {self.cmdopts} {subcmd}'
        process = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, _ = process.communicate()
        output = stdout.decode('utf-8')
        return output

    def shell(self, command: str):
        return self.__execute(f'shell "{command}"')

    def pull(self, device_filename, filename):
        self.__execute(f'pull "{device_filename}" "{filename}"')

    def push(self, filename, device_filename):
        self.__execute(f'push "{filename}" "{device_filename}"')

    def shell_as_root(self, command):
        if int(self.shell('id -u')) == 0:
            return self.shell(command)
        elif int(self.shell('su 0 -c id -u')) == 0:
            return self.shell(f'su 0 -c {command}')
        elif int(self.shell('su 0 id -u')) == 0:
            return self.shell(f'su 0 {command}')
        else:
            raise NoRootException('No have root permission')


class AdbWrapper():

    def connect(serial: str = None) -> Device:
        cmdopts = f'-s {serial}' if serial else ''
        status = os.system(f'adb {cmdopts} shell exec')
        if status == 0:
            return Device(serial, cmdopts)
        elif status == 127:
            raise Exception('Install adb in the system env PATH first')
        else:
            raise Exception('Whether to connect multiple devices?')
