import os
import shlex
import subprocess


class _AdbWrapper():

    def __init__(self, serial: str = None):
        self.serial = serial
        self.cmdopts = f'-s {serial}' if serial else ''
        if os.system(f'adb {self.cmdopts} shell exec') != 0:
            raise Exception('Install adb in the system env PATH first')

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
