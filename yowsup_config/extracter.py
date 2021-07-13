import base64
import json
import os
import random
import shlex
from enum import Enum
from hashlib import pbkdf2_hmac
from typing import Dict
from xml.etree import ElementTree

from yowsup_config import logger

from .adb_wrapper import _AdbWrapper

DEVICE_AXOLOTLDB_EXTRACT_PATH = '/data/local/tmp/axolotl/'
SOMETOKEN = 'A\u0004\u001d@\u0011\u0018V\u0002T(3{;ES'


class NoRootException(Exception):
    pass


class AppNotFoundException(Exception):
    pass


class KeyPairInvalideException(Exception):
    pass


class SuType(Enum):
    NONE = 0
    AOSP = 1
    THIRD = 2


class Extracter():

    def __init__(self, device_serial=None, package='com.whatsapp'):
        self.device = _AdbWrapper(device_serial)
        self.package = package
        self.su_type = SuType.NONE

    def setLogLevel(self, level):
        logger.setLevel(level)

    def extractFromDevice(self, dirpath: str):
        # check root supported
        logger.info('check root supported')
        su_check_cmd = f'([ $(id -u) -eq 0 ] && printf {SuType.AOSP.name}) || su 0 -c printf {SuType.THIRD.name} 2>/dev/null || su 0 printf {SuType.AOSP.name} 2>/dev/null || printf {SuType.NONE.name}'
        self.su_type = SuType[self.device.shell(su_check_cmd)]
        if self.su_type == SuType.NONE:
            logger.error('Only support rooted device!')
            raise NoRootException('Only support rooted device!')
        logger.debug(f'root type [{self.su_type.name}]')
        logger.info('check root supported pass')
        # check whatsapp installed
        logger.info(f'check {self.package} installed')
        app_installed = bool(self.device.shell(f'pm path {self.package} &>/dev/null && printf 1 || printf 0'))
        if not app_installed:
            logger.error(f'Please install {self.package} and register first')
            raise AppNotFoundException(f'Please install {self.package} and register first')
        logger.info(f'check {self.package} installed pass')
        # extract prefs file
        logger.info('extract config file')
        self.extractSharedPreference(dirpath)
        logger.info('extract config file done')
        # extract db file
        logger.info('extract axolotl db file')
        self.extractAxolotlDatabase(dirpath)
        logger.info('extract axolotl db file done')
        logger.info('Done')

    def extractSharedPreference(self, dirpath: str):
        # parse keystore.xml
        keystore = self.__parsePrefs(f'/data/data/{self.package}/shared_prefs/keystore.xml')
        client_static_keypair = keystore.get('client_static_keypair', self.__decryptKeyPairJavaImpl(keystore['client_static_keypair_pwd_enc']))
        logger.debug('client_static_keypair=' + client_static_keypair)
        server_static_public = self.__b64padding(keystore.get('server_static_public'))
        logger.debug('server_static_public=' + server_static_public)
        # parse com.whatsapp_preferences_light.xml
        prefs = self.__parsePrefs(f'/data/data/{self.package}/shared_prefs/{self.package}_preferences_light.xml')
        phone = prefs.get('registration_jid')
        cc = prefs.get('cc')
        carrier = self.__choiceCarrier(cc)
        mcc = carrier['mcc']
        mnc = carrier['mnc']
        sim_mcc = carrier['mcc']
        sim_mnc = carrier['mnc']
        edge_routing_info = self.__b64padding(prefs.get('routing_info'))
        expid = prefs.get('phoneid_id')
        fdid = prefs.get('perf_device_id')
        id = base64.b64encode(fdid[0:20].encode('utf-8')).decode('utf-8')

        config = {
            '__version__': 1,
            'cc': cc,
            'client_static_keypair': client_static_keypair,
            'edge_routing_info': edge_routing_info,
            'expid': expid,
            'fdid': fdid,
            'id': id,
            'mcc': mcc,
            'mnc': mnc,
            'phone': phone,
            'server_static_public': server_static_public,
            'sim_mcc': sim_mcc,
            'sim_mnc': sim_mnc
        }
        logger.debug("======config.json======")
        logger.debug('\n' + json.dumps(config, indent=4))
        filepath = os.path.join(dirpath, 'config.json')
        with open(filepath, 'w') as f:
            f.write(json.dumps(config, indent=4))
            f.flush()

    def extractAxolotlDatabase(self, dirpath: str):
        self.device.shell(f'rm -rf {DEVICE_AXOLOTLDB_EXTRACT_PATH}; mkdir {DEVICE_AXOLOTLDB_EXTRACT_PATH}')
        ok = bool(self.__runAsRootOnDevice(f'cp /data/data/{self.package}/databases/axolotl.db* {DEVICE_AXOLOTLDB_EXTRACT_PATH} &>/dev/null && printf 1 || printf 0'))
        if not ok:
            raise Exception('extract axolotl.db failure, please report issue')
        self.__runAsRootOnDevice(f'chown 2000:2000 -R {DEVICE_AXOLOTLDB_EXTRACT_PATH}')
        filepaths = self.device.shell(f'ls -1 {DEVICE_AXOLOTLDB_EXTRACT_PATH}/*')
        for filepath in filepaths.splitlines():
            self.device.pull(filepath, dirpath)

    def __decryptKeyPair(self, keypair_enc: str):
        array = json.loads(keypair_enc)
        type = int(array[0])
        ciphertext = base64.b64decode(array[1] + '=' * 3)
        iv = base64.b64decode(array[2] + '=' * 3)
        salt = base64.b64decode(array[3] + '=' * 3)
        password = array[4]
        if type != 2:
            raise KeyPairInvalideException('KeyPair type shoud be 2')
        magic_token = [chr(ord(c) ^ 18) for c in SOMETOKEN]
        magic_token = ''.join(magic_token) + password

        key = pbkdf2_hmac('sha1', magic_token.encode('utf-8'), salt, 16, 32)
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_OFB, iv)
        print(base64.b64encode(cipher.decrypt(ciphertext)).decode('utf-8'))
        # decrypter = pyaes.Decrypter(pyaes.AESModeOfOperationOFB(key, iv), PADDING_NONE)
        # decryptedData = decrypter.feed(ciphertext)
        # decryptedData += decrypter.feed()
        # return base64.b64encode(decryptedData).decode('utf-8')

    def __decryptKeyPairJavaImpl(self, keypair_enc: str):
        dirpath = os.path.dirname(os.path.abspath(__file__))
        device_filename = '/data/local/tmp/decrypt.dex'
        self.device.push(os.path.join(dirpath, 'common', 'decrypt.dex'), device_filename)
        keypair_enc = keypair_enc.replace('"', '\\"')
        return self.device.shell(f'echo {shlex.quote(keypair_enc)} | CLASSPATH={device_filename} app_process /system/bin  com.kaisar.wakeypairtools.Decrypt').strip()

    def __choiceCarrier(self, country_code: str):
        dirpath = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(dirpath, 'common', 'mcc-mnc-table.json')) as f:
            carriers = json.load(f)
            matched_carriers = []
            for carrier in carriers:
                if country_code == carrier['country_code']:
                    matched_carriers.append(carrier)
            return random.choice(matched_carriers)

    def __parsePrefs(self, device_prefs_file: str) -> Dict[str, str]:
        xml = self.__runAsRootOnDevice(f'cat {device_prefs_file}')
        logger.debug(f'======{device_prefs_file}======')
        logger.debug('\n' + xml)
        root = ElementTree.fromstring(xml)
        return {child.attrib['name']: child.text for child in root}

    def __runAsRootOnDevice(self, command):
        if self.su_type == SuType.THIRD:
            return self.device.shell(f'su 0 -c {command}')
        elif self.su_type == SuType.AOSP:
            if int(self.device.shell('id -u')) == 0:
                return self.device.shell(command)
            else:
                return self.device.shell(f'su 0 {command}')
        else:
            raise NoRootException('Only support rooted device!')

    def __b64padding(self, text: str):
        return text + '=' * (-len(text) % 4)
