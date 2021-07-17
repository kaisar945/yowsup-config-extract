import base64
import json
import os
import random
import shlex
import shutil
import tempfile
from hashlib import pbkdf2_hmac
from typing import Dict
from xml.etree import ElementTree

from yowsup_config import logger

from .adb_wrapper import NoRootException, _AdbWrapper

DEVICE_AXOLOTLDB_EXTRACT_PATH = '/data/local/tmp/axolotl/'
SOMETOKEN = 'A\u0004\u001d@\u0011\u0018V\u0002T(3{;ES'


class AppNotInstalledException(Exception):
    pass


class ExportConfigException(Exception):
    pass


class KeyPairInvalideException(ExportConfigException):
    pass


class ExportAxolotlException(Exception):
    pass


class Extracter():

    def setLogLevel(self, level):
        logger.setLevel(level)

    def extractFromDevice(self, serial=None, package: str = 'com.whatsapp', dirpath: str = tempfile.gettempdir()) -> str:
        device = _AdbWrapper(serial)
        # check root supported
        logger.info('check root permission')
        try:
            rooted = device.shell_as_root('printf rooted')
        except NoRootException as e:
            logger.info('no root')
            raise e
        logger.info(rooted)
        # check package installed
        logger.info('check app installed')
        app_installed = bool(int(device.shell(f'pm path {package} &>/dev/null && printf 1 || printf 0')))
        if not app_installed:
            logger.info('not installed')
            raise AppNotInstalledException(f'{package} not installed')
        logger.info(f'{package} installed')
        # extract prefs file
        logger.info('extract config file')
        config_dirpath = self.__extractSharedPreference(device, package, dirpath)
        logger.info('done')
        # extract db file
        logger.info('extract axolotl db file')
        self.__extractAxolotlDatabase(device, package, config_dirpath)
        logger.info('done')
        logger.info(f'save to {config_dirpath}')
        logger.info('Finish')
        return config_dirpath

    def __extractSharedPreference(self, device: _AdbWrapper, package: str, dirpath: str):
        # parse keystore.xml
        keystore_filepath = f'/data/data/{package}/shared_prefs/keystore.xml'
        file_exists = bool(int(device.shell_as_root(f'[[ -f {keystore_filepath} ]] && printf 1 || printf 0')))
        if not file_exists:
            logger.info(f'{keystore_filepath} miss')
            raise FileNotFoundError(f'not found {keystore_filepath} on device')
        keystore = self.__parsePrefs(device, keystore_filepath)
        client_static_keypair = keystore.get('client_static_keypair', '')
        if not client_static_keypair:
            client_static_keypair_encrypted = keystore.get('client_static_keypair_pwd_enc', '')
            if not client_static_keypair_encrypted:
                logger.info('client_static_keypair miss')
                raise KeyPairInvalideException(f'client_static_keypair not found in {keystore_filepath}')
            client_static_keypair = self.__decryptKeyPairJavaImpl(device, client_static_keypair_encrypted)
        logger.debug('client_static_keypair=' + client_static_keypair)

        server_static_public = keystore.get('server_static_public', '')
        if not server_static_public:
            logger.info('server_static_public miss')
            raise KeyPairInvalideException(f'server_static_public not found in {keystore_filepath}')
        server_static_public = self.__b64padding(server_static_public)
        logger.debug('server_static_public=' + server_static_public)

        # parse com.whatsapp_preferences_light.xml
        prefs_light_filepath = f'/data/data/{package}/shared_prefs/{package}_preferences_light.xml'
        file_exists = bool(int(device.shell_as_root(f'[[ -f {prefs_light_filepath} ]] && printf 1 || printf 0 ')))
        if not file_exists:
            logger.info(f'{prefs_light_filepath} miss')
            raise FileNotFoundError(f'not found {prefs_light_filepath} on device')
        prefs = self.__parsePrefs(device, prefs_light_filepath)
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
        config_dirpath = os.path.join(dirpath, phone)
        shutil.rmtree(config_dirpath, ignore_errors=True)
        os.makedirs(config_dirpath, exist_ok=False)
        filepath = os.path.join(config_dirpath, 'config.json')
        with open(filepath, 'w') as f:
            f.write(json.dumps(config, indent=4))
            f.flush()
        return config_dirpath

    def __extractAxolotlDatabase(self, device: _AdbWrapper, package: str, dirpath: str):
        device.shell(f'rm -rf {DEVICE_AXOLOTLDB_EXTRACT_PATH}; mkdir {DEVICE_AXOLOTLDB_EXTRACT_PATH}')
        ok = bool(int(device.shell_as_root(f'cp /data/data/{package}/databases/axolotl.db* {DEVICE_AXOLOTLDB_EXTRACT_PATH} &>/dev/null && printf 1 || printf 0')))
        if not ok:
            raise ExportAxolotlException('extract axolotl.db fail, please report issue')
        device.shell_as_root(f'chown 2000:2000 -R {DEVICE_AXOLOTLDB_EXTRACT_PATH}')
        filepaths = device.shell(f'ls -1 {DEVICE_AXOLOTLDB_EXTRACT_PATH}/*')
        for filepath in filepaths.splitlines():
            device.pull(filepath, dirpath)

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

    def __decryptKeyPairJavaImpl(self, device: _AdbWrapper, keypair_enc: str) -> str:
        dirpath = os.path.dirname(os.path.abspath(__file__))
        device_filename = '/data/local/tmp/decrypt.dex'
        device.push(os.path.join(dirpath, 'common', 'decrypt.dex'), device_filename)
        keypair_enc = keypair_enc.replace('"', '\\"')
        return device.shell(f'echo {shlex.quote(keypair_enc)} | CLASSPATH={device_filename} app_process /system/bin  com.kaisar.wakeypairtools.Decrypt').strip()

    def __choiceCarrier(self, country_code: str):
        dirpath = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(dirpath, 'common', 'mcc-mnc-table.json')) as f:
            carriers = json.load(f)
            matched_carriers = []
            for carrier in carriers:
                if country_code == carrier['country_code']:
                    matched_carriers.append(carrier)
            return random.choice(matched_carriers)

    def __parsePrefs(self, device: _AdbWrapper, device_prefs_file: str) -> Dict[str, str]:
        xml = device.shell_as_root(f'cat {device_prefs_file}')
        logger.debug(f'======{device_prefs_file}======')
        logger.debug('\n' + xml)
        root = ElementTree.fromstring(xml)
        return {child.attrib['name']: child.text for child in root}

    def __b64padding(self, text: str):
        return text + '=' * (-len(text) % 4)
