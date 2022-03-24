import base64
import json
import logging
import os
import random
import shutil
from enum import Enum
from hashlib import pbkdf2_hmac
from typing import Dict
from xml.etree import ElementTree

from Crypto.Cipher import AES
from yowsupx.config import (AppNotInstalledException, KeyPairInvalideException,
                            NoRootException)
from yowsupx.config.adbwrapper import AdbWrapper

logger = logging.getLogger(__name__)

DEVICE_AXOLOTLDB_EXTRACT_PATH = '/data/local/tmp/axolotl/'
SOMETOKEN = 'A\u0004\u001d@\u0011\u0018V\u0002T(3{;ES'


class OutputFormat(Enum):

    conf = 1
    hash = 2

    @classmethod
    def argtype(cls, s: str):
        try:
            return cls[s]
        except KeyError:
            raise KeyError(f"{s!r} is not a valid {cls.__name__}")

    def __str__(self):
        return self.name


def setLogLevel(level):
    logger.setLevel(level)


def fromDevice(serial: str = None, package: str = 'com.whatsapp', format=OutputFormat.conf) -> str:
    """
    Extract the yowsup configuration file from the rooted device.
    """
    device = AdbWrapper.connect(serial)
    # check device root support
    logger.debug('check root permission')
    try:
        rooted = device.shell_as_root('printf rooted')
    except NoRootException as e:
        logger.debug('no root')
        raise e
    logger.debug(rooted)
    # check package installed
    logger.debug('check app installed')
    app_installed = bool(int(device.shell(f'pm path {package} &>/dev/null && printf 1 || printf 0')))
    if not app_installed:
        logger.debug('not installed')
        raise AppNotInstalledException(f'{package} not installed')
    logger.debug(f'{package} installed')
    logger.debug('extract config file')
    # parse keystore.xml
    keystore_filepath = f'/data/data/{package}/shared_prefs/keystore.xml'
    file_exists = bool(int(device.shell_as_root(f'[[ -f {keystore_filepath} ]] && printf 1 || printf 0')))
    if not file_exists:
        logger.debug(f'{keystore_filepath} miss')
        raise FileNotFoundError(f'not found {keystore_filepath} on device')
    keystore = loadPrefsFromDevice(device, keystore_filepath)

    # parse {package}_preferences_light.xml
    prefs_light_filepath = f'/data/data/{package}/shared_prefs/{package}_preferences_light.xml'
    file_exists = bool(int(device.shell_as_root(f'[[ -f {prefs_light_filepath} ]] && printf 1 || printf 0 ')))
    if not file_exists:
        logger.debug(f'{prefs_light_filepath} miss')
        raise FileNotFoundError(f'not found {prefs_light_filepath} on device')
    prefs_light = loadPrefsFromDevice(device, prefs_light_filepath)

    if format == OutputFormat.conf:
        # extract config file
        return extractConfig(keystore, prefs_light)
    elif format == OutputFormat.hash:
        # extract hash file
        return extractHash(keystore, prefs_light)


def fromDirectory(datadir: str, package: str = 'com.whatsapp', format=OutputFormat.conf) -> str:
    """
    Extract the yowsup configuration file from the directory.
    """
    # extract prefs file
    logger.debug('extract config file')
    keystore_filename = 'keystore.xml'
    keystore_filepath = __find_file(keystore_filename, datadir)
    if not keystore_filepath:
        logger.debug(f'{keystore_filename} miss')
        raise FileNotFoundError(f'not found {keystore_filename} on {datadir}')
    keystore = loadPrefsFromDirectory(keystore_filepath)

    # parse {package}_preferences_light.xml
    prefs_light_filename = f'{package}_preferences_light.xml'
    prefs_light_filepath = __find_file(prefs_light_filename, datadir)
    if not prefs_light_filepath:
        logger.debug(f'{prefs_light_filename} miss')
        raise FileNotFoundError(f'not found {prefs_light_filename} on {datadir}')
    prefs_light = loadPrefsFromDirectory(prefs_light_filepath)

    if format == OutputFormat.conf:
        # extract config file
        return extractConfig(keystore, prefs_light)
    elif format == OutputFormat.hash:
        # extract hash file
        return extractHash(keystore, prefs_light)


def extractConfig(keystore: Dict[str, str], prefs_light: Dict[str, str]):
    client_static_keypair = keystore.get('client_static_keypair', '')
    if not client_static_keypair:
        client_static_keypair_encrypted = keystore.get('client_static_keypair_pwd_enc', '')
        if not client_static_keypair_encrypted:
            logger.debug('client_static_keypair miss')
            raise KeyPairInvalideException('client_static_keypair not found')
        client_static_keypair = decryptKeyPair(client_static_keypair_encrypted)
    logger.debug('client_static_keypair=' + client_static_keypair)

    server_static_public = keystore.get('server_static_public', '')
    if not server_static_public:
        logger.debug('server_static_public miss')
        raise KeyPairInvalideException('server_static_public not found')
    server_static_public = b64padding(server_static_public)
    logger.debug('server_static_public=' + server_static_public)

    phone = prefs_light.get('registration_jid')
    # cc = prefs_light.get('cc')
    # carrier = choiceCarrier(cc)
    # mcc = carrier['mcc']
    # mnc = carrier['mnc']
    # sim_mcc = carrier['mcc']
    # sim_mnc = carrier['mnc']
    # edge_routing_info = b64padding(prefs_light.get('routing_info'))
    # expid = prefs_light.get('phoneid_id')
    # fdid = prefs_light.get('perf_device_id')
    # id = base64.b64encode(fdid[0:20].encode('utf-8')).decode('utf-8')

    config = {
        '__version__': 1,
        # 'cc': cc,
        'client_static_keypair': client_static_keypair,
        # 'edge_routing_info': edge_routing_info,
        # 'expid': expid,
        # 'fdid': fdid,
        # 'id': id,
        # 'mcc': mcc,
        # 'mnc': mnc,
        'phone': phone,
        'server_static_public': server_static_public,
        # 'sim_mcc': sim_mcc,
        # 'sim_mnc': sim_mnc
    }
    return json.dumps(config, indent=4)


def extractHash(keystore: Dict[str, str], prefs_light: Dict[str, str]):
    client_static_keypair = keystore.get('client_static_keypair', '')
    if not client_static_keypair:
        client_static_keypair_encrypted = keystore.get('client_static_keypair_pwd_enc', '')
        if not client_static_keypair_encrypted:
            logger.debug('client_static_keypair miss')
            raise KeyPairInvalideException('client_static_keypair not found')
        client_static_keypair = decryptKeyPair(client_static_keypair_encrypted)
    logger.debug('client_static_keypair=' + client_static_keypair)

    phone = prefs_light.get('registration_jid')
    plain_bytes = base64.b64decode(client_static_keypair)
    half_size = int(len(plain_bytes) / 2)
    key1 = base64.b64encode(plain_bytes[half_size:]).decode(encoding='utf-8')  # with + / =
    key2 = base64.b64encode(plain_bytes[:half_size]).decode(encoding='utf-8')  # with + / =
    return f"{phone},{key1},{key2}"


def __find_file(name, path):
    for root, dirs, files in os.walk(path):
        if name in files:
            return os.path.join(root, name)


def decryptKeyPair(keypair_enc: str):
    array = json.loads(keypair_enc)
    type = int(array[0])
    ciphertext = base64.urlsafe_b64decode(b64padding(array[1]))
    iv = base64.urlsafe_b64decode(b64padding(array[2]))
    salt = base64.urlsafe_b64decode(b64padding(array[3]))
    password = array[4]
    if type != 2:
        raise KeyPairInvalideException('KeyPair type shoud be 2')
    password = (''.join([chr(ord(c) ^ 18) for c in SOMETOKEN]) + password).encode('utf-8')
    sha1_key = pbkdf2_hmac(
        hash_name='sha1',
        password=password,
        salt=salt,
        iterations=16,
        dklen=16
    )
    cryptor = AES.new(sha1_key, AES.MODE_OFB, iv)
    plain_bytes = cryptor.decrypt(ciphertext)
    return base64.b64encode(plain_bytes).decode('utf-8')


def choiceCarrier(country_code: str):
    dirpath = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(dirpath, 'common', 'mcc-mnc-table.json')) as f:
        carriers = json.load(f)
        matched_carriers = []
        for carrier in carriers:
            if country_code == carrier['country_code']:
                matched_carriers.append(carrier)
        return random.choice(matched_carriers)


def loadPrefsFromDevice(device: AdbWrapper, device_prefs_file: str) -> Dict[str, str]:
    xml = device.shell_as_root(f'cat {device_prefs_file}')
    logger.debug(f'======{device_prefs_file}======')
    logger.debug('\n' + xml)
    return parsePrefs(xml)


def loadPrefsFromDirectory(prefs_filepath: str) -> Dict[str, str]:
    logger.debug(f'======{prefs_filepath}======')
    with open(prefs_filepath, 'r') as f:
        xml = f.read()
        logger.debug('\n' + xml)
        return parsePrefs(xml)


def parsePrefs(xml) -> Dict[str, str]:
    root = ElementTree.fromstring(xml)
    return {child.attrib['name']: child.text for child in root}


def b64padding(text: str):
    return text + '=' * (-len(text) % 4)
