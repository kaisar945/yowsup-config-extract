class AppNotInstalledException(Exception):
    pass


class ExportConfigException(Exception):
    pass


class KeyPairInvalideException(ExportConfigException):
    pass


class NoRootException(Exception):
    pass
