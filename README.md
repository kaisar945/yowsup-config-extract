# yowsup-config


This is the [yowsup](https://github.com/tgalal/yowsup) configuration extractor, can be extracted from rooted android devices or local files.

## Build & Install

You should install [adb](https://developer.android.com/studio/releases/platform-tools) first in your system environment then follow the steps below.
```
$ git clone https://github.com/kaisar945/yowsup-config-extract.git ~/$ yowsup-config-extract
$ cd ~/yowsup-config-extract
$ python3 setup.py sdist
$ pip3 install dist/yowsup-config-extracter-x.x.x.tar.gz
```

## How to use?

1. Extract from rooted android device
    ```
    yowsup-config-extract -s {device-serial} -o {out-dir}
    ```

2. Extract from local directory
    ```
    yowsup-config-extract -D {local-directory} -o {out-dir}
    ```

3. See the ```--help``` option for other usage.
    ```
    usage: yowsup-config-extract [-h] [-s SERIAL] [-D DATADIR] [-p PACKAGE]
                             [-o OUT] [-d]

    Extract config from rooted android device for yowsup project.

    optional arguments:
    -h, --help            show this help message and exit
    -p PACKAGE, --package PACKAGE
                            for mod package default:com.whatsapp
    -o OUT, --out OUT     specific save directory
    -d, --debug           show debug log

    Extracter options:
    -s SERIAL, --serial SERIAL
                            extract from specific device
    -D DATADIR, --datadir DATADIR
                            extract from specific local directory
    ```

## Notice
- Not support for ```ios``` devices and no plans.