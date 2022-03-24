# yowsup-config


This is the [yowsup](https://github.com/tgalal/yowsup) configuration extractor, can be extracted from rooted android devices or local files.

## Build & Install

You should install [adb](https://developer.android.com/studio/releases/platform-tools) first in your system environment then follow the steps below.
```shell
$ git clone https://github.com/kaisar945/yowsup-config-extract.git
$ cd yowsup-config-extract
$ python3 setup.py sdist
$ pip3 install dist/yowsup-config-extracter-x.x.x.tar.gz
```

## How to use?

1. Extract from rooted android device
    ```shell
    yowsup-config-extract -s {android-device-serial} -fmt {conf|hash}
    ```

2. Extract from local directory
    ```shell
    yowsup-config-extract -d {local-directory} -fmt {conf|hash}
    ```

3. See the ```--help``` option for other usage.
    ```
    usage: yowsup-config-extract [-h] [-s SERIAL] [-d DATADIR] [-p PACKAGE] [-fmt {conf,hash}] [-D]
    
    Extract config file for yowsup project.
    
    optional arguments:
      -h, --help            show this help message and exit
      -p PACKAGE, --package PACKAGE
                            for mod package, default:com.whatsapp
    
    Extracter options:
      -s SERIAL, --serial SERIAL
                            extract from specific android device
      -d DATADIR, --datadir DATADIR
                            extract from specific local directory
    
    Output options:
      -fmt {conf,hash}, --output-format {conf,hash}
                            output format
      -D, --debug           show debug log
    ```

## Notice
- Not support for ```ios``` devices and no plans.