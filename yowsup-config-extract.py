import argparse
from yowsup_config.extracter import Extracter


def main():
    parser = argparse.ArgumentParser(prog='yowsup-config-extract', description='Extract config from rooted android device for yowsup project.')
    parser.add_argument('--out', type=str, help='specific save directory')
    args = parser.parse_args()
    if args.out:
        Extracter().extractFromDevice(args.out)
    else:
        print('no handle command')


if __name__ == '__main__':
    main()
