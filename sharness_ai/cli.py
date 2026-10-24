import argparse
import sys

from sharness_ai._version import VERSION


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='sharness', description='sharness — the SHarness-AI command line tool')
    parser.add_argument('--version', action='version', version=f'sharness-ai {VERSION}')
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    parser.parse_args(argv)
    parser.print_help()
    return 0


if __name__ == '__main__':
    sys.exit(main())
