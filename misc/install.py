import argparse
from subprocess import check_call


def main(args: argparse.Namespace):
    venv_args = ["uv", "venv"]
    if args.python:
        venv_args.extend(["--python", args.python, f".venv{args.python}"])
    check_call(venv_args)
    install_args = ["uv", "pip", "install", "-r", "test-requirements.txt", "-e", "."]
    if args.python:
        install_args.extend(["--python", f".venv{args.python}"])
    check_call(install_args)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--python")
    main(parser.parse_args())
