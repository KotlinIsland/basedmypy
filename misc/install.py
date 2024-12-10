import argparse
from subprocess import check_call


def main(args: argparse.Namespace):
    venv_args = ["uv", "venv", "--python", args.python, f".venv{args.python}"]
    check_call(venv_args)
    install_args = ["uv", "pip", "install", "-r", "test-requirements.txt", "-e", ".", "--python", f".venv{args.python}"]
    check_call(install_args)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--python", rquired=True)
    main(parser.parse_args())
