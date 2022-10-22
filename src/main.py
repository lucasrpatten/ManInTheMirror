"""Program entry point"""
from cmd_line_args import Arguments

args = Arguments()

if __name__ == "__main__":
    args.parse_cmd_line()
