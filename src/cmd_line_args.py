"""Manages command line arguments"""

from dataclasses import dataclass
import sys


@dataclass
class Flag:
    """Represents a command line flag"""
    name: str
    help_message: str
    aliases: tuple[str] = None
    exclusive: tuple[str] = None


@dataclass
class Argument:
    """Represents a command line argument"""
    value: str | int


help_flag = Flag(
    name="help",
    aliases=("h"),
    help_message="Display this help menu"
)

other_flag = Flag(name="other", aliases=("o"), help_message="pass")

flags = (help_flag, other_flag)


class Arguments:
    """Command line argument managment"""

    def __init__(self):
        args = sys.argv
        self.args = args[1:]
        self.flags = [i.lstrip('-') for i in self.args if i.startswith('-')]

    def which_flag(self, arg: str):
        """Detertmines which flag the argument is for

        Returns:
            flag_name: The name of the flag
        """
        for i in flags:
            if arg == i.name or arg in i.aliases:
                return i.name
            else:
                raise Exception(f"{arg} is not a valid argument")

    def check_collisions(self):
        """checks if therfe are any exclusive arguments that have been passed"""

    def parse_cmd_line(self):
        """
        Parse the command line arguments to properly initiate the program.
        """
        if help_flag.name in self.flags or [True for i in self.flags in help_flag.aliases]:  # pylint: disable=fixme, line-too-long
            self.check_collisions()
