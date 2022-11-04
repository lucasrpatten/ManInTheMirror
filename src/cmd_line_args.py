"""Manages command line arguments"""

from dataclasses import dataclass
import sys


@dataclass
class Flag:
    """Represents a command line flag"""
    name: str
    help_message: str
    exclusive: list[str] = ()
    aliases: list[str] = ()


@dataclass
class Argument:
    """Represents a command line argument"""
    value: str | int


class Flags:
    """Contains all command line flags"""

    def __init__(self) -> None:
        self.help_flag = Flag(
            name="help",
            aliases=("h"),
            exclusive=["*"],
            help_message="Display this help menu"
        )

        self.other_flag = Flag(
            name="other",
            aliases=["o"],
            help_message="pass",
            exclusive=["help"]
        )

        self.flags = (self.help_flag, self.other_flag)


class Arguments(Flags):
    """Command line argument management"""

    def __init__(self):
        Flags.__init__(self)
        args = sys.argv
        self.args = args[1:]
        self.flag_args = [i.lstrip('-') for i in self.args if i.startswith('-')]
        self.command_names = self.get_cmd_names()

    def get_cmd_names(self) -> list:
        """Get the names of all the flags

        Returns:
            command_names: the names of the commands
        """
        command_names = []
        for i in self.flag_args:
            command_names.append(self.which_flag(i))
        return command_names

    def which_flag(self, arg: str):
        """Determines which flag the argument is for

        Returns:
            flag_name: The name of the flag
        """
        for flag in self.flags:
            if arg == str(flag.name) or arg in list[str](flag.aliases):
                return str(flag.name)
            else:
                pass
        raise Exception(f"{arg} is not a valid argument")

    def exclusive_list(self, name: str) -> list[str]:
        """
            Determines what arguments are exclusive with given one
        Returns:
            exclusive_list: list of exclusive arguments
        """
        # remove use of eval if possible
        return eval(f'self.{name}_flag.exclusive')

    def check_collisions(self):
        """raises exception if there are exclusive collisions"""
        for name in self.command_names:
            for exclusive in self.exclusive_list(name):
                if exclusive in self.command_names:
                    raise Exception(f"'{exclusive}' argument is exclusive to '{name}'")
                elif exclusive == "*" and len(self.command_names) > 1:
                    raise Exception(f"the '{name}' argument must be the only flag passed")

    def help_command(self):
        """Prints out the help menu"""
        heading = f"|{'Command':^10}|{'Aliases':^20}|{'Exclusive To':^40}|{'Description':^60}|"
        print(heading)
        print('─' * (10 + 20 + 40 + 60 + 5))
        for flag in self.flags:
            name = '--' + flag.name
            aliases = str(['-' + i for i in flag.aliases])
            exclusives = str(flag.exclusive)
            description = flag.help_message
            print(f"|{name :^10}|{aliases:^20}|{exclusives:^40}|{description:^60}|")

    def parse_cmd_line(self):
        """
        Parse the command line arguments to properly initiate the program.
        """
        self.check_collisions()
        for flag in self.command_names:
            match flag:
                case 'help':
                    self.help_command()
                case _:
                    pass
