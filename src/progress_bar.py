import sys


class ProgressBar:
    def __init__(self, iterable):
        self.iterable = iterable
        self.length = len(iterable)
        self.current = 0

    def __iter__(self):
        self.current = 0
        for item in self.iterable:
            yield item
            self.current += 1
            self.print_progress()

    def print_progress(self):
        progress = self.current / self.length
        bar_length = 30
        filled_length = int(progress * bar_length)
        bar = "█" * filled_length + " " * (bar_length - filled_length)
        percent = round(progress * 100, 2)
        sys.stdout.write('\r|%s| %s%% Completed' % (bar, percent))
        sys.stdout.flush()
        if percent == 100:
            sys.stdout.write("\n")
