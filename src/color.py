class Color:
    @staticmethod
    def disabled():
        Color.PURPLE = ''
        Color.CYAN = ''
        Color.DARKCYAN = ''
        Color.BLUE = ''
        Color.GREEN = ''
        Color.YELLOW = ''
        Color.RED = ''
        Color.BOLD = ''
        Color.UNDERLINE = ''
        Color.END = ''

    @staticmethod
    def enabled():
        Color.PURPLE = '\033[95m'
        Color.CYAN = '\033[96m'
        Color.DARKCYAN = '\033[36m'
        Color.BLUE = '\033[94m'
        Color.GREEN = '\033[92m'
        Color.YELLOW = '\033[93m'
        Color.RED = '\033[91m'
        Color.BOLD = '\033[1m'
        Color.UNDERLINE = '\033[4m'
        Color.END = '\033[0m'
