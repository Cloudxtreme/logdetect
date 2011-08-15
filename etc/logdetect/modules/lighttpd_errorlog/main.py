class LogdetectExtension:
    parent = ""

    def __init__(self, parent):
        self.parent = parent

    def parseAll(self, data):
        print data
