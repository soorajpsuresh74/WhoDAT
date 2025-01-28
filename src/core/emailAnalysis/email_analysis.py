from src.core.emailAnalysis.emailParser import parse_my_mail


class EmailAnalysis:
    def __init__(self, file=None):
        self.file = file
        if self.file:
            self.metadata, self.content, self.links, self.attachments = parse_my_mail(self.file)
