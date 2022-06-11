from zope.interface import implementer

from twisted.internet.defer import succeed
from twisted.web.iweb import IBodyProducer

@implementer(IBodyProducer)
class StringBodyProducer(object):

    def __init__(self, data):
        self.data = data
        self.length = len(data)
        self.written = None

    def startProducing(self, consumer):
        consumer.write(self.data)
        self.written = self.data
        return succeed(None)

    def pauseProducing(self):
        pass

    def stopProducing(self):
        pass
