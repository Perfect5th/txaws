# Licenced under the txaws licence available at /LICENSE in the txaws source.

"""
Tests for L{txaws.client.base}.
"""

import os

from io import StringIO
from datetime import datetime
from hashlib import sha256

from zope.interface import implementer

import attr

from twisted.internet import reactor, ssl
from twisted.internet.defer import Deferred
from twisted.internet.error import ConnectionRefusedError
from twisted.protocols.policies import WrappingFactory
from twisted.python import log
from twisted.python.filepath import FilePath
from twisted.python.failure import Failure
from twisted.test.test_sslverify import makeCertificate
from twisted.trial.unittest import TestCase
from twisted.web import server, static
from twisted.web.http_headers import Headers
from twisted.web.client import ResponseDone
from twisted.web.resource import Resource
from twisted.web.error import Error as TwistedWebError
from twisted.web.iweb import IAgent

from txaws.service import REGION_US_EAST_1
from txaws.credentials import AWSCredentials
from txaws.client import base, ssl
from txaws.client.base import (
    RequestDetails, BaseClient, BaseQuery, error_wrapper,
    StreamingBodyReceiver, _URLContext, url_context,
)
from txaws._auth_v4 import _CanonicalRequest
from txaws.service import AWSServiceEndpoint
from txaws.testing.producers import StringBodyProducer

from zope.interface.verify import verifyClass


class URLContextTests(TestCase):
    """
    Tests for L{txaws.client.base.url_context}.
    """
    def test_construction(self):
        """
        L{url_context} constructs a L{_URLContext} with its parameters.
        """
        params = dict(
            scheme="https",
            host="example.invalid",
            port=80,
            path=["foo"],
            query=[("bar", "baz")],
        )
        self.assertEqual(
            _URLContext(**params),
            url_context(**params),
        )


class ErrorWrapperTestCase(TestCase):

    def test_204_no_content(self):
        failure = Failure(TwistedWebError(204, b"No content"))
        wrapped = error_wrapper(failure, None)
        self.assertEqual(wrapped, "204 No content")

    def test_302_found(self):
        # XXX I'm not sure we want to raise for 300s...
        failure = Failure(TwistedWebError(302, b"found"))
        error = self.assertRaises(
            Exception, error_wrapper, failure, None)
        self.assertEqual(failure.type, type(error))
        self.assertTrue(isinstance(error, TwistedWebError))
        self.assertEqual(str(error), "302 found")

    def test_500(self):
        failure = Failure(TwistedWebError(500, b"internal error"))
        error = self.assertRaises(
            Exception, error_wrapper, failure, None)
        self.assertTrue(isinstance(error, TwistedWebError))
        self.assertEqual(str(error), "500 internal error")

    def test_timeout_error(self):
        failure = Failure(Exception("timeout"))
        error = self.assertRaises(Exception, error_wrapper, failure, None)
        self.assertTrue(isinstance(error, Exception))
        self.assertEqual(str(error), "timeout")

    def test_connection_error(self):
        failure = Failure(ConnectionRefusedError("timeout"))
        error = self.assertRaises(
            Exception, error_wrapper, failure, ConnectionRefusedError)
        self.assertTrue(isinstance(error, ConnectionRefusedError))


class BaseClientTestCase(TestCase):

    def test_creation(self):
        client = BaseClient("creds", "endpoint", "query factory", "parser")
        self.assertEqual(client.creds, "creds")
        self.assertEqual(client.endpoint, "endpoint")
        self.assertEqual(client.query_factory, "query factory")
        self.assertEqual(client.parser, "parser")


class PuttableResource(Resource):

    def render_PUT(self, reuqest):
        return b''


class BaseQueryTestCase(TestCase):

    def setUp(self):
        self.cleanupServerConnections = 0
        name = self.mktemp()
        os.mkdir(name)
        FilePath(name).child("file").setContent(b"0123456789")
        r = static.File(name)
        r.putChild(b'thing_to_put', PuttableResource())
        self.site = server.Site(r, timeout=None)
        self.wrapper = WrappingFactory(self.site)
        self.port = self._listen(self.wrapper)
        self.portno = self.port.getHost().port

    def tearDown(self):
        # If the test indicated it might leave some server-side connections
        # around, clean them up.
        connections = list(self.wrapper.protocols.keys())
        # If there are fewer server-side connections than requested,
        # that's okay.  Some might have noticed that the client closed
        # the connection and cleaned up after themselves.
        for n in range(min(len(connections), self.cleanupServerConnections)):
            proto = connections.pop()
            log.msg("Closing %r" % (proto,))
            proto.transport.loseConnection()
        if connections:
            log.msg("Some left-over connections; this test is probably buggy.")
        return self.port.stopListening()

    def _listen(self, site):
        return reactor.listenTCP(0, site, interface="127.0.0.1")

    def _get_url(self, path):
        return "http://127.0.0.1:%d/%s" % (self.portno, path)

    def test_creation(self):
        query = BaseQuery("an action", "creds", "http://endpoint")
        self.assertEqual(query.action, "an action")
        self.assertEqual(query.creds, "creds")
        self.assertEqual(query.endpoint, "http://endpoint")

    def test_init_requires_action(self):
        self.assertRaises(TypeError, BaseQuery)

    def test_init_requires_creds(self):
        self.assertRaises(TypeError, BaseQuery, None)

    def test_get_page(self):
        query = BaseQuery(
            "an action", "creds", AWSServiceEndpoint("http://endpoint"),
        )
        d = query.get_page(self._get_url("file"))
        d.addCallback(self.assertEqual, b"0123456789")
        return d

    def test_get_request_headers_no_client(self):

        query = BaseQuery("an action", "creds", "http://endpoint")
        results = query.get_request_headers()
        self.assertEqual(results, None)

    def test_get_request_headers_with_client(self):

        def check_results(results):
            self.assertEqual(list(results.keys()), [])
            self.assertEqual(list(results.values()), [])

        query = BaseQuery(
            "an action", "creds", AWSServiceEndpoint("http://endpoint"),
        )
        d = query.get_page(self._get_url("file"))
        d.addCallback(query.get_request_headers)
        return d.addCallback(check_results)

    def test_get_response_headers_no_client(self):

        query = BaseQuery("an action", "creds", "http://endpoint")
        results = query.get_response_headers()
        self.assertEqual(results, None)

    def test_get_response_headers_with_client(self):

        def check_results(results):
            #self.assertEquals(sorted(results.keys()), [
            #    "accept-ranges", "content-length", "content-type", "date",
            #    "last-modified", "server"])
            # XXX I think newclient exludes content-length from headers?
            # Also the header names are capitalized ... do we need to worry
            # about backwards compat?
            self.assertEqual(sorted(results.keys()), [
                b"Accept-Ranges", b"Content-Type", b"Date",
                b"Last-Modified", b"Server"])
            self.assertEqual(len(list(results.values())), 5)

        query = BaseQuery(
            "an action", "creds", AWSServiceEndpoint("http://endpoint"),
        )
        d = query.get_page(self._get_url("file"))
        d.addCallback(query.get_response_headers)
        return d.addCallback(check_results)

    def test_errors(self):
        query = BaseQuery(
            "an action", "creds", AWSServiceEndpoint("http://endpoint"),
        )
        d = query.get_page(self._get_url("not_there"))
        self.assertFailure(d, TwistedWebError)
        return d

    def test_custom_body_producer(self):

        def check_producer_was_used(ignore):
            self.assertEqual(producer.written, 'test data')

        producer = StringBodyProducer('test data')
        query = BaseQuery(
            "an action", "creds", AWSServiceEndpoint("http://endpoint"),
            body_producer=producer,
        )
        d = query.get_page(self._get_url("thing_to_put"), method='PUT')
        return d.addCallback(check_producer_was_used)

    def test_custom_receiver_factory(self):

        class TestReceiverProtocol(StreamingBodyReceiver):
            used = False

            def __init__(self):
                StreamingBodyReceiver.__init__(self)
                TestReceiverProtocol.used = True

        def check_used(ignore):
            self.assertTrue(TestReceiverProtocol.used)

        query = BaseQuery(
            "an action", "creds",
            AWSServiceEndpoint("http://endpoint"),
            receiver_factory=TestReceiverProtocol,
        )
        d = query.get_page(self._get_url("file"))
        d.addCallback(self.assertEqual, b"0123456789")
        d.addCallback(check_used)
        return d

    # XXX for systems that don't have certs in the DEFAULT_CERT_PATH, this test
    # will fail; instead, let's create some certs in a temp directory and set
    # the DEFAULT_CERT_PATH to point there.
    def test_ssl_hostname_verification(self):
        """
        If the endpoint passed to L{BaseQuery} has C{ssl_hostname_verification}
        sets to C{True}, no ContextFactory is passed to C{connectSSL},
        allowing it to use Twisted's default BrowserLikePolicyForHTTPS
        """
        agent_creations = []

        @implementer(IAgent)
        class FakeAgent(object):
            def __init__(self, reactor, contextFactory=None,
                         connectTimeout=None, bindAddress=None, pool=None):
                agent_creations.append((reactor, contextFactory,
                                        connectTimeout, bindAddress, pool))

            def request(self, method, uri, headers=None, bodyProducer=None):
                return Deferred()

        verifyClass(IAgent, FakeAgent)

        certs = [makeCertificate(O="Test Certificate", CN="something")[1]]
        self.patch(base, "Agent", FakeAgent)
        self.patch(ssl, "_ca_certs", certs)
        endpoint = AWSServiceEndpoint(ssl_hostname_verification=True)
        query = BaseQuery("an action", "creds", endpoint, reactor="ignored")
        query.get_page("https://example.com/file")

        self.assertEqual(len(agent_creations), 1)
        [(_, contextFactory, _, _, _)] = agent_creations
        self.assertIsNone(contextFactory)


class StreamingBodyReceiverTestCase(TestCase):

    def test_readback_mode_on(self):
        """
        Test that when readback mode is on inside connectionLost() data will
        be read back from the start of the file we're streaming and results
        passed to finished callback.
        """

        receiver = StreamingBodyReceiver()
        d = Deferred()
        receiver.finished = d
        receiver.content_length = 5
        fd = receiver._fd
        receiver.dataReceived(b'hello')
        why = Failure(ResponseDone('done'))
        receiver.connectionLost(why)
        self.assertEqual(d.result, b'hello')
        self.assertTrue(fd.closed)

    def test_readback_mode_off(self):
        """
        Test that when readback mode is off connectionLost() will simply
        callback finished with the fd.
        """

        receiver = StreamingBodyReceiver(readback=False)
        d = Deferred()
        receiver.finished = d
        receiver.content_length = 5
        fd = receiver._fd
        receiver.dataReceived(b'hello')
        why = Failure(ResponseDone('done'))
        receiver.connectionLost(why)
        self.assertIdentical(d.result, fd)
        self.assertIdentical(receiver._fd, fd)
        self.assertFalse(fd.closed)

    def test_user_fd(self):
        """
        Test that user's own file descriptor can be passed to init
        """
        user_fd = StringIO()
        receiver = StreamingBodyReceiver(user_fd)
        self.assertIdentical(receiver._fd, user_fd)



@attr.s
@implementer(IAgent)
class StubAgent(object):
    _requests = attr.ib(init=False, default=attr.Factory(list))

    def request(self, method, url, headers, bodyProducer):
        result = Deferred()
        self._requests.append((method, url, headers, bodyProducer, result))
        return result


class QueryTestCase(TestCase):
    """
    Tests for L{query}.
    """
    def setUp(self):
        self.credentials = AWSCredentials(
            "access key id", "secret access key",
        )
        self.agent = StubAgent()
        self.now = datetime.utcfromtimestamp(1234567890)

    def utcnow(self):
        return self.now

    def test_canonical_request(self):
        """
        L{_Query._canonical_request} is the canonical request which should
        be signed according to the AWS SigV4 rules.
        """
        url_context = base.url_context(
            scheme="https",
            host="example.invalid",
            port=443,
            path=["foo", "bar"],
            query=[("baz",), ("quux", "thud")],
        )
        content_sha256 = sha256(b"random whatever").hexdigest()
        details = RequestDetails(
            region=REGION_US_EAST_1,
            service="iam",
            method="GET",
            url_context=url_context,
            content_sha256=content_sha256,
        )

        query = base.query(
            credentials=self.credentials,
            details=details,
        )
        self.assertEqual(
            attr.asdict(_CanonicalRequest(
                method="GET",
                canonical_uri="/foo/bar",
                # Amazon docs don't make it clear that no-argument
                # query parameters (like "baz" in this case) should be
                # transformed into empty-value query parameters for
                # the canonical request.  They should.
                canonical_query_string="baz=&quux=thud",
                canonical_headers="host:example.invalid\nx-amz-date:20090213T233130Z\n",
                signed_headers="host;x-amz-date",
                payload_hash=content_sha256,
            )),
            attr.asdict(query._canonical_request(Headers({
                "host": ["example.invalid"],
                "x-amz-date": ["20090213T233130Z"],
            }))),
        )

    def test_submit(self):
        """
        C{submit} uses the given L{IAgent} to issue a request as described
        by the query's credentials and request details.
        """
        url_context = base.url_context(
            scheme="https",
            host="example.invalid",
            port=443,
            path=[],
        )
        content_sha256 = sha256(b"").hexdigest()
        details = RequestDetails(
            region=REGION_US_EAST_1,
            service="iam",
            method="GET",
            url_context=url_context,
            content_sha256=content_sha256,
        )
        query = base.query(
            credentials=self.credentials,
            details=details,
        )

        self.assertNoResult(query.submit(self.agent, utcnow=self.utcnow))
        [(method, url, headers, _, _)] = self.agent._requests

        date = b"20090213T233130Z"
        host = b"example.invalid"

        authorization = query._sign(
            self.now,
            self.credentials,
            details.service,
            details.region,
            query._canonical_request(
                Headers({
                    b"host": [host],
                    b"x-amz-date": [date],
                }),
            )
        )

        self.assertEqual(details.method, method.decode())
        self.assertEqual("https://example.invalid:443/", url.decode())
        self.assertEqual(
            Headers({
                b"host": [host],
                b"x-amz-date": [date],
                b"x-amz-content-sha256": [content_sha256],
                b"authorization": [authorization],
            }), headers,
        )
        # It's hard to make an assertion about the bodyProducer or I
        # would do that too.
