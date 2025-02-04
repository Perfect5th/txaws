# Licenced under the txaws licence available at /LICENSE in the txaws source.

"""
Tests for ``txaws.route53``.
"""

from ipaddress import IPv4Address, IPv6Address

from twisted.internet.task import Cooperator
from twisted.trial.unittest import TestCase
from twisted.web.http import OK, BAD_REQUEST
from twisted.web.static import Data
from twisted.web.resource import IResource, Resource

from txaws.service import AWSServiceRegion
from txaws.testing.integration import get_live_service
from txaws.testing.route53_tests import route53_integration_tests

from txaws.route53.model import (
    HostedZone, RRSetKey, RRSet, AliasRRSet,
    create_rrset, delete_rrset, upsert_rrset,
)
from txaws.route53.client import (
    A, AAAA, NAPTR, PTR, SPF, SRV, TXT, MX, NS, SOA, CNAME,
    UnknownRecordType,
    Name, get_route53_client,
    Route53Error,
)

from treq.testing import RequestTraversalAgent

def uncooperator(started=True):
    return Cooperator(
        # Don't stop consuming the iterator.
        terminationPredicateFactory=lambda: lambda: False,
        scheduler=lambda what: (what(), object())[1],
        started=started,
    )

class POSTableData(Data):
    posted = ()

    def __init__(self, data, type, status=OK):
        Data.__init__(self, data, type)
        self._status = status

    def render_POST(self, request):
        request.setResponseCode(self._status)
        self.posted += (request.content.read(),)
        return Data.render_GET(self, request)


def static_resource(hierarchy):
    root = Resource()
    for k, v in hierarchy.items():
        if IResource.providedBy(v):
            root.putChild(k, v)
        elif isinstance(v, dict):
            root.putChild(k, static_resource(v))
        else:
            raise NotImplementedError(v)
    return root


class sample_create_resource_record_sets_error_result(object):
    label = Name("duplicate.example.invalid.")
    type = "CNAME"

    cname = CNAME(
        canonical_name=Name("somewhere.example.invalid."),
    )
    rrset = RRSet(
        label=label,
        type="CNAME",
        ttl=600,
        records={cname},
    )

    xml = """\
<?xml version="1.0"?>
<ErrorResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><Error><Type>Sender</Type><Code>InvalidChangeBatch</Code><Message>[Tried to create resource record set [name='{label}', type='{type}'] but it already exists]</Message></Error><RequestId>9197fef4-03cc-11e9-b35f-7947070744f2</RequestId></ErrorResponse>
""".format(label=label, type=type).encode()


class sample_list_resource_record_sets_result(object):
    label = Name("example.invalid.")
    soa_ttl = 60
    soa = SOA(
        mname=Name("1.awsdns-1.net."),
        rname=Name("awsdns-hostmaster.amazon.com."),
        serial=1,
        refresh=7200,
        retry=900,
        expire=1209600,
        minimum=86400,
    )
    ns_ttl = 120
    ns1 = NS(
        nameserver=Name("ns-1.awsdns-1.net."),
    )
    ns2 = NS(
        nameserver=Name("ns-2.awsdns-2.net."),
    )

    cname_ttl = 180
    # The existence of a CNAME record for example.invalid. is bogus
    # because if you have a CNAME record for a name you're not
    # supposed to have any other records for it - and we have soa, ns,
    # etc.  However, noone is interpreting this data with DNS
    # semantics.  We're just parsing it.  Hope that's okay with you.
    cname = CNAME(
        canonical_name=Name("somewhere.example.invalid."),
    )
    xml = """\
<?xml version="1.0"?>
<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ResourceRecordSets><ResourceRecordSet><Name>{label}</Name><Type>NS</Type><TTL>{ns_ttl}</TTL><ResourceRecords><ResourceRecord><Value>{ns1.nameserver}</Value></ResourceRecord><ResourceRecord><Value>{ns2.nameserver}</Value></ResourceRecord></ResourceRecords></ResourceRecordSet><ResourceRecordSet><Name>{label}</Name><Type>SOA</Type><TTL>{soa_ttl}</TTL><ResourceRecords><ResourceRecord><Value>{soa.mname} {soa.rname} {soa.serial} {soa.refresh} {soa.retry} {soa.expire} {soa.minimum}</Value></ResourceRecord></ResourceRecords></ResourceRecordSet><ResourceRecordSet><Name>{label}</Name><Type>CNAME</Type><TTL>{cname_ttl}</TTL><ResourceRecords><ResourceRecord><Value>{cname.canonical_name}</Value></ResourceRecord></ResourceRecords></ResourceRecordSet></ResourceRecordSets><IsTruncated>false</IsTruncated><MaxItems>100</MaxItems></ListResourceRecordSetsResponse>
""".format(
    label=label,
    soa=soa, soa_ttl=soa_ttl,
    ns1=ns1, ns2=ns2, ns_ttl=ns_ttl,
    cname=cname, cname_ttl=cname_ttl,
).encode("utf-8")


class sample_change_resource_record_sets_result(object):
    rrset = RRSet(
        label=Name("example.invalid."),
        type="NS",
        ttl=86400,
        records={
            NS(Name("ns1.example.invalid.")),
            NS(Name("ns2.example.invalid.")),
        },
    )
    xml = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<ChangeResourceRecordSetsResponse>
   <ChangeInfo>
      <Comment>string</Comment>
      <Id>string</Id>
      <Status>string</Status>
      <SubmittedAt>timestamp</SubmittedAt>
   </ChangeInfo>
</ChangeResourceRecordSetsResponse>
"""

class sample_list_hosted_zones_result(object):
    details = dict(
        name="example.invalid.",
        identifier="ABCDEF123456",
        reference="3CCF1549-806D-F91A-906F-A3727E910C87",
        rrset_count=6,
    )
    xml = """\
<?xml version="1.0"?>
<ListHostedZonesResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><HostedZones><HostedZone><Id>/hostedzone/{identifier}</Id><Name>{name}</Name><CallerReference>{reference}</CallerReference><Config><PrivateZone>false</PrivateZone></Config><ResourceRecordSetCount>{rrset_count}</ResourceRecordSetCount></HostedZone></HostedZones><IsTruncated>false</IsTruncated><MaxItems>100</MaxItems></ListHostedZonesResponse>
""".format(**details).encode()


class sample_list_resource_records_with_alias_result(object):
    normal_target = Name("bar.example.invalid.")
    normal = RRSet(
        label=Name("foo.example.invalid."),
        type="CNAME",
        ttl=60,
        records={CNAME(canonical_name=normal_target)},
    )

    normal_xml = """\
<ResourceRecordSet><Name>{label}</Name><Type>{type}</Type><TTL>{ttl}</TTL><ResourceRecords><ResourceRecord><Value>{value}</Value></ResourceRecord></ResourceRecords></ResourceRecordSet>
""".format(
    label=normal.label,
    type=normal.type,
    ttl=normal.ttl,
    value=normal_target,
)

    alias = AliasRRSet(
        label=Name("bar.example.invalid."),
        type="A",
        dns_name=Name(
            "dualstack.a952f315901e6b3c812e57076f5b4138-0795221525.us-east-1.elb.amazonaws.com.",
        ),
        evaluate_target_health=False,
        hosted_zone_id="ZSXD5Q7O3X7TRK",
    )

    alias_xml = """\
<ResourceRecordSet><Name>{label}</Name><Type>{type}</Type><AliasTarget><HostedZoneId>{hosted_zone_id}</HostedZoneId><DNSName>{dns_name}</DNSName><EvaluateTargetHealth>{evaluate_target_health}</EvaluateTargetHealth></AliasTarget></ResourceRecordSet>
""".format(
    label=alias.label,
    type=alias.type,
    hosted_zone_id=alias.hosted_zone_id,
    dns_name=alias.dns_name,
    evaluate_target_health=["false", "true"][alias.evaluate_target_health],
)

    xml = """\
<?xml version="1.0"?>\n
<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ResourceRecordSets>{normal}{alias}</ResourceRecordSets><IsTruncated>false</IsTruncated><MaxItems>100</MaxItems></ListResourceRecordSetsResponse>
""".format(normal=normal_xml, alias=alias_xml).encode("utf-8")


class ListHostedZonesTestCase(TestCase):
    """
    Tests for C{list_hosted_zones}.
    """
    def test_some_zones(self):
        agent = RequestTraversalAgent(static_resource({
            b"2013-04-01": {
                b"hostedzone": Data(
                    sample_list_hosted_zones_result.xml,
                    "text/xml",
                ),
            },
        }))
        aws = AWSServiceRegion(access_key="abc", secret_key="def")
        client = get_route53_client(agent, aws, uncooperator())
        zones = self.successResultOf(client.list_hosted_zones())
        expected = [HostedZone(**sample_list_hosted_zones_result.details)]
        self.assertEqual(expected, zones)


class ListResourceRecordSetsTestCase(TestCase):
    """
    Tests for C{list_resource_record_sets}.
    """
    def _client_for_rrsets(self, zone_id, rrsets_xml):
        agent = RequestTraversalAgent(static_resource({
            b"2013-04-01": {
                b"hostedzone": {
                    zone_id: {
                        b"rrset": Data(
                            rrsets_xml,
                            "text/xml",
                        )
                    }
                }
            }
        }))
        aws = AWSServiceRegion(access_key="abc", secret_key="def")
        return get_route53_client(agent, aws, uncooperator())


    def test_soa_ns_cname(self):
        zone_id = b"ABCDEF1234"
        client = self._client_for_rrsets(
            zone_id, sample_list_resource_record_sets_result.xml)
        rrsets = self.successResultOf(client.list_resource_record_sets(
            zone_id=zone_id.decode()))
        expected = {
            RRSetKey(
                label=sample_list_resource_record_sets_result.label,
                type="SOA",
            ): RRSet(
                label=sample_list_resource_record_sets_result.label,
                type="SOA",
                ttl=sample_list_resource_record_sets_result.soa_ttl,
                records={sample_list_resource_record_sets_result.soa},
            ),
            RRSetKey(
                label=sample_list_resource_record_sets_result.label,
                type="NS",
            ): RRSet(
                label=sample_list_resource_record_sets_result.label,
                type="NS",
                ttl=sample_list_resource_record_sets_result.ns_ttl,
                records={
                    sample_list_resource_record_sets_result.ns1,
                    sample_list_resource_record_sets_result.ns2,
                },
            ),
            RRSetKey(
                label=sample_list_resource_record_sets_result.label,
                type="CNAME",
            ): RRSet(
                label=sample_list_resource_record_sets_result.label,
                type="CNAME",
                ttl=sample_list_resource_record_sets_result.cname_ttl,
                records={sample_list_resource_record_sets_result.cname},
            ),
        }
        self.assertEqual(rrsets, expected)


    def _simple_record_test(self, record_type, record):
        zone_id = b"ABCDEF1234"
        template = """\
<?xml version="1.0"?>
<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <ResourceRecordSets>
    <ResourceRecordSet>
      <Name>{label}</Name>
      <Type>{type}</Type>
      <TTL>{ttl}</TTL>
      <ResourceRecords>
        <ResourceRecord><Value>{record}</Value></ResourceRecord>
      </ResourceRecords>
    </ResourceRecordSet>
  </ResourceRecordSets>
  <IsTruncated>false</IsTruncated>
  <MaxItems>100</MaxItems>
</ListResourceRecordSetsResponse>
"""
        label = Name("foo")
        client = self._client_for_rrsets(
            zone_id, template.format(
                label=label,
                type=record_type,
                ttl=60, record=record.to_text(),
            ).encode("utf-8")
        )
        expected = {
            RRSetKey(label=label, type=record_type): RRSet(
                label=label, type=record_type, ttl=60, records={record},
            ),
        }
        rrsets = self.successResultOf(
            client.list_resource_record_sets(zone_id=zone_id.decode()),
        )
        self.assertEqual(expected, rrsets)


    def test_a(self):
        self._simple_record_test(
            "A",
            # RFC 5737 suggests an address like this one.
            A(IPv4Address("192.0.2.1")),
        )


    def test_aaaa(self):
        self._simple_record_test(
            "AAAA",
            # RFC 3849 suggests an address like this one.
            AAAA(IPv6Address("2001:DB8::d0c")),
        )


    def test_cname(self):
        self._simple_record_test(
            "CNAME",
            CNAME(Name("bar")),
        )


    def test_mx(self):
        self._simple_record_test(
            "MX",
            MX(Name("bar"), 15),
        )


    def test_naptr_with_regexp(self):
        self._simple_record_test(
            "NAPTR",
            NAPTR(
                order=3,
                preference=7,
                flag="SUP",
                service="E2U+sip",
                regexp="!^(\\+441632960083)$!sip:\\1@example.test!",
                replacement=Name("."),
            ),
        )


    def test_naptr_with_replacement(self):
        self._simple_record_test(
            "NAPTR",
            NAPTR(
                order=3,
                preference=7,
                flag="SUP",
                service="E2U+sip",
                regexp="",
                replacement=Name("foo.example.test."),
            ),
        )


    def test_ptr(self):
        self._simple_record_test(
            "PTR",
            PTR(Name("foo.example.test")),
        )


    def test_spf(self):
        self._simple_record_test(
            "SPF",
            # RFC 5737 suggests an address like this one.
            SPF("v=spf1 ip4:192.0.2.1/24 -all"),
        )


    def test_srv(self):
        self._simple_record_test(
            "SRV",
            SRV(1, 2, 3, Name("example.test")),
        )


    def test_txt(self):
        self._simple_record_test(
            "TXT",
            TXT([
                "foo bar baz quux",
                "bzzzzzt",
                "\"",
                "\N{LATIN SMALL LETTER E WITH ACUTE}",
            ]),
        )


    def test_txt_encoding(self):
        self.assertEqual(
            '"foo bar baz quux" "bzzzzzt" "\\""',
            TXT([
                "foo bar baz quux",
                "bzzzzzt",
                "\"",
            ]).to_text(),
        )

        # TODO: Proper octal encoding/decoding for special characters.
        # self.assertEqual(
        #     u'"octal encoding example" "\\351"',
        #     TXT([
        #         u"octal encoding example",
        #         u"\N{LATIN SMALL LETTER E WITH ACUTE}",
        #     ]).to_text(),
        # )


    def test_unknown_record_type_roundtrip(self):
        self.assertEqual(
            "foo bar baz",
            UnknownRecordType("foo bar baz").to_text(),
        )


    def test_unknown_record_type(self):
        zone_id = b"ABCDEF1234"
        template = """\
<?xml version="1.0"?>
<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <ResourceRecordSets>
    <ResourceRecordSet>
      <Name>{label}</Name>
      <Type>{type}</Type>
      <TTL>{ttl}</TTL>
      <ResourceRecords>
        <ResourceRecord><Value>{record}</Value></ResourceRecord>
      </ResourceRecords>
    </ResourceRecordSet>
  </ResourceRecordSets>
  <IsTruncated>false</IsTruncated>
  <MaxItems>100</MaxItems>
</ListResourceRecordSetsResponse>
"""
        label = Name("foo")
        client = self._client_for_rrsets(
            zone_id, template.format(
                label=label,
                type="X-TXAWS-FICTIONAL",
                ttl=60, record="good luck interpreting this",
            ).encode("utf-8")
        )
        expected = {
            RRSetKey(label=label, type="X-TXAWS-FICTIONAL"): RRSet(
                label=label, type="X-TXAWS-FICTIONAL", ttl=60,
                records={UnknownRecordType("good luck interpreting this")},
            ),
        }
        rrsets = self.successResultOf(
            client.list_resource_record_sets(zone_id=zone_id.decode()))
        self.assertEqual(expected, rrsets)


    def test_alias_records(self):
        """
        If there are special AWS-custom "alias" records in the response, they are
        represented in the result as ``AliasRRSet`` instances.
        """
        zone_id = b"ABCDEF1234"
        client = self._client_for_rrsets(
            zone_id, sample_list_resource_records_with_alias_result.xml)
        rrsets = self.successResultOf(client.list_resource_record_sets(
            zone_id=zone_id.decode()))
        expected = {
            RRSetKey(
                label=sample_list_resource_records_with_alias_result.normal.label,
                type=sample_list_resource_records_with_alias_result.normal.type,
            ): sample_list_resource_records_with_alias_result.normal,
            RRSetKey(
                label=sample_list_resource_records_with_alias_result.alias.label,
                type=sample_list_resource_records_with_alias_result.alias.type,
            ): sample_list_resource_records_with_alias_result.alias,
        }
        self.assertEqual(rrsets, expected)


    def test_unsupported_records(self):
        """
        If there are resource record sets of unsupported type in the response,
        they are dropped.
        """
        zone_id = b"ABCDEF1234"
        crazy_xml = sample_list_resource_records_with_alias_result.xml.replace(
            b"ResourceRecords>", b"XXResourceRecords>",
        ).replace(
            b"AliasTarget>", b"XXAliasTarget>"
        )
        client = self._client_for_rrsets(zone_id, crazy_xml)
        rrsets = self.successResultOf(client.list_resource_record_sets(
            zone_id=zone_id.decode()))
        expected = {}
        self.assertEqual(rrsets, expected)



class ChangeResourceRecordSetsTestCase(TestCase):
    """
    Tests for C{change_resource_record_sets}.
    """
    def test_error_changes(self):
        duplicate_resource = POSTableData(
            sample_create_resource_record_sets_error_result.xml,
            "text/xml",
            BAD_REQUEST,
        )
        zone_id = "1234ABCDEF"
        agent = RequestTraversalAgent(static_resource({
            b"2013-04-01": {
                b"hostedzone": {
                    zone_id.encode("ascii"): {
                        b"rrset": duplicate_resource,
                    },
                },
            },
        }))
        aws = AWSServiceRegion(access_key="abc", secret_key="def")
        client = get_route53_client(agent, aws, uncooperator())
        err = self.failureResultOf(client.change_resource_record_sets(
            zone_id=zone_id,
            changes=[create_rrset(sample_create_resource_record_sets_error_result.rrset)],
        ), Route53Error)

        expected =  {
            'Code': 'InvalidChangeBatch',
            'Message': "[Tried to create resource record set [name='duplicate.example.invalid.', type='CNAME'] but it already exists]",
            'Type': 'Sender',
        }
        self.assertEqual(err.value.errors, [expected])


    def test_some_changes(self):
        change_resource = POSTableData(
            sample_change_resource_record_sets_result.xml,
            "text/xml",
        )
        zone_id = "ABCDEF1234"
        agent = RequestTraversalAgent(static_resource({
            b"2013-04-01": {
                b"hostedzone": {
                    zone_id.encode("ascii"): {
                        b"rrset": change_resource,
                    }
                },
            },
        }))
        aws = AWSServiceRegion(access_key="abc", secret_key="def")
        client = get_route53_client(agent, aws, uncooperator())
        self.successResultOf(client.change_resource_record_sets(
            zone_id=zone_id,
            changes=[
                create_rrset(sample_change_resource_record_sets_result.rrset),
                delete_rrset(sample_change_resource_record_sets_result.rrset),
                upsert_rrset(sample_change_resource_record_sets_result.rrset),
            ],
        ))
        # Ack, what a pathetic assertion.
        change_template = "<Change><Action>{action}</Action><ResourceRecordSet><Name>example.invalid.</Name><Type>NS</Type><TTL>86400</TTL><ResourceRecords><ResourceRecord><Value>ns1.example.invalid.</Value></ResourceRecord><ResourceRecord><Value>ns2.example.invalid.</Value></ResourceRecord></ResourceRecords></ResourceRecordSet></Change>"
        changes = [
            change_template.format(action="CREATE"),
            change_template.format(action="DELETE"),
            change_template.format(action="UPSERT"),
        ]
        expected = """\
<?xml version="1.0" encoding="UTF-8"?>
<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ChangeBatch><Changes>{changes}</Changes></ChangeBatch></ChangeResourceRecordSetsRequest>""".format(changes="".join(changes)).encode("utf-8")
        self.assertEqual((expected,), change_resource.posted)



def get_live_client(case):
    return get_live_service(case).get_route53_client()


class LiveRoute53TestCase(route53_integration_tests(get_live_client)):
    """
    Tests for the real Route53 implementation against AWS itself.
    """
