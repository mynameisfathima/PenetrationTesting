import dns.resolver
import dns.dnssec
import dns.name
import dns.message
import dns.query
import dns.rdatatype

def check_dnssec(domain):
    try:
        # Prepare the query
        domain_name = dns.name.from_text(domain)
        request = dns.message.make_query(domain, dns.rdatatype.DNSKEY, want_dnssec=True)

        # Send query to authoritative DNS server (e.g., Google's public resolver)
        response = dns.query.udp(request, '8.8.8.8', timeout=5)

        # Extract DNSKEY and RRSIG
        answer = response.answer
        dnskey_rrset = None
        rrsig_rrset = None
        for rrset in answer:
            if rrset.rdtype == dns.rdatatype.DNSKEY:
                dnskey_rrset = rrset
            elif rrset.rdtype == dns.rdatatype.RRSIG:
                rrsig_rrset = rrset

        # Check if both records are available
        if dnskey_rrset and rrsig_rrset:
            print(f"[✓] DNSSEC is enabled for {domain}")
            return True
        else:
            print(f"[✗] DNSSEC not properly configured or missing records for {domain}")
            return False

    except Exception as e:
        print(f"[!] Error checking DNSSEC for {domain}: {e}")
        return False

# Test the function
check_dnssec("verisignlabs.com")
