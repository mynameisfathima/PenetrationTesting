 # DNS have to be checked separately, as they are not part of the response object.
from pprint import pprint
import re
from typing import Any, Dict, List
from .scanutils import check_dnssec
def dns_matcher(response: dict, matcher:list) -> bool:
    """
    Checks if the response DNS matches the expected DNS.
    """

    record_type = matcher[0].get('type')
    words = matcher[0].get('words', [])
    regexes = matcher[0].get('regex', [])
    condition = matcher[0].get('condition', 'or').lower()
     

    def check_word(value):
        return [w in value for w in words]

    def check_regex(value):
        return [bool(re.search(r, value)) for r in regexes]
    
    results = []

    for r_type, records in response.items():
        if isinstance(records, list):
            for record in records:
                if record_type == 'word':
                    results.extend(check_word(record))
                elif record_type == 'regex':
                    results.extend(check_regex(record))
    
    if condition == 'and':
        print(all(results) if results else False)
    print(any(results) if results else False)