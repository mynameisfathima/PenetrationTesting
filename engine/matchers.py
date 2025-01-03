import re
from typing import Any, Dict, List
from requests import Response


def run_matchers(response: Response, matchers_config: List[Dict[str, Any]]) -> bool:
    """
    Given a list of matchers from a template, checks the response
    to see if any or all matchers pass (the logic can be extended).
    For simplicity, we do an 'all' match logic (all must pass).
    """
    for matcher in matchers_config:
        matcher_type = matcher.get("type")

        if matcher_type == "regex":
            if not regex_match(response, matcher):
                return False
        elif matcher_type == "word":
            if not word_match(response, matcher):
                return False
        elif matcher_type == "status":
            if not status_match(response, matcher):
                return False
        elif matcher_type == "header":
            if not header_search(response, matcher):
                return False
    return True


def header_search(response, matcher):
    headers = dict(response.headers)
    stuff_to_match = matcher['name']
    condition_type = matcher['condition'] # Either Present or Contains
    if condition_type == 'present':
        if stuff_to_match in headers:
            return True
        else:
            return False
    elif condition_type == "contains":
        if stuff_to_match in headers:
            header_to_check = headers[stuff_to_match]
            value = matcher['value']
            if value in header_to_check:
                return True
            else:
                return False
        else:
            return False
    
def regex_match(response: Response, matcher: Dict[str, Any]) -> bool:
    """
    Checks if the response body matches a given regex pattern.
    """
    pattern = matcher.get("pattern")
    if not pattern:
        return False
    return bool(re.search(pattern, response.text))

def word_match(response: Response, matcher: Dict[str, Any]) -> bool:
    """
    Checks if th respose body contains the word
    """
    word_to_search = matcher.get("word")
    if not word_to_search:
        return False
    pool_of_response_text = response.text
    return bool(pool_of_response_text.find(word_to_search) > 0) # returns false if not found, ie, returns -1


def status_match(response: Response, matcher: Dict[str, Any]) -> bool:
    """
    Checks if the response status code is in the expected list.
    """
    statuses = matcher.get("status", [])
    return response.status_code in statuses



