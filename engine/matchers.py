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
    patterns = matcher.get("pattern", [])
    condition = matcher.get("condition", "or").lower()

    if not patterns or not isinstance(patterns, list):
        return False
    
    pool_of_response_text = response.text
    if condition == "and":
        return all(bool(re.search(pattern, pool_of_response_text)) for pattern in patterns)
    elif condition == "or":
        return any(bool(re.search(pattern, pool_of_response_text)) for pattern in patterns)

def word_match(response: Response, matcher: Dict[str, Any]) -> bool:
    """ 
    Checks if the response body contains the specified words.
    """
    words_to_search = matcher.get("words", [])
    condition = matcher.get("condition", "or").lower()

    # Validate that `words_to_search` contains strings
    words_to_search = [str(word) for word in words_to_search if isinstance(word, (str, int, float))]

    # Return False if no valid words are available
    if not words_to_search:
        return False

    pool_of_response_text = response.text

    # Check based on the specified condition
    if condition == "and":
        return all(word in pool_of_response_text for word in words_to_search)
    elif condition == "or":
        return any(word in pool_of_response_text for word in words_to_search)
    else:
        return False  # Default case if an unknown condition is provided


def status_match(response: Response, matcher: Dict[str, Any]) -> bool:
    """
    Checks if the response status code is in the expected list.
    """
    statuses = matcher.get("status", [])
    return response.status_code in statuses


