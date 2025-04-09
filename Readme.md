## **PT Toolkit,**

> This outlines all the activities of a drop-in replacment for a pentesting tool, inspired from nuclei.
> This is a hobby project to learn workings of an application and integrate with LLM in the future

---



#### Anatomy of Yaml

```yaml
id: "login page checker"
info:
  name: "See if Login page exist"
  author: "DanBrown47"
  severity: "medium"

requests:

- method: GET
  path:
  - "{{BaseURL}}/login"
- matchers:
  - type: regex
    pattern: "(?i)login"
  - type: status
    status:

    - 200
```

In the above yaml it is expected the application sends a request to baseURL and route login, then it checks if the response hits 200 as well as if the page contains the name "login" which is done by the regex. 

<small>
Test Case 1 
python3 main.py https://google.com templates/http
<small>
---


TODO : DMARC - DNS 
TODO : DKIM - DNS
TODO : Rua - DNS
TODO : ruf  - DNS