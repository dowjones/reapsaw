## Overview
Reapsaw automation solution was build to run scans and provide developers consolidated report with friendly recommendations on fixes.

* Vulnerabilities reported to build pipeline, ReportPortal and Jira,
* Easy to integrate within build pipeline;
* BugBar functionality.

## Prerequisites:

* Installed [Docker v18.09+](https://docs.docker.com/docker-for-mac/install/)
* You need to build and package the project for test it as for deploy
* Checkmarx or Snyk API token

Instructions about how to setup Checkmarx and Snyk can be found on the right hand menu.

Pull the code of the project for scanning from the CSV:
```bash
$ git clone <git_repo_url>
```

For the demo purposes we will use one of the [OWASP repositories](https://github.com/OWASP/NodeGoat):

```bash
$ git clone https://github.com/OWASP/NodeGoat
$ cd NodeGoat
$ npm install # exit code 0
```
> Make sure you're got no errors after the build step command.

## Install Reapsaw

This will let you run `Reapsaw` on your local machine.

> Ensure you have Checkmarx or Snyk token in place.


1. Clone [`Reapsaw`](https://github.com/dowjones/sast):
```bash
$ git clone https://github.com/dowjones/sast
```
Now, look in your project folder and see that there is a newly created `sast` folder with `Reapsaw` source code.

2. Build image:
```bash
$ cd sast
$ docker build -t sast:latest .
....
 ---> b995eb5d7d1a
Successfully built b995eb5d7d1a
Successfully tagged sast:latest
```
Here `-t sast:latest` is the name and tag of image.

The resulting image will be tagged as `sast:latest`:

3. Run container:
```js
$ docker run --name sast --rm \
     -v <path_to_folder_with_source_code>:/code \
     -e TASKS=<tasks> \
     -e CX_PROJECT=<project_name> \
     -e CX_URL=<cx_url> \
     -e CX_USER=<cx_user> \
     -e CX_PASSWORD=<cx_user_pwd> \
     -e SNYK_TOKEN=<snyk_token> \
      sast:latest
```
There are a few different run options:
```js
    -e TASKS       # Available option: "cx","snyk","cx,snyk"
    -e TASKS='cx'  # e.g You want Checkmarx scan to happen:
    -e CX_PROJECT  # Project name in Checkmarx
    -e CX_URL      # Checkmarx (e.g. https://checkmarx.com)
    -e CX_USER     # username
    -e CX_PASSWORD # password
    -e SNYK_TOKEN  # Snyk API token
```

> If you want to Checkmarx and Snyk to happen together:
```js
$ docker run --name sast --rm \
 -v /Users/demo/NodeGoat:/code \
 -e TASKS="cx,snyk" \
 -e CX_PROJECT="demo_sast" \
 -e CX_URL="https://mycheckmarx.com" \
 -e CX_USER="my_user_id" \
 -e CX_PASSWORD="my_user_pwd" \
 -e SNYK_TOKEN="my-snyk-api-token" \
  sast:latest
```

`Reapsaw` will start scanning source code and creates reports in `reports/` folder.
Container will be automatically deleted when run finished.

Reports are available on your host machine in `reports` folder:

```bash
$ cat <path_to_folder_with_source_code>/reports/json_report.json
```

> If you want only Snyk to happen
```js
$ docker run --name sast --rm \
      -e TASKS="snyk" \
      -v <path_to_folder_with_source_code>:/code \
      -e SNYK_TOKEN=<SNYK_TOKEN> \
      sast:latest
```


## Reports:
* JSON report
```python
[
 {
    "Issue Name": <string>,       # Vulnerability name e.g "SQL Injection"
    "Issue Tool": <string>,       # Tool name e.g "Checkmarx"
    "Issue Priority": <string>,   # "Major" by default
    "Issue Severity": <string>,   # According to BugBar configuration
    "Description": <string>,      # Used for Jira, e.g The software does not sufficiently validate ...
    "Recommendations": <string>,  # Recommendation from tool or BugBar e.g Upgrade `marked` to version 0.6.2 or higher
    "Instances": <string>,        # Location of finding/module e.g "File routes/login.js"
    "Jira Name": <string>,        # Title of the corresponding ticket created in Jira. Get's from BugBar
    "Links": <string>,            # Link to the "Checkmarx Viewer"
    "Snippet": <string>,          # Code snippet if applicable: "var url_params = url.parse(req.url, true).query;"
    "top_level_module": <string>, # Name of the top level module to update e.g "marked" ,
     ....
  }
]
```

<details><summary>Example</summary>
<p>

#### JSON report

```json
[
  {
    "Issue Name": "Cross-site Scripting (XSS).app/routes/contributions.js",
    "Issue Tool": "Checkmarx",
    "Steps To Reproduce": "",
    "Issue Priority": "Major",
    "Issue Severity": "High",
    "Issue Confidence": "Certain",
    "CWE": "[CWE-79|https://cwe.mitre.org/data/definitions/79]",
    "CVE": "",
    "Overview": "",
    "Recommendations": "# Validate all input, regardless of source. Validation should be based on a whitelist: accept only data fitting a specified structure, rather than reject bad patterns. Check for:\n#* Data type\n#* Size\n#* Range\n#* Format\n#* Expected values\n# Fully encode all dynamic data before embedding it in output.\n# Encoding should be context-sensitive. For example:\n#* HTML encoding for HTML content\n#* HTML Attribute encoding for data output to attribute values\n#* JavaScript encoding for server-generated JavaScript.\n# Consider using either the ESAPI encoding library, or the built-in platform functions. For earlier versions of ASP.NET, consider using the AntiXSS library.\n# In the Content-Type HTTP response header, explicitly define character encoding (charset) for the entire page.\n# Set the httpOnly flag on the session cookie, to prevent XSS exploits from stealing the cookie.\n\n",
    "References": "Line 34 in file [app/routes/contributions.js|https://checkmarx.com/CxWebClient/ViewerMain.aspx?scanid=1041725&projectid=3133&pathid=6]",
    "Paths": "",
    "URLs": "",
    "error_string": "Cross-site Scripting (XSS) 79\napp/routes/contributions.js",
    "Description": " The software does not sufficiently validate, filter, escape, and/or encode user-controllable input before it is placed in output that is used as a web page that is served to other users.\n    GROUP: JavaScript_Server_Side_Vulnerabilities\n    CATEGORY: A7-Cross-Site Scripting (XSS)\n    *Code*:\n    ``` var userId = req.session.userId; ```",
    "Instances": "File app/routes/contributions.js",
    "Attachments": [],
    "Tags": [
        {
            "TestType": "sast"
        },
        {
            "Provider": "Reapsaw"
        },
        {
            "Tool": "Checkmarx"
        }
    ],
    "Jira Name": "Cross-site Scripting (XSS)",
    "Repo": "",
    "Links": "https://checkmarx.com/CxWebClient/ViewerMain.aspx?scanid=1041725&projectid=3133&pathid=6",
    "Snippet": "var userId = req.session.userId;",
    "Jira Description": "h3.*Instances:*\nFile app/routes/contributions.js\nh3.*Recommendations:*\n\n# Validate all input, regardless of source. Validation should be based on a whitelist: accept only data fitting a specified structure, rather than reject bad patterns. Check for:\n#* Data type\n#* Size\n#* Range\n#* Format\n#* Expected values\n# Fully encode all dynamic data before embedding it in output.\n# Encoding should be context-sensitive. For example:\n#* HTML encoding for HTML content\n#* HTML Attribute encoding for data output to attribute values\n#* JavaScript encoding for server-generated JavaScript.\n# Consider using either the ESAPI encoding library, or the built-in platform functions. For earlier versions of ASP.NET, consider using the AntiXSS library.\n# In the Content-Type HTTP response header, explicitly define character encoding (charset) for the entire page.\n# Set the httpOnly flag on the session cookie, to prevent XSS exploits from stealing the cookie.\n\n\nh3.*Overview:*\n{panel:title=Cross-site Scripting (XSS)}*Description*: \nThe software does not sufficiently validate, filter, escape, and/or encode user-controllable input before it is placed in output that is used as a web page that is served to other users.\n    GROUP: JavaScript_Server_Side_Vulnerabilities\n    CATEGORY: A7-Cross-Site Scripting (XSS)\n    *Code*:\n    ``` var userId = req.session.userId; ```\n\n*References*: \nLine 10 in file [app/routes/contributions.js|https://checkmarx.com/CxWebClient/ViewerMain.aspx?scanid=1041725&projectid=3133&pathid=5]\n\n{panel}\n{panel:title=Cross-site Scripting (XSS)}*Description*: \nThe software does not sufficiently validate, filter, escape, and/or encode user-controllable input before it is placed in output that is used as a web page that is served to other users.\n    GROUP: JavaScript_Server_Side_Vulnerabilities\n    CATEGORY: A7-Cross-Site Scripting (XSS)\n    *Code*:\n    ``` var userId = req.session.userId; ```\n\n*References*: \nLine 34 in file [app/routes/contributions.js|https://checkmarx.com/CxWebClient/ViewerMain.aspx?scanid=1041725&projectid=3133&pathid=6]\n\n{panel}\n"
  },
  {
    "Issue Name": "Regular Expression Denial of Service (ReDoS).marked",
    "Issue Tool": "Snyk",
    "Steps To Reproduce": "",
    "Issue Priority": "Major",
    "Issue Severity": "High",
    "Issue Confidence": "Certain",
    "CWE": "CWE-185",
    "CVE": "",
    "Overview": "",
    "Recommendations": "Upgrade `marked` to version 0.6.2 or higher",
    "References": "\r\n- [GitHub PR](https://github.com/markedjs/marked/pull/1083)\r\n- [GitHub Commit](https://github.com/markedjs/marked/pull/1083)",
    "Paths": "owasp-nodejs-goat>marked@0.3.9",
    "URLs": "",
    "error_string": "marked",
    "Description": "*Vulnerable Package:* marked\n*Current Version:* 0.3.9\n*Vulnerable Version(s):* <0.3.18\n \n *Remediation:*\r\nUpgrade marked to version 0.3.17 or higher\r\n\r\n\n  Overview\r\n[`marked`](https://www.npmjs.com/package/marked) is a markdown parser built for speed\r\n\r\nAffected versions of this package are vulnerable to Regular Expression Denial of Service (ReDoS) attacks. This can cause an impact of about 10 seconds matching time for data 150 characters long.\r\n\r\n\n ",
    "Instances": "marked",
    "Attachments": [],
    "Tags": [
      {
        "TestType": "sast"
      },
      {
        "Provider": "Reapsaw"
      },
      {
        "Tool": "Snyk"
      }
    ],
    "Jira Name": "Vulnerable Software",
    "Repo": "",
    "top_level_module": "marked",
    "upgrades": [
      false,
      "marked@0.3.18"
    ],
    "language": "js",
    "RP Defect Type": "Product Bug"
  }
]
```
</p>
</details>

<details><summary>JUNIT report</summary>
<p>


```xml
<testsuites disabled="0" errors="10" failures="0" tests="10" time="0.0">
    <testsuite disabled="0" errors="10" failures="0" name="SAST Scan" skipped="0" tests="10" time="0">
        <testcase classname="Certain" name="Cross-site Scripting (XSS).app/routes/contributions.js">
            <error message="Cross-site Scripting (XSS) 79&#10;app/routes/contributions.js&#10;&#10;h3.*Instances:*&#10;File app/routes/contributions.js&#10;h3.*Recommendations:*&#10;&#10;# Validate all input, regardless of source. Validation should be based on a whitelist: accept only data fitting a specified structure, rather than reject bad patterns. Check for:&#10;#* Data type&#10;#* Size&#10;#* Range&#10;#* Format&#10;#* Expected values&#10;# Fully encode all dynamic data before embedding it in output.&#10;# Encoding should be context-sensitive. For example:&#10;#* HTML encoding for HTML content&#10;#* HTML Attribute encoding for data output to attribute values&#10;#* JavaScript encoding for server-generated JavaScript.&#10;# Consider using either the ESAPI encoding library, or the built-in platform functions. For earlier versions of ASP.NET, consider using the AntiXSS library.&#10;# In the Content-Type HTTP response header, explicitly define character encoding (charset) for the entire page.&#10;# Set the httpOnly flag on the session cookie, to prevent XSS exploits from stealing the cookie.&#10;&#10;&#10;h3.*Overview:*&#10;{panel:title=Cross-site Scripting (XSS)}*Description*: &#10;The software does not sufficiently validate, filter, escape, and/or encode user-controllable input before it is placed in output that is used as a web page that is served to other users.&#10;    GROUP: JavaScript_Server_Side_Vulnerabilities&#10;    CATEGORY: A7-Cross-Site Scripting (XSS)&#10;    *Code*:&#10;    ``` var userId = req.session.userId; ```&#10;&#10;*References*: &#10;Line 10 in file [app/routes/contributions.js|https://checkmarx.com/CxWebClient/ViewerMain.aspx?scanid=1041725&amp;projectid=3133&amp;pathid=5]&#10;&#10;{panel}&#10;{panel:title=Cross-site Scripting (XSS)}*Description*: &#10;The software does not sufficiently validate, filter, escape, and/or encode user-controllable input before it is placed in output that is used as a web page that is served to other users.&#10;    GROUP: JavaScript_Server_Side_Vulnerabilities&#10;    CATEGORY: A7-Cross-Site Scripting (XSS)&#10;    *Code*:&#10;    ``` var userId = req.session.userId; ```&#10;&#10;*References*: &#10;Line 34 in file [app/routes/contributions.js|https://checkmarx.com/CxWebClient/ViewerMain.aspx?scanid=1041725&amp;projectid=3133&amp;pathid=6]&#10;&#10;{panel}&#10;&#10;&#10;"
                   type="High"/>
        </testcase>

        <testcase classname="Certain" name="Vulnerable Software Version.marked">
            <error message="marked&#10;&#10;h3.*Instances:*&#10;marked&#10;h3.*Recommendations:*&#10;&#10;Upgrade `marked` to version 0.6.2 or higher&#10;h3.*Overview:*&#10;{panel:title=Regular Expression Denial of Service (ReDoS)}*Description*: &#10;*Vulnerable Package:* marked&#10;*Current Version:* 0.3.9&#10;*Vulnerable Version(s):* &lt;0.3.18&#10; &#10; *Remediation:*&#10;Upgrade marked to version 0.3.17 or higher&#10;&#10;&#10;  Overview&#10;[`marked`](https://www.npmjs.com/package/marked) is a markdown parser built for speed&#10;&#10;Affected versions of this package are vulnerable to Regular Expression Denial of Service (ReDoS) attacks. This can cause an impact of about 10 seconds matching time for data 150 characters long.&#10;&#10;*References*: &#10;- [GitHub PR](https://github.com/markedjs/marked/pull/1083)&#10;- [GitHub Commit](https://github.com/markedjs/marked/pull/1083)&#10;&#10;*Paths*: &#10;owasp-nodejs-goat&gt;marked@0.3.9&#10;&#10;{panel}&#10;{panel:title=Regular Expression Denial of Service (ReDoS)}*Description*: &#10;*Vulnerable Package:* marked&#10;*Current Version:* 0.3.9&#10;*Vulnerable Version(s):* &lt;0.4.0&#10; &#10; *Remediation:*&#10;&#10;Upgrade `marked` to version 0.4.0 or higher.&#10;&#10;&#10;&#10;  Overview&#10;&#10;[marked](https://marked.js.org/) is a low-level compiler for parsing markdown without caching or blocking for long periods of time.&#10;&#10;&#10;Affected versions of this package are vulnerable to Regular Expression Denial of Service (ReDoS).&#10;A  Denial of Service condition could be triggered through exploitation of the `heading` regex.&#10;&#10;*References*: &#10;- [GitHub Commit](https://github.com/markedjs/marked/commit/09afabf69c6d0c919c03443f47bdfe476566105d)&#10;&#10;- [GitHub PR](https://github.com/markedjs/marked/pull/1224)&#10;&#10;*Paths*: &#10;owasp-nodejs-goat&gt;marked@0.3.9&#10;&#10;{panel}&#10;{panel:title=Regular Expression Denial of Service (ReDoS)}*Description*: &#10;*Vulnerable Package:* marked&#10;*Current Version:* 0.3.9&#10;*Vulnerable Version(s):* &gt;=0.1.3 &lt;0.6.2&#10; &#10; *Remediation:*&#10;&#10;Upgrade `marked` to version 0.6.2 or higher.&#10;&#10;&#10;&#10;  Overview&#10;&#10;[marked](https://marked.js.org/) is a low-level compiler for parsing markdown without caching or blocking for long periods of time.&#10;&#10;&#10;Affected versions of this package are vulnerable to Regular Expression Denial of Service (ReDoS).&#10;The `inline.text regex` may take quadratic time to scan for potential email addresses starting at every point.&#10;&#10;*References*: &#10;- [GitHub Commit](https://github.com/markedjs/marked/pull/1460/commits/be27472a8169dda7875330939f8115ab677cdc07)&#10;&#10;- [GitHub Commit Introducing the Vuln](https://github.com/markedjs/marked/commit/00f1f7a23916ef27186d0904635aa3509af63d47)&#10;&#10;- [GitHub PR](https://github.com/markedjs/marked/pull/1460)&#10;&#10;*Paths*: &#10;owasp-nodejs-goat&gt;marked@0.3.9&#10;&#10;{panel}&#10;&#10;&#10;"
                   type="High"/>
        </testcase>

    </testsuite>
</testsuites>
```
</p>
</details>

## Other options
1. Run multiple tools:
```js
$ docker exec -t sast scan
```
  * to run only Checkmarx:

```js
$ docker exec -t -e TASKS=cx sast scan
```

2. Generating reports:

```js
$ docker exec -it sast generate_reports -r false
```
3. Convert Report into HTML:

```js
$ docker exec -it sast junit2html /code/reports/junit_report.xml /code/reports/report.html
```
4. HTML report in Browser:

```js
$ open <path_to_folder_with_source_code>/reports/report.html

```

<details><summary>Example</summary>
<p>

#### HTML report
![HTML](https://github.com/dowjones/sast/blob/develop/docs/html_report.png)
</p>
</details>


5.  Push reports to ReportPortal :

> If want to send results in Report Portal you should add next environment variables :
```js
    -e REPORT_PORTAL_URL  #  Report Portal (e.g. http://reportportal.io)
    -e RP_TOKEN           #  You can get UUID user profile page in the Report Portal.
    -e RP_PROJECT         #  Project name in Report Portal
```
Find Report Portal configuration by the link:

```js
$ docker exec -it \
     -e RP_PROJECT="demo_data" \
     -e REPORT_PORTAL_URL="https://reportportal.io" \
     -e RP_TOKEN="API-TOKEN" \
      sast generate_reports
```


6. Push vulnerabilities to JIRA
> Make sure you're have a connection to Jira.

* Set env variables with JIRA parameters:
```js
   -e JIRA_HOST   # URL to JIRA
   -e JIRA_USR    # user name
   -e JIRA_PWD    # user password
```
```js
$ docker exec -it \
  -e JIRA_HOST='https://jira.example.net' \
  -e JIRA_PWD='password' \
  -e JIRA_USR='username' \
  sast push_to_jira --jira_project TEST --jira_assignee testuser
```
There are different options :

    --jira_project  # Required
    --jira_assignee # Required
    --report_file   # Optional
    --defect_type   # Optional

<details><summary>JIRA Ticket Example</summary>
<p>
<img src="https://github.com/dowjones/sast/blob/json_to_jira/docs/ticket.png" alt="ticket_example">
</p>
</details>