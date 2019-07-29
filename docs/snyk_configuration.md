Snyk helps to find and fix known vulnerabilities in your dependencies, both ad hoc and as part of your CI (Build) system.
> We are using "Snyk CLI" you should `Snyk API token` in order to use it.

## Prerequisites
You can use free version with `Reapsaw` for scanning open source repositories.
Using open source license you can run only `200` scans on private projects.

> Details about Snyk licence can be found by the link [plans](https://snyk.io/plans/)

* Snyk API token
* Internet connection with `snyk.io`

`SNYK_TOKEN` env variable with your Snyk API token and add "snyk" in TASKS environment variable.

`Reapsaw` languages support:
* NodeJs
* Java
* .Net
* Scala

## How to build application code base

### NodeJS Playbook
1. Before scan install application modules:
```shell
npm install
```
2. Add `snyk` in `TASKS` environment variable:
```js
$ docker run --name sast --rm -d \
       -e TASKS="snyk" \
       -v <PATH_TO_FOLDER_WITH_PROJECT_CODE_AFTER_BUILD>:/code \
       -e SNYK_TOKEN=<SNYK_TOKEN> \
       sast:latest
```

3. Report example:

> Note: For the findings from Snyk we are reporting top level dependencies

<details><summary>JSON report</summary>
<p>

```js
[{
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
  }]
```
</p>
</details>

### .NET Playbook

If you are using .Net you should add required params:
* `lang`='dotnet'
* `sln_file`=<PATH_TO_SLN_FILE> # e.g `src/Project.sln`

1. Build application
```bash
$ dotnet restore
```
```js
$ docker run --name sast --rm -d \
        -e TASKS="snyk" \
        -v <PATH_TO_FOLDER_WITH_PROJECT_CODE_AFTER_BUILD>:/code \
        -e lang='dotnet' \
        -e sln_file=<PATH_TO_SLN_FILE> \
        -e SNYK_TOKEN=<SNYK_TOKEN> \
        sast:latest
```



### Java Playbook
1. Build application
```bash
$ mvn build
```
> It should work for Java other build tools if not reach out to us.

2. Run `Reapsaw`
### Scala Playbook
1. Before scan install application modules:
```bash
$ sbt build
```