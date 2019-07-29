## Jenkins pipelines

You need to add next credentials and tokens in Jenkins:
* sastPassword: Used as Checkmarx user password
* rpToken: Used for writing to ReportPortal
* snykToken: Used as Snyk token

Information how to do it can be found by the links below:

* [Credentials Binding Plugin](https://jenkins.io/doc/pipeline/steps/credentials-binding/)


Please find below Jenkins pipeline example with SAST step :

```bash

node() {
    stage('Checkout') {
        deleteDir()
        // scmUrl string param: link to GitHub repo
        git branch: 'master', url: 'https://github.com/OWASP/NodeGoat'
    }

    stage('SAST') {

        def appName = 'demo_sast'
        def runParams = ""
        def sast_params = [
                PROJECT    : appName,
                CX_URL     : '<cx_url>',
                CX_USER    : '<cx_user>',
                CX_PASSWORD: '<cx_pwd>',
                TASKS      : 'cx,snyk',
                REPORT_PORTAL_URL: '<rp_url>',
                RP_TOKEN   : '<rp_token>',
                SNYK_TOKEN : '<snyk_token>']
        for (param in sast_params) {
            runParams += " -e ${param.key}=\"${param.value}\""
        }
        try {
            sh "mkdir -p reports"
            sh "docker run -td --entrypoint=cat --network host ${runParams} --name ${appName} sast:latest"
            sh "docker cp ${WORKSPACE}/. ${appName}:/code"
            sh "docker exec -t ${appName} scan"
            sh "docker exec -t ${appName} generate_reports"
            sh 'echo "Results:"'
            sh "docker exec -t ${appName} cat reports/json_report.json"
        } catch (e) {
            sh 'echo "Error in SAST scan"'
            sh "echo ${e.getMessage()}"
        } finally{
            sh "docker stop ${appName}"
            sh "docker rm ${appName}"
        }
    }
}
```