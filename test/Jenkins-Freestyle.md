## Jenkins execute shell example

## Prerequisites:

* Create freestyle Jenkins job
* Built `Reapsaw` container
* Update next parameters in script:
```js
    CX_PROJECT  # Project name in Checkmarx
    CX_URL      # Checkmarx (e.g. https://checkmarx.com)
    CX_USER     # username
    CX_PASSWORD # password
    RP_URL      # Report Portal 
    RP_TOKEN    # API token
```

Information how to do it can be found by the links below:
* https://wiki.jenkins.io/display/JENKINS/Credentials+Binding+Plugin



Please find below example how to get `Reapsaw` results against `https://github.com/appsecco/dvna` in Jenkins:
```shell
# Make sure you already build container `docker build -t sast .`
# The TOOLS is a list of scanning tools
# will be cx by default, Snyk can be used as a dependency scanner. In order to use it, please set SNYK_TOKEN
TOOLS="cx"

# The CX_USER is a name of application user for automated scns
CX_URL="PLEASE_PASTE_CX_URL"
CX_USER="PLEASE_PASTE_CX_USERID"
CX_PASSWORD="PLEASE_PASTE_CX_PASSWORD"

# The CX_PATH contain paths to be excluded from Checkmarx scan (Coma separated list e.g. code,some/other/code)
CX_PATH="docs,terraform,tests"

RP_URL="PLEASE_PASTE_REPORT_PORTAL_URL"
# The RP_TOKEN used to send results in aggregation storage
RP_TOKEN="PLEASE_PASTE_RP_TOKEN"

# PRJ is a Checkmarx project name
PRJ="demo_sast"

# Clear Jenkins job WORKSPACE
rm -rf $WORKSPACE/*

# Clone repository
mkdir code

# clone code base in `code` folder
git clone https://github.com/appsecco/dvna $WORKSPACE/code -b master

# create folder for reports
mkdir -p code/reports

# Stop container if in run state
if docker stop $PRJ ; then
  echo 'stopping sast container'
else
    echo 'starting sast..'
fi

# Remove container if in run state
if docker rm $PRJ ; then
  echo 'removing sast container'
else
    echo 'starting sast..'
fi

docker run -d -t --entrypoint=cat \
    -e TASKS=$TOOLS \
    -e CX_URL=$CX_URL \
    -e CX_USER=$CX_USER \
    -e CX_PASSWORD=$CX_PASSWORD \
    -e CX_PROJECT=$PRJ \
    -e RP_PROJECT=$PRJ \
    -e cx_path="$CX_PATH" \
    --name $PRJ sast:latest

# copy code base from workspace inside container
docker cp "$WORKSPACE/code/." $PRJ:/code

# print working dir files for the scan inside container
docker exec -t demo_sast ls -la

# start scan
docker exec -t demo_sast scan

# generate reports locally - without sending in RP
docker exec -t demo_sast generate_reports -r=false


# review results
docker exec -t demo_sast ls reports

# review results : json
docker exec -t demo_sast cat reports/json_report.json

# generate html report
docker exec -i demo_sast junit2html /code/reports/junit_report.xml /code/reports/report.html

# send results in ReportPortal
docker exec -t -e REPORT_PORTAL_URL=$RP_URL -e RP_TOKEN=$RP_TOKEN -e RP_PROJECT=$PRJ -e RP_LAUNCH_NAME=$PRJ demo_sast generate_reports

# stop sast container
docker stop $PRJ

# remove sast container
docker rm $PRJ

```