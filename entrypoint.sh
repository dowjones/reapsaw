#!/bin/bash

create_reports()
{

#	----------------------------------------------------------------
#	Generate consolidated report and send results to Report Portal
#	----------------------------------------------------------------
	RP=false
    if [[ "${REPORT_PORTAL_URL}" && "${RP_TOKEN}" ]]; then
        if [[ "${RP_PROJECT}" || "${PROJECT}" ]]; then
            RP=true
        else
            echo "Please specify RP_PROJECT as environment variable for sending in Report Portal"
            exit 0
        fi

    fi
    generate_reports -r $RP
	exit 0
}

{
    if [[ "${TASKS}" ]]; then
        mkdir -p /code/reports
        if [[ "${TASKS}" == "snyk" ]]; then
            echo "Snyk selected..."
            if [[ "${SNYK_TOKEN}" ]]; then
                scan
                create_reports
            else
                echo "Please specify SNYK_TOKEN as environment variable."
            fi
        elif [[ "${TASKS}" == *"cx" ]] || [[ "${TASKS}" == *"cx_commit" ]] || [[ "${TASKS}" == "cx"* ]]; then
           if [[ "${CX_USER}" ]] && [[ "${CX_PASSWORD}" ]] && [[ "${CX_URL}" ]]; then
                if [[ "${TASKS}" == *"snyk"* ]]; then
                    if [[ "${SNYK_TOKEN}" ]]; then
                        echo "Checkmarx and Snyk tools selected..."
                        scan
                        create_reports
                    else
                        echo "Please specify SNYK_TOKEN as environment variable."
                    fi
                else
                    echo "Checkmarx selected..."
                    scan
                    create_reports
                fi
            else
                echo "Please specify next environment variables to run Checkmarx: 'CX_USER', 'CX_PASSWORD' and 'CX_URL'."
            fi
        else
           echo "Unsupported TASKS value: ${TASKS}"
           echo "Possible options: \"cx,snyk\", \"cx\",\"snyk\""
        fi
    else
        echo "Please set TASKS environment variable"
    fi

} || {
    echo "Something went wrong. Please verify docker run command."
    exit 0
}
