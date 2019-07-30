## Failed to establish connection:

```
[Errno -3] Temporary failure in name resolution':
```

If you have network connection on the host machine but no internet inside docker container this means you should change network interface for docker run command.

### Resolution:
Add `--network host` in run docker command:

```js
docker run --network host --name sast --rm -d \
    -e TASKS=<tasks>  \
    -v <path_to_folder_with_project_after_build>:/code \
    -e CX_PROJECT=<project_name> \
    -e SNYK_TOKEN=<snyk_token> \
    -e CX_USER=<cx_user> \
    -e CX_PASSWORD=<cx_pwd> sast:latest

```

## Checkmarx error:

2019-05-23 10:33:00,905 - sast_controller.drivers.cx.Checkmarx - CRITICAL - Invalid connection

### Resolution:
1.  Double check CX_USER and PASSWORD parameters in script
2.  Verify that manually you are able to login in Checkmarx