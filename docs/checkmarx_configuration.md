Contact your administrator for getting Checkmarx access. 

>`Reapsaw` creates new project with “Default” preset if no existing

## How to create new project 
Before running the container we recommend to create new project and specify preset in Checkmarx.
1. Create new project and click next: 
![cx1](https://github.com/dowjones/sast/blob/develop/docs/create_cx_prj.png)

2. In "Location" select "Source Control": GIT https://github.com/OWASP/NodeGoat:
![cx2](https://github.com/dowjones/sast/blob/develop/docs/create_cx_prj_3.png)

3. Click finish
![cx2](https://github.com/dowjones/sast/blob/develop/docs/create_cx_prj_1.png)

4. Verify that project created:
![cx3](https://github.com/dowjones/sast/blob/develop/docs/create_cx_prj2.png)

Details can be found in Checkmarx documentation by the links:
* [Create Project](https://checkmarx.atlassian.net/wiki/spaces/KC/pages/589955153/Creating+and+Configuring+a+CxSAST+Project+v8.8.0)
* [Preset Manager](https://checkmarx.atlassian.net/wiki/spaces/KC/pages/49250315/Preset+Manager)
* [Creating and Managing Projects](https://checkmarx.atlassian.net/wiki/spaces/KC/pages/28606543/Creating+and+Managing+Projects).

## Reapsaw parameters:
```js
     CX_URL      # Checkmarx (e.g. https://checkmarx.com)
     CX_USER     # username
     CX_PASSWORD # password
     CX_PROJECT  # project name
```

### [Optional parameters]:
Use next parameter to remove from scan unused folders or files.

```js
     cx_files    # Coma separated list, e.g. cx_files="txt,png,xls"
     cx_path     # Coma separated list  e.g. cx_path="docs/,tests/,some/other/code"
```