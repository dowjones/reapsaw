# Contributing


Fork, then clone the repo:
```shell
    git clone https://github.com/dowjones/sast.git
```
The easiest way to run test, lint, etc is via docker:

https://docs.docker.com/install/

Make sure the tests pass:
```shell
    docker exec -ti sast_open python -m unittest discover /tmp/sast_controller/tests/
```


### Testing
You will need to create  fork of the library and cover you feature with tests.

Push to your fork and [submit a pull request][pr].

We may suggest some changes, improvements, or alternatives.

If the above requirements are met and communications are clear (good comments, dialog, and [commit messages][commit]) your PR will likely be accepted.

[commit]: http://git-scm.com/book/en/v2/Distributed-Git-Contributing-to-a-Project#Commit-Guidelines