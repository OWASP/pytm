# Contributing

Below you will find a collection of guidelines for submitting issues as well as contributing code to the PyTM repository.
Please read those before starting an issue or a pull request.

## Issues

Specific PyTM design and development issues, bugs, and feature requests are maintained by GitHub Issues.

*Please do not post installation, build, usage, or modeling questions, or other requests for help to Issues.*
Use the [PyTM-users list](https://groups.google.com/forum/#!forum/pytm-users) instead.
This helps developers maintain a clear, uncluttered, and efficient view of the state of PyTM.
See the chapter [PyTM-users](#PyTM-users) below for guidance on posting to the users list.

When reporting an issue, it's most helpful to provide the following information, where applicable:
* How does the problem look like and what steps reproduce it?
* Can you reproduce it using the latest [master](https://github.com/izar/pytm/tree/master)?
* What is your running environment? In particular:
	* OS,
	* Python version,
	* Dot or PlantUML version, if relevant,
	* Your model file, if possible.
* **What have you already tried** to solve the problem? How did it fail? Are there any other issues related to yours?
* If the bug is a crash, provide the backtrace (usually printed by PyTM).

If only a small portion of the code/log is relevant to your issue, you may paste it directly into the post, preferably using Markdown syntax for code block: triple backtick ( \`\`\` ) to open/close a block.
In other cases (multiple files, or long files), please **attach** them to the post - this greatly improves readability.

If the problem arises during a complex operation (e.g. large model using PyTM), please reduce the example to the minimal size that still causes the error.
Also, minimize influence of external modules, data etc. - this way it will be easier for others to understand and reproduce your issue, and eventually help you.
Sometimes you will find the root cause yourself in the process.

Try to give your issue a title that is succinct and specific. The devs will rename issues as needed to keep track of them.

To execute the test suite, from the root of the repo run `make test`. To control what tests to run, use `python3 -m unittest -v tests/<test_name>`.

To regenerate test fixtures for `json.dumps` and report tests add a `print(output)` statement in the test and run `make test 2>/dev/null > tests/output.json` or  `make test 2>/dev/null > tests/output.md`.

## PyTM-users

Before you post to the [PyTM-users list](https://groups.google.com/forum/#!forum/pytm-users), make sure you look for existing solutions.

* [GitHub issues](https://github.com/izar/pytm/issues) tracker (some problems have been answered there),

Found a post/issue with your exact problem, but with no answer?
Don't just leave a "me too" message - provide the details of your case.
Problems with more available information are easier to solve and attract good attention.

When posting to the list, make sure you provide as much relevant information as possible - recommendations for an issue report (see above) are a good starting point.

Formatting recommendations hold: paste short logs/code fragments into the post (use fixed-width text for them), **attach** long logs or multiple files.

## Pull Requests

PyTM welcomes all contributions.

Briefly: read commit by commit, a PR should tell a clean, compelling story of _one_ improvement to PyTM. In particular:

* A PR should do one clear thing that obviously improves PyTM, and nothing more. Making many smaller PRs is better than making one large PR; review effort is superlinear in the amount of code involved.
* Similarly, each commit should be a small, atomic change representing one step in development. PRs should be made of many commits where appropriate.
* Please do rewrite PR history to be clean rather than chronological. Within-PR bugfixes, style cleanups, reversions, etc. should be squashed and should not appear in merged PR history.
* Anything nonobvious from the code should be explained in comments, commit messages, or the PR description, as appropriate.

(With many thanks to the Caffe project for their original CONTRIBUTING.md file)
