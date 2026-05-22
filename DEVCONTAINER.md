# Devcontainer

The `pytm` devcontainer is an adaption of the
[devcontainer Ubuntu base image](https://github.com/devcontainers/images/tree/main/src/base-ubuntu)
for painless CLI management support via [`brew`](https://brew.sh/).
This enables easy integration into devcontainer based workflows, CLI based instalaltion of additional `brew` packages
as well as common devcontainer features which are based on `apt` packages in a lot of cases.

The devcontainer uses the following [features](https://containers.dev/features):

- [common-utils](https://github.com/devcontainers/features/tree/main/src/common-utils)
- [git](https://github.com/devcontainers/features/tree/main/src/git)
- [homebrew](https://github.com/meaningful-ooo/devcontainer-features/tree/main/src/homebrew)
- some modern tools from [devcontainer-extra/features](https://github.com/devcontainers-extra/features)

## Build a local devcontainer via the CLI

To manage devcontainer via the CLI you can use
[devcontainer cli](https://github.com/devcontainers/cli).

    devcontainer build --workspace-folder .

The first startup takes some time for building the image. Later startups are significantly faster.

## Usage

The most simple, getting started usage scenario is:

    vscode ➜ /workspaces/pytm (devcontainer) $ mkdir -p tm
    vscode ➜ /workspaces/pytm (devcontainer) $ ./tm.py --report docs/basic_template.md | pandoc -f markdown -t html > tm/report.html
    vscode ➜ /workspaces/pytm (devcontainer) $ ./tm.py --dfd | dot -Tpng -o tm/dfd.png
    vscode ➜ /workspaces/pytm (devcontainer) $ ./tm.py --seq | java -Djava.awt.headless=true -jar $PLANTUML_PATH -tpng -pipe > tm/seq.png
