# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.231.6/containers/ubuntu/.devcontainer/base.Dockerfile

# [Choice] Ubuntu version (use hirsuite or bionic on local arm64/Apple Silicon): hirsute, focal, bionic
ARG VARIANT="hirsute"
FROM mcr.microsoft.com/vscode/devcontainers/base:0-${VARIANT}

# [Optional] Uncomment this section to install additional OS packages.
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends vim g++ cmake clang acl dbus \
    kbd ed efibootmgr systemd kmod netcat-openbsd ntfs-3g inetutils-ping \
    libelf-dev python3-pip python3-psutil libc6-dbg python3-setuptools make

USER vscode
RUN sudo -H pip3 install wheel lit
