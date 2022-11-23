# Copyright (c) 2017 DataDirect Networks, Inc.
# All Rights Reserved.
# Author: lixi@ddn.com
# Added RHEL8 support (asrivastava@tintri.com)
"""
Common library for ESMON
"""
import logging

# Local libs
from installer import utils

RPM_PATTERN_RHEL6 = r"^%s-\d.+(\.el6|).*\.rpm$"
RPM_PATTERN_RHEL7 = r"^%s-\d.+(\.el7|).*\.rpm$"
RPM_PATTERN_RHEL8 = r"^%s-\d.+(\.el8|).*\.rpm$"
PATTERN_PYTHON_LIBRARY = r"^%s-\d+\.\d+\.\d+\.tar\.gz$"

def clone_src_from_git(build_dir, git_url, branch,
                       ssh_identity_file=None):
    """
    Get the soure codes from Git server.
    """
    command = ("rm -fr %s && mkdir -p %s && git init %s" %
               (build_dir, build_dir, build_dir))
    retval = utils.run(command)
    if retval.cr_exit_status != 0:
        logging.error("failed to run command [%s], "
                      "ret = [%d], stdout = [%s], stderr = [%s]",
                      command, retval.cr_exit_status, retval.cr_stdout,
                      retval.cr_stderr)
        return -1

    command = ("cd %s && git config remote.origin.url %s && "
               "GIT_SSH_COMMAND=\"ssh -i /root/.ssh/id_dsa\" "
               "git fetch --tags --progress %s "
               "+refs/heads/*:refs/remotes/origin/* && "
               "git checkout origin/%s -f" %
               (build_dir, git_url, git_url, branch))
    if ssh_identity_file is not None:
        # Git 2.3.0+ has GIT_SSH_COMMAND
        command = ("ssh-agent sh -c 'ssh-add " + ssh_identity_file +
                   " && " + command + "'")

    retval = utils.run(command)
    if retval.cr_exit_status != 0:
        logging.error("failed to run command [%s], "
                      "ret = [%d], stdout = [%s], stderr = [%s]",
                      command, retval.cr_exit_status, retval.cr_stdout,
                      retval.cr_stderr)
        return -1
    return 0

#
# python-requests, PyYAML, python2-filelock, python-slugify, pytz,
# python-dateutil are needed by esmon_install.
#
# python-chardet and python-urllib3 are needed by python-requests.
#
# python-backports-ssl_match_hostname and python-six are needed by
# python-urllib3.
#
# python-ipaddress and python-backports are needed by
# python-backports-ssl_match_hostname.
#
# libyaml is needed by PyYAML.
ES_INSTALL_DEPENDENT_RPMS = ["rsync",
                             "python-chardet",
                             "python-backports",
                             "python-ipaddress",
                             "python-backports-ssl_match_hostname",
                             "python-six",
                             "python-urllib3",
                             "libyaml",
                             "PyYAML",
                             "python-requests",
                             "python-filelock",
                             "python-slugify",
                             "pytz",
                             "python-dateutil"]

# patch is needed to patch /etc/influxdb/influxdb.conf file
# fontconfig and urw-base35-fonts are needed by grafana rpm
# fontpackages-filesystem, bitmap-console-fonts(font(:lang=en)) are
# needed by fontconfig
# xorg-x11-font-utils is needed by urw-base35-fonts
# libXfont is needed by xorg-x11-font-utils
# libfontenc is needed by libXfont
ES_SERVER_DEPENDENT_RPMS = ["rsync", "patch", "fontpackages-filesystem",
                            "bitmap-console-fonts", "fontconfig",
                            "libfontenc", "libXfont",
                            "xorg-x11-font-utils", "urw-base35-fonts"]


# yajl is needed by collectd
# lm_sensors-libs is needed by collectd-sensors
# zeromq3 is needed by collectd-ssh
# openpgm is needed by zeromq3
# libmnl is needed by collectd
ES_CLIENT_DEPENDENT_RPMS = ["rsync", "yajl", "lm_sensors-libs",
                            "openpgm", "zeromq3", "libmnl", "autoconf",
                            "automake", "flex", "bison", "libtool",
                            "pkg-config", "python3-devel"]
