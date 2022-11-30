# Copyright (c) 2022 DataDirect Networks, Inc.
# All Rights Reserved.
# Author: asrivastava@tintri.com
"""
Library for building Collectd
"""
# pylint: disable=too-many-lines
import sys
import logging
import os
import re

# Local libs
from installer import utils
from installer import time_util
from installer import ssh_host
from installer import common

COLLECTD_STRING = "collectd"
COLLECT_GIT_STRING = COLLECTD_STRING + ".git"
RPM_STRING = "RPMS"
COLLECTD_RPM_NAMES = ["collectd", "collectd-disk", "collectd-filedata",
                      "collectd-ime", "collectd-sensors", "libcollectdclient"]


def collectd_build(workspace, build_host, base_path,
                   collectd_git_path,
                   collectd_tarball_name, distro_number):
    """
    Build Collectd on a host
    """
    # pylint: disable=too-many-return-statements,too-many-arguments
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    host_collectd_git_dir = ("%s/%s" % (workspace, COLLECT_GIT_STRING))
    host_collectd_rpm_dir = ("%s/%s" % (host_collectd_git_dir, RPM_STRING))
    local_rpm_dir = base_path

    ret = build_host.sh_send_file(collectd_git_path, workspace)
    if ret:
        logging.error("failed to send file [%s] on local host to "
                      "directory [%s] on host [%s]",
                      collectd_git_path, workspace,
                      build_host.sh_hostname)
        return -1

    command = ("cd %s && chmod u+x version-gen.sh" %
               (host_collectd_git_dir))
    retval = build_host.sh_run(command)
    if retval.cr_exit_status:
        logging.error("failed to run command [%s] on host [%s], "
                      "ret = [%d], stdout = [%s], stderr = [%s]",
                      command,
                      build_host.sh_hostname,
                      retval.cr_exit_status,
                      retval.cr_stdout,
                      retval.cr_stderr)
        return -1

    command = ("cd %s && mkdir -p libltdl/config && sh ./build.sh && "
               "./configure && "
               "make dist-bzip2" %
               (host_collectd_git_dir))
    retval = build_host.sh_run(command)
    if retval.cr_exit_status:
        logging.error("failed to run command [%s] on host [%s], "
                      "ret = [%d], stdout = [%s], stderr = [%s]",
                      command,
                      build_host.sh_hostname,
                      retval.cr_exit_status,
                      retval.cr_stdout,
                      retval.cr_stderr)
        return -1

    command = ("cd %s && ls collectd-*.tar.bz2" %
               (host_collectd_git_dir))
    retval = build_host.sh_run(command)
    if retval.cr_exit_status:
        logging.error("failed to run command [%s] on host [%s], "
                      "ret = [%d], stdout = [%s], stderr = [%s]",
                      command,
                      build_host.sh_hostname,
                      retval.cr_exit_status,
                      retval.cr_stdout,
                      retval.cr_stderr)
        return -1

    collectd_tarballs = retval.cr_stdout.split()
    if len(collectd_tarballs) != 1:
        logging.error("unexpected output of Collectd tarball: [%s]",
                      retval.cr_stdout)
        return -1

    collectd_tarball_fname = collectd_tarballs[0]

    if (not collectd_tarball_fname.endswith(".tar.bz2") or
            len(collectd_tarball_fname) <= 8):
        logging.error("unexpected Collectd tarball fname: [%s]",
                      collectd_tarball_fname)
        return -1

    collectd_tarball_current_name = collectd_tarball_fname[:-8]

    command = ("cd %s && tar jxf %s && "
               "mv %s %s && tar cjf %s.tar.bz2 %s" %
               (host_collectd_git_dir, collectd_tarball_fname,
                collectd_tarball_current_name, collectd_tarball_name,
                collectd_tarball_name, collectd_tarball_name))
    retval = build_host.sh_run(command)
    if retval.cr_exit_status:
        logging.error("failed to run command [%s] on host [%s], "
                      "ret = [%d], stdout = [%s], stderr = [%s]",
                      command,
                      build_host.sh_hostname,
                      retval.cr_exit_status,
                      retval.cr_stdout,
                      retval.cr_stderr)
        return -1

    command = ("cd %s && mkdir {BUILD,RPMS,SOURCES,SRPMS} && "
               "mv %s.tar.bz2 SOURCES" %
               (host_collectd_git_dir, collectd_tarball_name))
    retval = build_host.sh_run(command)
    if retval.cr_exit_status:
        logging.error("failed to run command [%s] on host [%s], "
                      "ret = [%d], stdout = [%s], stderr = [%s]",
                      command,
                      build_host.sh_hostname,
                      retval.cr_exit_status,
                      retval.cr_stdout,
                      retval.cr_stderr)
        return -1

    command = ('cd %s && '
               'rpmbuild -ba --with write_tsdb --with nfs --without java '
               '--without amqp --without gmond --without nut --without pinba '
               '--without ping --without varnish --without dpdkstat '
               '--without turbostat --without redis --without write_redis '
               '--without gps --without lvm --define "_topdir %s" '
               '--define="rev $(git rev-parse --short HEAD)" '
               '--define="dist .el%s" '
               'contrib/redhat/collectd.spec' %
               (host_collectd_git_dir, host_collectd_git_dir, distro_number))
    retval = build_host.sh_run(command)
    if retval.cr_exit_status:
        logging.error("failed to run command [%s] on host [%s], "
                      "ret = [%d], stdout = [%s], stderr = [%s]",
                      command,
                      build_host.sh_hostname,
                      retval.cr_exit_status,
                      retval.cr_stdout,
                      retval.cr_stderr)
        return -1

    ret = build_host.sh_get_file(host_collectd_rpm_dir, local_rpm_dir)
    if ret:
        logging.error("failed to get build RPMs from path [%s] on host "
                      "[%s] to local dir [%s]", host_collectd_rpm_dir,
                      build_host.sh_hostname, local_rpm_dir)
        return -1
    return 0


def collectd_build_check(workspace, build_host, base_path, collectd_git_path,
                         collectd_version_release,
                         collectd_tarball_name, distro, target_cpu):
    """
    Check and build Collectd RPMs
    """
    # pylint: disable=too-many-arguments,too-many-return-statements
    # pylint: disable=too-many-statements,too-many-branches,too-many-locals
    local_rpm_dir = ("%s/%s" %
                     (base_path, RPM_STRING))
    command = ("mkdir -p %s && ls %s" %
               (local_rpm_dir, local_rpm_dir))
    retval = build_host.sh_run(command)
    if retval.cr_exit_status:
        logging.error("failed to run command [%s] on host [%s], "
                      "ret = [%d], stdout = [%s], stderr = [%s]",
                      command,
                      build_host.sh_hostname,
                      retval.cr_exit_status,
                      retval.cr_stdout,
                      retval.cr_stderr)
        return -1
    rpm_collectd_fnames = retval.cr_stdout.split()

    if distro == ssh_host.DISTRO_RHEL8:
        distro_number = "8"
    elif distro == ssh_host.DISTRO_RHEL7:
        distro_number = "7"
    else:
        logging.error("unsupported distro [%s]", distro)
        return -1

    found = False
    for collect_rpm_name in COLLECTD_RPM_NAMES:
        collect_rpm_full = ("%s-%s.el%s.%s.rpm" %
                            (collect_rpm_name, collectd_version_release,
                             distro_number, target_cpu))
        found = False
        for rpm_collectd_fname in rpm_collectd_fnames[:]:
            if collect_rpm_full == rpm_collectd_fname:
                found = True
                rpm_collectd_fnames.remove(rpm_collectd_fname)
                logging.debug("RPM [%s/%s] already cached",
                              local_rpm_dir, collect_rpm_full)
                break

        if not found:
            logging.debug("RPM [%s] not cached in directory [%s], building "
                          "Collectd", collect_rpm_full, local_rpm_dir)
            break

    if not found:
        ret = collectd_build(workspace, build_host, base_path, collectd_git_path,
                             collectd_tarball_name,
                             distro_number)
        if ret:
            logging.error("failed to build Collectd on host [%s]",
                          build_host.sh_hostname)
            return -1

        # Don't trust the build, check RPMs again
        command = ("ls %s" % (local_rpm_dir))
        retval = build_host.sh_run(command)
        if retval.cr_exit_status:
            logging.error("failed to run command [%s] on host [%s], "
                          "ret = [%d], stdout = [%s], stderr = [%s]",
                          command,
                          build_host.sh_hostname,
                          retval.cr_exit_status,
                          retval.cr_stdout,
                          retval.cr_stderr)
            return -1
        rpm_collectd_fnames = retval.cr_stdout.split()

        for collect_rpm_name in COLLECTD_RPM_NAMES:
            collect_rpm_full = ("%s-%s.el%s.%s.rpm" %
                                (collect_rpm_name, collectd_version_release,
                                 distro_number, target_cpu))
            found = False
            for rpm_collectd_fname in rpm_collectd_fnames[:]:
                if collect_rpm_full == rpm_collectd_fname:
                    found = True
                    rpm_collectd_fnames.remove(rpm_collectd_fname)
                    logging.debug("RPM [%s/%s] already cached",
                                  local_rpm_dir, collect_rpm_full)
                    break

            if not found:
                logging.error("RPM [%s] not found in directory [%s] after "
                              "building Collectd", collect_rpm_full,
                              local_rpm_dir)
                return -1
    else:
        collect_rpm_pattern = (r"collectd-\S+-%s.el%s.%s.rpm" %
                               (collectd_version_release, distro_number,
                                target_cpu))
        collect_rpm_regular = re.compile(collect_rpm_pattern)
        for rpm_collectd_fname in rpm_collectd_fnames[:]:
            match = collect_rpm_regular.match(rpm_collectd_fname)
            if not match:
                fpath = ("%s/%s" %
                         (local_rpm_dir, rpm_collectd_fname))
                logging.debug("found a file [%s] not matched with pattern "
                              "[%s], removing it", fpath,
                              collect_rpm_pattern)

                command = ("rm -f %s" % (fpath))
                retval = build_host.sh_run(command)
                if retval.cr_exit_status:
                    logging.error("failed to run command [%s] on host [%s], "
                                  "ret = [%d], stdout = [%s], stderr = [%s]",
                                  command,
                                  build_host.sh_hostname,
                                  retval.cr_exit_status,
                                  retval.cr_stdout,
                                  retval.cr_stderr)
                    return -1
    return 0


def collectd_host_build(workspace, build_host, base_path, collectd_git_path,
                        collectd_version_release, collectd_tarball_name):
    """
    Build on host
    """
    # pylint: disable=too-many-return-statements,too-many-arguments
    # pylint: disable=too-many-statements,too-many-locals,too-many-branches
    distro = build_host.sh_distro()
    if distro is None:
        logging.error("failed to get distro on host [%s]",
                      build_host.sh_hostname)
        return -1

    target_cpu = build_host.sh_target_cpu()
    if target_cpu is None:
        logging.error("failed to get target cpu on host [%s]",
                      build_host.sh_hostname)
        return -1

    # Update to the latest distro release
    command = "yum update -y"
    retval = build_host.sh_run(command, timeout=1200)
    if retval.cr_exit_status:
        logging.error("failed to run command [%s] on host [%s], "
                      "ret = [%d], stdout = [%s], stderr = [%s]",
                      command,
                      build_host.sh_hostname,
                      retval.cr_exit_status,
                      retval.cr_stdout,
                      retval.cr_stderr)
        return -1

    # Sometimes yum update install i686 RPMs which cause multiple RPMs for
    # the same name. Uninstall i686 RPMs here.
    target_cpu = build_host.sh_target_cpu()
    if target_cpu is None:
        logging.error("failed to get target cpu on host [%s]",
                      build_host.sh_hostname)
        return -1

    # # Enable powertools for packages not available on repo in RHEL 8
    if distro == ssh_host.DISTRO_RHEL8:
        command = ("yum install dnf-plugins-core | yum config-manager --set-enabled powertools")
        build_host.sh_run(command)

    if target_cpu == "x86_64":
        command = "rpm -qa | grep i686"
        retval = build_host.sh_run(command, timeout=600)
        if retval.cr_exit_status == 0:
            command = "rpm -qa | grep i686 | xargs rpm -e"
            retval = build_host.sh_run(command, timeout=600)
            if retval.cr_exit_status:
                logging.error("failed to run command [%s] on host [%s], "
                              "ret = [%d], stdout = [%s], stderr = [%s]",
                              command,
                              build_host.sh_hostname,
                              retval.cr_exit_status,
                              retval.cr_stdout,
                              retval.cr_stderr)
                return -1

    command = ("rpm -e zeromq-devel")
    build_host.sh_run(command)

    # The RPMs needed by Collectd building
    # riemann-c-client-devel is not available for RHEL6, but that is fine
    command = ("yum install libgcrypt-devel libtool-ltdl-devel curl-devel "
               "libxml2-devel yajl-devel libdbi-devel libpcap-devel "
               "OpenIPMI-devel iptables-devel libvirt-devel "
               "libvirt-devel libmemcached-devel mysql-devel libnotify-devel "
               "libesmtp-devel postgresql-devel rrdtool-devel "
               "lm_sensors-libs lm_sensors-devel net-snmp-devel libcap-devel "
               "lvm2-devel libmnl-devel iproute-devel "
               "hiredis-devel libatasmart-devel protobuf-c-devel "
               "mosquitto-devel gtk2-devel openldap-devel "
               "zeromq-devel libssh2-devel rrdtool-devel rrdtool "
               "createrepo mkisofs yum-utils redhat-lsb unzip "
               "epel-release perl-Regexp-Common pylint "
               "lua-devel byacc ganglia-devel libmicrohttpd-devel "
               "riemann-c-client-devel xfsprogs-devel uthash-devel "
               "qpid-proton-c-devel perl-ExtUtils-Embed -y")
    retval = build_host.sh_run(command)
    if retval.cr_exit_status:
        logging.error("failed to run command [%s] on host [%s], "
                      "ret = [%d], stdout = [%s], stderr = [%s]",
                      command,
                      build_host.sh_hostname,
                      retval.cr_exit_status,
                      retval.cr_stdout,
                      retval.cr_stderr)
        return -1

    command = "mkdir -p %s" % workspace
    retval = build_host.sh_run(command)
    if retval.cr_exit_status:
        logging.error("failed to run command [%s] on host [%s], "
                      "ret = [%d], stdout = [%s], stderr = [%s]",
                      command,
                      build_host.sh_hostname,
                      retval.cr_exit_status,
                      retval.cr_stdout,
                      retval.cr_stderr)
        return -1

    ret = collectd_build_check(workspace, build_host, base_path, collectd_git_path,
                               collectd_version_release, collectd_tarball_name, distro, target_cpu)
    if ret:
        logging.error("failed to build collectd_build_check on host [%s]",
                      build_host.sh_hostname)
        return -1

    return 0

def collecd_build_prepare(current_dir, relative_workspace):
    """
    Prepare Collectd build
    """
    # pylint: disable=too-many-locals,too-many-return-statements
    # pylint: disable=too-many-branches,too-many-statements

    build_host = ssh_host.SSHHost("localhost", local=True)
    distro = build_host.sh_distro()
    if distro not in (ssh_host.DISTRO_RHEL7, ssh_host.DISTRO_RHEL8):
        logging.error("build can only be launched on RHEL7/CentOS7/RHEL8/CentOS8 host")
        return -1

    target_cpu = build_host.sh_target_cpu()
    if target_cpu is None:
        logging.error("failed to get target cpu on local_host [%s]",
                      build_host.sh_hostname)
        return -1

    collectd_git_path = current_dir + "/../" + "collectd.git"

    # collectd_git_url = "https://github.com/ayush-ddn/collectd.git"
    collectd_git_url = "https://github.com/DDNStorage/collectd.git"
    logging.info("using git url [%s]", collectd_git_url)

    # collectd_git_branch = "MOM-23178"
    collectd_git_branch = "master-ddn"
    logging.info("using git branch [%s]", collectd_git_branch)

    ret = common.clone_src_from_git(collectd_git_path, collectd_git_url,
                                    collectd_git_branch)
    if ret:
        logging.error("failed to clone Collectd branch [%s] from [%s] to "
                      "directory [%s]", collectd_git_branch,
                      collectd_git_url, collectd_git_path)
        return -1

    command = ("cd %s && git rev-parse --short HEAD" %
               collectd_git_path)
    retval = build_host.sh_run(command)
    if retval.cr_exit_status:
        logging.error("failed to run command [%s] on host [%s], "
                      "ret = [%d], stdout = [%s], stderr = [%s]",
                      command,
                      build_host.sh_hostname,
                      retval.cr_exit_status,
                      retval.cr_stdout,
                      retval.cr_stderr)
        return -1
    collectd_git_version = retval.cr_stdout.strip()

    command = (r"cd %s && grep Version contrib/redhat/collectd.spec | "
               r"grep -v \# | awk '{print $2}'" %
               collectd_git_path)
    retval = build_host.sh_run(command)
    if retval.cr_exit_status:
        logging.error("failed to run command [%s] on host [%s], "
                      "ret = [%d], stdout = [%s], stderr = [%s]",
                      command,
                      build_host.sh_hostname,
                      retval.cr_exit_status,
                      retval.cr_stdout,
                      retval.cr_stderr)
        return -1

    collectd_version_string = retval.cr_stdout.strip()
    collectd_tarball_name = "collectd-" + collectd_version_string

    command = (r"cd %s && grep Release contrib/redhat/collectd.spec | "
               r"grep -v \# | awk '{print $2}'" %
               collectd_git_path)
    retval = build_host.sh_run(command)
    if retval.cr_exit_status:
        logging.error("failed to run command [%s] on host [%s], "
                      "ret = [%d], stdout = [%s], stderr = [%s]",
                      command,
                      build_host.sh_hostname,
                      retval.cr_exit_status,
                      retval.cr_stdout,
                      retval.cr_stderr)
        return -1
    collectd_release_string = retval.cr_stdout.strip()
    collectd_release_string = collectd_release_string.replace('%{?rev}', collectd_git_version)
    collectd_release = collectd_release_string.replace('%{?dist}', '')
    collectd_version_release = collectd_version_string + "-" + collectd_release

    # The build host of CentOS7 could potentially be another host, not local
    # host
    local_workspace = current_dir + "/" + relative_workspace
    ret = collectd_host_build(local_workspace, build_host, current_dir, collectd_git_path,
                              collectd_version_release, collectd_tarball_name)
    if ret:
        logging.error("failed to prepare RPMs on local host")
        return -1
    return 0


def main():
    """
    Build Collectd
    """
    # pylint: disable=unused-variable
    identity = time_util.local_strftime(time_util.utcnow(), "%Y-%m-%d-%H_%M_%S")

    current_dir = os.getcwd()
    build_log_dir = "build_collectd"
    relative_workspace = build_log_dir + "/" + identity

    local_workspace = current_dir + "/" + relative_workspace
    local_log_dir = current_dir + "/" + build_log_dir
    if not os.path.exists(local_log_dir):
        os.mkdir(local_log_dir)
    elif not os.path.isdir(local_log_dir):
        logging.error("[%s] is not a directory", local_log_dir)
        sys.exit(-1)

    if not os.path.exists(local_workspace):
        os.mkdir(local_workspace)
    elif not os.path.isdir(local_workspace):
        logging.error("[%s] is not a directory", local_workspace)
        sys.exit(-1)

    utils.configure_logging(local_workspace)

    console_handler = utils.LOGGING_HANLDERS["console"]
    console_handler.setLevel(logging.DEBUG)

    ret = collecd_build_prepare(current_dir, relative_workspace)
    if ret:
        logging.error("build failed")
        sys.exit(ret)
    logging.info("Collectd is successfully built")
    sys.exit(0)
