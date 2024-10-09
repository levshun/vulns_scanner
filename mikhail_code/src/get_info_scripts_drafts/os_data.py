###############################
# Как собираем информацию из ОС для трансформации в CPE
# 1) dpkg -- низкоуровненый пакетный менеджер
# 2) apt -- высокоуровненый пакетный менеджер
# 3) snap -- 
# 4) о комп. железе -- 
###############################



##### Versioning in dpkg -l
# ##
# he version numbers in Debian are of the form

# [epoch:]upstream_version[-debian_revision] 

# where

#     epoch is a single (generally small) unsigned integer, which is included to allow mistakes in the version numbers of older versions of a package. 
# If omitted, the epoch is assumed to be zero.

#     upstream_version is usually the version number of the original source package from which the .deb file has been made. 
# It is usually kept the same as the format used for the upstream source.

#     debian_revision specifies the version of the Debian package based on the upstream version. 
# It is optional and is omitted in cases where a piece of software was written specifically to be a Debian package.
# ##


##### Upstream
# ##
# Within information technology, the term upstream (and related term "downstream") refers to the flow of data. 
# An upstream in open source is the source repository and project where contributions happen and releases are made. 
# The contributions flow from upstream to downstream.

# When talking about an upstream, it's usually the precursor to other projects and products. 
# One of the best-known examples is the Linux kernel, which is an upstream project for many Linux distributions. 
# Distributors like Red Hat take the unmodified (often referred to as "vanilla") kernel source and then add patches, 
# add an opinionated configuration, and build the kernel with the options they want to offer their users.
# ##



##### +dfsg
###
#  What does “dfsg” in the version string mean? “+dfsg.N” is a conventional way of extending a version string, 
# when the Debian package's upstream source tarball is actually different from the source released upstream. 
# This is typically because upstream's source release contains elements that do not satisfy the Debian Free Software Guildelines (DFSG) and hence may not be distributed as source in the Debian system.

# The changes should be documented in README.Debian-source. 
# The recommended way of forming the version string of a package re-packed for DFSG reasons is: “<UPSTREAM_VERSION>+dfsg.<REPACK_COUNT>-<DEBIAN_RELEASE>”. 
###

##### +really
####
# Epochs should not be used when a package needs to be rolled back. 
# In that case, use the +really convention: for example, if you uploaded 2.3-3 and now you need to go backwards to upstream 2.2, call your reverting.

# The presence of +really in the upstream_version component indicates that a newer upstream version has been rolled back to an older upstream version. 
# The part of the upstream_version component following +really is the true upstream version. See Epochs should be used sparingly for an example of when this is used.
####


##### И есть еще разные плюсы

##### Добавить класс для записи в ДБ???

import subprocess
import re

# listing dpkg

dpkg = "dpkg-query -W -f='${Package}---${Version}---${Architecture}\n'"

do = subprocess.Popen(dpkg, shell=True, stdout=subprocess.PIPE)
piped_input = do.communicate()[0]
splitted_results = str(piped_input).strip('b').strip("'").split("\\n")


# print(type(splitted_results))
# print(splitted_results[:20])

pluses = []
for app in splitted_results:
    print(app)
    try:
        package, version, architecture = app.split("---")
    except ValueError:
        continue
    # How versioning works: https://www.debian.org/doc/debian-policy/ch-controlfields.html#version
    if ':' in version:
        epoch = version.split(':')[0]
        version =  version.split(':')[1]
    if '-' in version:
        debian_revision = version.split('-')[1]
        version = version.split('-')[0]
        # Будем ли как-то бороться с этим?
    if '+' in version:
        print(version)
        print('Plus is here!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
        matched_plus_thing = re.findall('(\+.*)', version)
        if matched_plus_thing:
            if matched_plus_thing[0] not in pluses:
                pluses.append(matched_plus_thing[0])
        version = re.findall('(.*)\+.*', version)[0]
    print(package, version, architecture)
    print('*'*30)
    # break

    ### матчим package -> product and version->version

print(f'Those are weird special terms to indicate some version weird things: {pluses}')