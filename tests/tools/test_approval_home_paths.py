"""HOME-path classification invariants (regression for #84639 / #98868).

Command strings are classified only; none of the displayed paths are accessed.
Windows and UNC are path data, not claims about native shell execution.
"""

import pytest

from tools.approval import detect_dangerous_command


_HOMES = [
    "/root", "/tester", "/home/tester", "/home/test user",
    "C:/Accounts/tester", r"C:\Accounts\tester", "//server/share", r"\\server\share",
]
_WRITES = [
    "echo placeholder > {path}", "echo placeholder >> {path}",
    "echo placeholder | tee -a {path}", "cp placeholder {path}",
    "mv placeholder {path}", "install placeholder {path}",
    "sed -i 's/a/b/' {path}", "perl -pi {path}", "ruby -pi {path}",
]
_SPELLINGS = [(path, ".ssh/authorized_keys") for path in [
    "{home}/.ssh/authorized_keys", '"{home}/.ssh/key with spaces"',
    "{home}//.ssh/authorized_keys", "{home}/./.ssh/authorized_keys",
    "{home}/../{name}/.ssh/authorized_keys", r"{home}\/\.ssh/authorized_keys",
    '"{home}/.ssh/authorized_keys"', "'{home}/.ssh/authorized_keys'",
    '{home}/".ssh"/authorized_keys', "~/./.ssh/authorized_keys",
    "~//.ssh/authorized_keys", '"${HOME}/./.ssh/authorized_keys"',
]] + [("{home}/" + target, target) for target in [
    ".ssh/id_rsa", ".netrc", ".pgpass", ".npmrc", ".pypirc", ".bashrc",
    ".zshrc", ".profile", ".bash_profile", ".zprofile", ".hermes/.env", ".hermes/config.yaml",
]]


@pytest.mark.parametrize("home", _HOMES)
@pytest.mark.parametrize("spelling,target", _SPELLINGS)
@pytest.mark.parametrize("operation", _WRITES + [
    "rm -rf {path}",
    pytest.param('echo "$(echo placeholder >> {path})"', id="nested-substitution"),
])
def test_sensitive_home_spellings_agree(home, spelling, target, operation, monkeypatch):
    monkeypatch.setenv("HOME", home)
    name = home.replace("\\", "/").rsplit("/", 1)[-1]
    if " " in name:
        name = '"' + name + '"'
    home_word = home
    if " " in home and not spelling.startswith(("'", '"')):
        home_word = '"' + home + '"'
    path = spelling.replace("{home}", home_word).replace("{name}", name)
    command = operation.format(path=path)
    control = detect_dangerous_command(operation.format(path="~/" + target))
    assert control[0] and control[1] is not None
    assert detect_dangerous_command(command) == control, command


@pytest.mark.parametrize("home,path", [
    ("/root", "/srv/root/.bashrc"), ("/root", "root/.bashrc"),
    ("/home/tester", "/srv/home/tester/.bashrc"), ("/home/tester", "home/tester/.bashrc"),
    ("/root", "/root-other/.bashrc"), ("/root", "/root/notes.txt"),
    ("/root", "/root/reports/out.txt"), ("/root", "/root/.ssh-backup/key"),
    ("/root", "/root/.bashrc_backup"), ("/root", "/root/.netrc_backup"),
    ("/root", "/root/.ssh/../notes.txt"),
    ("", "/.bashrc"), ("/", "/.bashrc"), ("//", "//.bashrc"),
    ("//host", "//host/.bashrc"), ("/C:", "/C:/.bashrc"),
    ("C:/", "C:/.bashrc"), ("C:\\", "C:\\.bashrc"), (r"\\host", r"\\host\.bashrc"),
    ("C:/Accounts/tester", "C:/Accounts/tester/notes.txt"),
    (r"C:\Accounts\tester", r"C:\Accounts\tester\notes.txt"),
    ("//server/share", "//server/share/notes.txt"),
    (r"\\server\share", r"\\server\share\notes.txt"),
])
@pytest.mark.parametrize("operation", _WRITES + [
    "cat {path}", "cp {path} ordinary-backup", "sed -n '1p' {path}",
])
def test_non_home_paths_stay_allowed(home, path, operation, monkeypatch):
    monkeypatch.setenv("HOME", home)
    assert detect_dangerous_command(operation.format(path=path)) == (False, None, None)
    # Read/copy-out are not sensitive writes, even for true HOME credential paths.
    for control in (
        "cat ~/.bashrc", "cat ~/.ssh/id_rsa", "cp ~/.netrc ordinary-backup",
        "cp '~/.ssh/key with spaces' 'ordinary backup'",
        "echo 'echo placeholder >> /root/.bashrc'",
    ):
        assert detect_dangerous_command(control) == (False, None, None)

@pytest.mark.parametrize("home", ["/home/quality-user", "/root"])
@pytest.mark.parametrize("literal", [
    "key$literal", "key?literal", "key*literal", "key[literal]", "key{literal}", "key`literal`",
])
@pytest.mark.parametrize("quoting", ["single", "double", "escaped"])
@pytest.mark.parametrize("operation", ["echo placeholder > {path}", "cp placeholder {path}", "sed -i 's/a/b/' {path}"])
def test_literal_sensitive_descendants_keep_protection(home, literal, quoting, operation, monkeypatch):
    """A literal special character does not undo an already known credential prefix."""
    monkeypatch.setenv("HOME", home)

    def render(path):
        if quoting == "single":
            return "'" + path + "'"
        if quoting == "double":
            return '"' + path.replace("$", "\\$").replace("`", "\\`") + '"'
        return "".join("\\" + ch if ch in "$`*?[]{}" else ch for ch in path)

    control = detect_dangerous_command(operation.format(path=render("~/.ssh/" + literal)))
    assert control[0] and control[1] is not None
    assert detect_dangerous_command(operation.format(path=render(home + "/.ssh/" + literal))) == control
    for path in (
        home + "/notes/" + literal,
        home + "/.ssh-backup/" + literal,
        home + "-other/.ssh/" + literal,
        "/srv" + home + "/.ssh/" + literal,
        home + "/.ssh/../notes/" + literal,
    ):
        assert detect_dangerous_command(operation.format(path=render(path))) == (False, None, None), path
    for read in ("cat {path}", "cp {path} ordinary-backup", "sed -n '1p' {path}"):
        assert detect_dangerous_command(read.format(path=render(home + "/.ssh/" + literal))) == (False, None, None)


@pytest.mark.parametrize("home", ["/home/quality-user", "/root"])
@pytest.mark.parametrize("dynamic", [
    "$UNKNOWN", "`unknown`", "*", "?", "[ab]", "{a,b}",
    '"$UNKNOWN"', '"`unknown`"',
])
@pytest.mark.parametrize("operation", [
    "echo placeholder > {path}", "cp placeholder {path}", "sed -i 's/a/b/' {path}",
])
def test_unknown_expansions_are_not_lexically_resolved(home, dynamic, operation, monkeypatch):
    """Do not collapse .. across an unknown shell expansion into a protected path."""
    monkeypatch.setenv("HOME", home)
    path = home + "/notes/" + dynamic + "/../../.ssh/id_rsa"
    assert detect_dangerous_command(operation.format(path=path)) == (False, None, None)
