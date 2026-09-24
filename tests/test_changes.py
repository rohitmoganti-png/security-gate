"""Tests for 'what changed?' (security_gate/changes.py)."""

import pytest

from security_gate.changes import EMPTY_TREE, GitError, collect_changes


def test_added_modified_deleted_and_exact_new_lines(repo):
    repo.write("app.py", "".join(f"line{i}\n" for i in range(1, 11)))
    repo.write("old.py", "x = 1\n")
    base = repo.commit("base")

    repo.git("checkout", "-q", "-b", "feature")
    repo.write("app.py", open(repo.path / "app.py").read().replace("line3\n", "line3\nNEW\n"))
    repo.write("new.py", "a = 1\nb = 2\n")
    (repo.path / "old.py").unlink()
    repo.commit("feature")

    changes = collect_changes(repo.path, base, "HEAD")
    by_path = {f.path: f for f in changes.files}
    assert by_path["app.py"].status == "modified"
    assert by_path["app.py"].added_lines == {4}  # only the inserted line
    assert by_path["new.py"].status == "added"
    assert by_path["new.py"].added_lines == {1, 2}
    assert by_path["old.py"].status == "deleted"
    assert [f.path for f in changes.current_files] == sorted(["app.py", "new.py"])


def test_first_push_treats_every_file_as_new(repo):
    repo.write("a.py", "x = 1\n")
    repo.commit()
    for first_push_base in ("", "0" * 40):
        changes = collect_changes(repo.path, first_push_base)
        assert changes.base == EMPTY_TREE
        assert changes.files[0].status == "added"


def test_commits_added_to_main_later_are_not_blamed_on_the_branch(repo):
    repo.write("a.py", "x = 1\n")
    repo.commit("base")
    repo.git("checkout", "-q", "-b", "feature")
    repo.write("feature.py", "f = 1\n")
    repo.commit("feature work")
    repo.git("checkout", "-q", "main")
    repo.write("main_only.py", "m = 1\n")
    repo.commit("someone else's work on main")

    changes = collect_changes(repo.path, "main", "feature")
    assert [f.path for f in changes.files] == ["feature.py"]


def test_renamed_and_spaced_paths(repo):
    content = "".join(f"row {i}\n" for i in range(20))
    repo.write("old name.py", content)
    base = repo.commit()
    repo.git("mv", "old name.py", "new name.py")
    repo.commit()
    (f,) = collect_changes(repo.path, base).files
    assert (f.status, f.path) == ("renamed", "new name.py")


def test_touches_checks_line_ranges(repo):
    repo.write("a.py", "1\n")
    base = repo.commit()
    repo.write("a.py", "1\n2\n3\n")
    repo.commit()
    (f,) = collect_changes(repo.path, base).files
    assert f.touches(2) and f.touches(1, 3)
    assert not f.touches(1)


@pytest.mark.parametrize("bad_ref", ["--output=/tmp/x", "does-not-exist"])
def test_bad_refs_give_clear_errors(repo, bad_ref):
    repo.write("a.py", "x\n")
    repo.commit()
    with pytest.raises(GitError):
        collect_changes(repo.path, bad_ref)
