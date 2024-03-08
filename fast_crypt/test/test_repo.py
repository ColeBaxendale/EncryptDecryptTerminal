from fast_crypt.get_repo import get_current_repo


def test_get_current_repo_success(mocker):
    # Mock subprocess.check_output to return a successful GitHub repo URL
    mocker.patch(
        "subprocess.check_output",
        return_value=b"https://github.com/user/repo.git\n"
    )
    assert get_current_repo() == "user/repo"

def test_get_current_repo_not_github(mocker):
    # Mock subprocess.check_output to return a non-GitHub URL
    mocker.patch(
        "subprocess.check_output",
        return_value=b"https://someotherhost.com/user/repo.git\n"
    )
    assert get_current_repo() is None

def test_get_current_repo_exception(mocker):
    # Mock subprocess.check_output to raise an exception (e.g., git not found)
    mocker.patch(
        "subprocess.check_output",
        side_effect=Exception("Error executing git command")
    )
    assert get_current_repo() is None