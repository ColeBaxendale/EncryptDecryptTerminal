import subprocess
import click


def get_current_repo():
    try:
        remote_url = subprocess.check_output(["git", "config", "--get", "remote.origin.url"]).decode().strip()
        if "github.com" in remote_url:
            return remote_url.split("github.com/")[1].replace(".git", "")
    except Exception as e:
        click.echo(f"Error detecting repository: {e}")
    return None