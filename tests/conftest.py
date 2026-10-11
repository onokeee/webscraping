import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


import pytest


@pytest.fixture(autouse=True)
def _downloads_go_to_a_temp_dir(tmp_path_factory, monkeypatch):
    """Generated scripts save Excel / CSV downloads (DESIGN.md §8) into ``REQREC_OUTPUT_DIR`` or the
    current directory.  Tests run them in-process with the repository as cwd, so point the default
    at a throw-away folder; a test that sets ``REQREC_OUTPUT_DIR`` itself still wins."""
    monkeypatch.setenv("REQREC_OUTPUT_DIR", str(tmp_path_factory.mktemp("downloads")))
