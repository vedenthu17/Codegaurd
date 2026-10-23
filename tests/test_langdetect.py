import pytest

from codeguard.langdetect import detect_language

CASES = [
    ("import os\n\ndef main():\n    print(os.getcwd())\n", "python"),
    ("#!/usr/bin/env bash\nset -e\necho hi\n", "bash"),
    ("ls -la /tmp && echo done\n", "bash"),
    ("for f in *.log; do\n  gzip \"$f\"\ndone\n", "bash"),
    ("SELECT id, name FROM users WHERE id = 1;", "sql"),
    ("CREATE TABLE t (id INT);\nINSERT INTO t VALUES (1);", "sql"),
    ("const x = require('fs');\nmodule.exports = { x };", "javascript"),
    ("async function f() {\n  const r = await fetch(url);\n  return r.json();\n}", "javascript"),
    ("name: ci\non:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n", "yaml"),
    ("# Title\n\nSome prose here with a [link](http://example.com).\n\n## Section\n\n- item\n", "markdown"),
    ("Get-ChildItem -Path C:\\ | Remove-Item -Recurse", "powershell"),
    ("", "text"),
]


@pytest.mark.parametrize("code,lang", CASES)
def test_detect(code, lang):
    assert detect_language(code) == lang
