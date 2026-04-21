from skylos.llm.graph import CodeGraph


def test_find_taint_paths_detects_request_args_get_to_subprocess_run():
    source = (
        "from flask import request\n"
        "import subprocess\n\n"
        "def ls():\n"
        "    cmd = request.args.get('cmd')\n"
        "    return subprocess.run(cmd, shell=True)\n"
    )

    graph = CodeGraph()
    graph.build(source)

    paths = graph.find_taint_paths("ls")

    assert paths
    assert any(path["sink_type"] == "subprocess.run" for path in paths)
    assert any(path["source"].endswith("request.args.get") for path in paths)


def test_find_taint_paths_detects_request_args_subscript_to_check_output():
    source = (
        "from flask import request\n"
        "import subprocess\n\n"
        "def dump_user():\n"
        "    query = request.args['id']\n"
        "    return subprocess.check_output(query, shell=True)\n"
    )

    graph = CodeGraph()
    graph.build(source)

    paths = graph.find_taint_paths("dump_user")

    assert paths
    assert any(path["sink_type"] == "subprocess.check_output" for path in paths)
    assert any(path["source"].endswith("request.args") for path in paths)
