import textwrap

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.config.cicd.github_actions import scan_github_actions


def _write(tmp_path, name, text):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(
        workflows / name, textwrap.dedent(text).lstrip(), encoding="utf-8"
    )


def _injections(tmp_path):
    return sorted(
        (finding["file"].rsplit("/", 1)[-1], finding["line"], finding["severity"])
        for finding in scan_github_actions(tmp_path)
        if finding["rule_id"] == "SKY-D294"
    )


def _workflow(trigger, steps, job_extra="", workflow_extra=""):
    return (
        f"name: t\non: {trigger}\npermissions: {{}}\n{workflow_extra}"
        "jobs:\n  a:\n    runs-on: ubuntu-latest\n"
        f"{job_extra}    steps:\n{steps}"
    )


def test_attacker_text_reaches_code_through_every_expression_form(tmp_path):
    steps = (
        "      - run: echo \"${{ github['event']['issue']['title'] }}\"\n"
        "      - run: echo \"${{ format('{0}', github.event.comment.body) }}\"\n"
        "      - run: echo \"${{ github.event_name == 'x' && github.event.comment.body || '' }}\"\n"
        "      - run: echo '${{ toJSON(github.event) }}'\n"
        "      - run: echo '${{ toJSON(github) }}'\n"
        "      - run: echo \"${{ fromJSON(toJSON(github.event.issue.title)) }}\"\n"
        "      - run: echo \"${{ fromJSON(github.event.issue.body).cmd }}\"\n"
        "      - run: echo \"${{ case(github.event.issue.locked, github.event.issue.title, 'x') }}\"\n"
    )
    _write(tmp_path, "ci.yml", _workflow("issue_comment", steps))
    assert _injections(tmp_path) == [("ci.yml", line, "HIGH") for line in range(8, 16)]


def test_values_an_attacker_cannot_shape_are_not_injection(tmp_path):
    steps = (
        "      - run: echo \"${{ github.event.pull_request.number }} ${{ github.event.pull_request.head.sha }}\"\n"
        "      - run: echo \"${{ github.event.issue.title == 'x' }} ${{ contains(github.event.issue.title, 'x') }}\"\n"
        "      - run: echo \"${{ case(github.event.issue.title, 'a', 'b') }}\"\n"
        "      - run: echo \"${{ secrets.TOKEN }} ${{ needs.x.result }} ${{ github.actor }}\"\n"
        "      - run: echo \"${{ github.ref_name }} ${{ github.base_ref }} ${{ vars.REGION }}\"\n"
        "      - run: echo \"${{ github.ref == 'refs/heads/main' && '' || 'dev' }}\"\n"
    )
    _write(tmp_path, "ci.yml", _workflow("pull_request_target", steps))
    assert _injections(tmp_path) == []


def test_severity_follows_who_can_trigger_the_job(tmp_path):
    step = "      - run: echo \"${{ github.event.issue.title }} ${{ github.head_ref }}\"\n"
    _write(tmp_path, "outsider.yml", _workflow("issues", step))
    _write(tmp_path, "pr.yml", _workflow("pull_request", step))
    _write(tmp_path, "push.yml", _workflow("push", step))
    gated = "    if: github.event.issue.author_association == 'OWNER'\n"
    _write(tmp_path, "gated.yml", _workflow("issues", step, job_extra=gated))
    assert _injections(tmp_path) == [
        ("gated.yml", 9, "LOW"),
        ("gated.yml", 9, "LOW"),
        ("outsider.yml", 8, "HIGH"),
        ("outsider.yml", 8, "HIGH"),
        ("pr.yml", 8, "LOW"),
        ("pr.yml", 8, "LOW"),
        ("push.yml", 8, "LOW"),
        ("push.yml", 8, "LOW"),
    ]


def test_env_values_are_followed_to_what_sets_them(tmp_path):
    job_env = "    env:\n      TITLE: ${{ github.event.issue.title }}\n      SAFE: constant\n"
    workflow_env = "env:\n  BODY: ${{ github.event.issue.body }}\n  TITLE: shadowed\n"
    steps = (
        "      - run: echo \"${{ env.TITLE }}\"\n"
        "      - run: echo \"${{ env.BODY }}\"\n"
        "      - run: echo \"${{ env.SAFE }} ${{ env.GITHUB_SHA }} ${{ env.UNSET }}\"\n"
        "      - run: echo \"${{ env.TITLE }}\"\n"
        "        env:\n          TITLE: fixed\n"
        "      - run: echo \"${{ env.SAFE }}\"\n"
        "        env:\n          SAFE: ${{ github.event.comment.body }}\n"
    )
    _write(
        tmp_path,
        "ci.yml",
        _workflow("issue_comment", steps, job_extra=job_env, workflow_extra=workflow_env),
    )
    assert _injections(tmp_path) == [
        ("ci.yml", 14, "HIGH"),
        ("ci.yml", 15, "HIGH"),
        ("ci.yml", 20, "HIGH"),
    ]


def test_unset_env_counts_only_when_a_step_writes_github_env(tmp_path):
    steps = (
        "      - run: echo \"X=$(cat input)\" >> \"$GITHUB_ENV\"\n"
        "      - run: echo \"${{ env.X }}\"\n"
    )
    _write(tmp_path, "ci.yml", _workflow("issues", steps))
    assert _injections(tmp_path) == [("ci.yml", 9, "LOW")]


def test_matrix_values_are_followed(tmp_path):
    direct = "    strategy:\n      matrix:\n        t: ${{ fromJSON(github.event.issue.body) }}\n"
    include = (
        "    strategy:\n      matrix:\n        os: [ubuntu-latest]\n"
        "        include: ${{ fromJSON(github.event.issue.body) }}\n"
    )
    static = "    strategy:\n      matrix:\n        os: [ubuntu-latest, macos-latest]\n"
    step = "      - run: echo \"${{ matrix.t }} ${{ matrix.os }}\"\n"
    _write(tmp_path, "direct.yml", _workflow("issues", step, job_extra=direct))
    _write(tmp_path, "include.yml", _workflow("issues", step, job_extra=include))
    _write(tmp_path, "static.yml", _workflow("issues", step, job_extra=static))
    assert _injections(tmp_path) == [
        ("direct.yml", 11, "HIGH"),
        ("include.yml", 12, "HIGH"),
        ("include.yml", 12, "HIGH"),
    ]


def test_inputs_are_followed_to_local_callers(tmp_path):
    callee = (
        "name: callee\non:\n  workflow_call:\n    inputs:\n"
        "      who:\n        type: string\n      count:\n        type: number\n"
        "permissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: echo \"${{ inputs.who }} ${{ inputs.count }}\"\n"
    )
    _write(tmp_path, "callee.yml", callee)
    _write(
        tmp_path,
        "caller.yml",
        "name: caller\non: issues\npermissions: {}\njobs:\n  call:\n"
        "    uses: ./.github/workflows/callee.yml\n"
        "    with:\n      who: ${{ github.event.issue.title }}\n      count: 3\n",
    )
    _write(
        tmp_path,
        "quiet.yml",
        "name: quiet\non: push\npermissions: {}\njobs:\n  call:\n"
        "    uses: ./.github/workflows/callee.yml\n    with:\n      who: fixed\n",
    )
    assert _injections(tmp_path) == [("callee.yml", 14, "HIGH")]


def test_inputs_without_a_local_caller_or_from_dispatch(tmp_path):
    callee = (
        "name: callee\non:\n  workflow_call:\n    inputs:\n      who:\n        type: string\n"
        "permissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: echo \"${{ inputs.who }}\"\n"
    )
    _write(tmp_path, "callee.yml", callee)
    dispatch = (
        "name: dispatch\non:\n  workflow_dispatch:\n    inputs:\n"
        "      note:\n        type: string\n      env:\n        type: choice\n"
        "        options: [a, b]\n"
        "permissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: echo \"${{ inputs.note }} ${{ inputs.env }}\"\n"
    )
    _write(tmp_path, "dispatch.yml", dispatch)
    assert _injections(tmp_path) == [("callee.yml", 12, "MEDIUM"), ("dispatch.yml", 15, "LOW")]


def test_composite_action_inputs_and_events(tmp_path):
    action = tmp_path / "act"
    action.mkdir()
    assert write_text_no_symlink(
        action / "action.yml",
        "name: act\ndescription: x\ninputs:\n  foo:\n    description: x\n"
        "runs:\n  using: composite\n  steps:\n    - shell: bash\n"
        "      run: echo \"${{ inputs.foo }} ${{ github.event.issue.title }} ${{ inputs.undeclared }}\"\n",
        encoding="utf-8",
    )
    assert _injections(tmp_path) == [("action.yml", 10, "MEDIUM"), ("action.yml", 10, "MEDIUM")]


def test_code_inputs_of_known_actions_and_job_options(tmp_path):
    steps = (
        "      - uses: actions/github-script@v7\n"
        "        with:\n          script: console.log('${{ github.event.issue.body }}')\n"
        "      - uses: mikefarah/yq@v4\n"
        "        with:\n          cmd: yq '${{ github.event.issue.title }}' a.yml\n"
        "      - uses: actions/github-script@v7\n"
        "        with:\n          github-token: ${{ github.event.issue.title }}\n"
    )
    container = "    container:\n      image: node\n      options: --label ${{ github.event.issue.title }}\n"
    _write(tmp_path, "ci.yml", _workflow("issues", steps, job_extra=container))
    assert _injections(tmp_path) == [
        ("ci.yml", 9, "HIGH"),
        ("ci.yml", 13, "HIGH"),
        ("ci.yml", 16, "HIGH"),
    ]


def test_repeated_expressions_get_their_own_lines(tmp_path):
    workflow = (
        "name: t\non: issues\npermissions: {}\njobs:\n"
        "  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: |\n          echo \"${{ github.event.issue.title }}\"\n"
        "          echo \"${{ github.event.issue.title }}\"\n"
        "  b:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: echo \"${{ github.event.issue.title }}\"\n"
    )
    _write(tmp_path, "ci.yml", workflow)
    assert _injections(tmp_path) == [("ci.yml", 9, "HIGH"), ("ci.yml", 10, "HIGH"), ("ci.yml", 14, "HIGH")]


def test_unparsable_expressions_still_report(tmp_path):
    step = "      - run: echo \"${{ github.event.issue.title = 1 }}\"\n"
    _write(tmp_path, "ci.yml", _workflow("issues", step))
    assert _injections(tmp_path) == [("ci.yml", 8, "MEDIUM")]


def test_step_and_job_outputs_are_followed(tmp_path):
    steps = (
        "      - id: stage\n"
        "        env:\n          TEXT: ${{ github.event.pull_request.title }}\n          SAFE: fixed\n"
        "        run: |\n"
        "          printf 'code=%s\\n' \"$TEXT\" >> \"$GITHUB_OUTPUT\"\n"
        "          echo \"other=$SAFE\" >> \"$GITHUB_OUTPUT\"\n"
        "          echo \"count=$(wc -l < list)\" >> \"$GITHUB_OUTPUT\"\n"
        "          echo \"body<<EOF\" >> \"$GITHUB_OUTPUT\"\n"
        "          echo \"$TEXT\" >> \"$GITHUB_OUTPUT\"\n"
        "          echo \"EOF\" >> \"$GITHUB_OUTPUT\"\n"
        "          echo \"direct=${{ github.event.pull_request.body }}\" >> $GITHUB_OUTPUT\n"
        "      - run: echo \"${{ steps.stage.outputs.code }}\"\n"
        "      - run: echo \"${{ steps.stage.outputs.other }} ${{ steps.stage.outputs.count }}\"\n"
        "      - run: echo \"${{ steps.stage.outputs.body }}\"\n"
        "      - run: echo \"${{ steps.missing.outputs.x }}\"\n"
    )
    _write(tmp_path, "ci.yml", _workflow("pull_request_target", steps))
    assert _injections(tmp_path) == [
        ("ci.yml", 19, "HIGH"),
        ("ci.yml", 20, "HIGH"),
        ("ci.yml", 22, "HIGH"),
    ]


def test_job_outputs_reach_a_reusable_workflow(tmp_path):
    _write(
        tmp_path,
        "caller.yml",
        "name: caller\non: issue_comment\npermissions: {}\njobs:\n"
        "  prepare:\n    runs-on: ubuntu-latest\n"
        "    outputs:\n      code: ${{ steps.stage.outputs.code }}\n      fixed: ok\n"
        "    steps:\n      - id: stage\n"
        "        env:\n          TEXT: ${{ github.event.comment.body }}\n"
        "        run: echo \"code=$TEXT\" >> \"$GITHUB_OUTPUT\"\n"
        "  invoke:\n    needs: prepare\n    uses: ./.github/workflows/reusable.yml\n"
        "    with:\n      command: ${{ needs.prepare.outputs.code }}\n"
        "      other: ${{ needs.prepare.outputs.fixed }}\n",
    )
    _write(
        tmp_path,
        "reusable.yml",
        "name: reusable\non:\n  workflow_call:\n    inputs:\n"
        "      command:\n        type: string\n      other:\n        type: string\n"
        "jobs:\n  demo:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: ${{ inputs.command }}\n      - run: ${{ inputs.other }}\n",
    )
    assert _injections(tmp_path) == [("reusable.yml", 13, "HIGH")]


def test_payload_fields_are_judged_by_the_events_that_carry_them(tmp_path):
    workflow = (
        "name: t\non:\n  issue_comment:\n  push:\n  workflow_dispatch:\n"
        "    inputs:\n      command:\n        type: string\n"
        "permissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: echo \"${{ github.event.inputs.command }}\"\n"
        "      - run: echo \"${{ github.event.head_commit.message }}\"\n"
        "      - run: echo \"${{ github.event.comment.body }}\"\n"
        "      - run: echo \"${{ github.event.repository.description }}\"\n"
    )
    _write(tmp_path, "ci.yml", workflow)
    assert _injections(tmp_path) == [
        ("ci.yml", 14, "LOW"),
        ("ci.yml", 15, "LOW"),
        ("ci.yml", 16, "HIGH"),
    ]


def test_odd_but_valid_expressions_do_not_break_the_scan(tmp_path):
    chain = "||".join(["0"] * 2000)
    steps = (
        f"      - run: echo \"${{{{ {chain}||github.event.comment.body }}}}\"\n"
        "      - run: echo \"${{ NaN || github.event.comment.body }}\"\n"
    )
    _write(tmp_path, "ci.yml", _workflow("issue_comment", steps))
    assert _injections(tmp_path) == [("ci.yml", 8, "HIGH"), ("ci.yml", 9, "HIGH")]
