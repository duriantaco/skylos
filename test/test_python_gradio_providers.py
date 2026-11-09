from skylos.rules.danger.danger import scan_ctx


def test_gradio_update_api_does_not_rebind_the_module(tmp_path):
    path = tmp_path / "server.py"
    path.write_text(
        "import gradio as gr\ndef visibility():\n    return gr.update(visible=True)\ngr.Blocks().launch(server_name='0.0.0.0')"
    )
    findings = scan_ctx(tmp_path, [path])
    assert len([f for f in findings if f["rule_id"] == "SKY-D358"]) == 1
