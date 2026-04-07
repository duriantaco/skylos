from skylos.server_frontend import render_frontend_html


def test_render_frontend_html_contains_expected_markup():
    html = render_frontend_html("test-token")

    assert "<!DOCTYPE html>" in html
    assert "Skylos Dead Code Analyzer" in html
    assert 'id="analyzeBtn"' in html
    assert "wrapper.textContent = message" in html
    assert "name.textContent = item.name" in html


def test_render_frontend_html_escapes_token_for_script_context():
    html = render_frontend_html('tok-"</script>-x')

    assert 'const SKYLOS_WEB_TOKEN = "tok-\\"<\\/script>-x";' in html
    assert "</script>-x" not in html
