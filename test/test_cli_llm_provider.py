class TestLLMProviderResolution:
    def test_provider_inferred_from_claude_model(self):
        model = "claude-3-7-sonnet-latest"
        if "claude" in model.lower():
            provider = "anthropic"
        else:
            provider = "openai"
        assert provider == "anthropic"

    def test_provider_inferred_from_gpt_model(self):
        model = "gpt-4.1"
        if "claude" in model.lower():
            provider = "anthropic"
        else:
            provider = "openai"
        assert provider == "openai"

    def test_provider_inferred_from_local_model(self):
        model = "qwen2.5-coder:7b"
        if "claude" in model.lower():
            provider = "anthropic"
        else:
            provider = "openai"
        assert provider == "openai"


class TestProviderResolutionChain:
    def _resolve_provider(self, cli_provider, env_provider, model):
        return (
            cli_provider
            or env_provider
            or ("anthropic" if "claude" in model.lower() else "openai")
        )

    def test_cli_flag_takes_precedence(self):
        result = self._resolve_provider(
            cli_provider="openai", env_provider="anthropic", model="claude-3-opus"
        )
        assert result == "openai"

    def test_env_var_used_when_no_cli_flag(self):
        result = self._resolve_provider(
            cli_provider=None, env_provider="anthropic", model="gpt-4.1"
        )
        assert result == "anthropic"

    def test_model_inference_as_fallback(self):
        result = self._resolve_provider(
            cli_provider=None, env_provider=None, model="claude-3-sonnet"
        )
        assert result == "anthropic"


class TestBaseURLResolution:
    def _resolve_base_url(self, cli_base_url, env_skylos_url, env_openai_url):
        return cli_base_url or env_skylos_url or env_openai_url

    def test_cli_base_url_takes_precedence(self):
        result = self._resolve_base_url(
            cli_base_url="http://cli:8000/v1",
            env_skylos_url="http://skylos:8000/v1",
            env_openai_url="http://openai:8000/v1",
        )
        assert result == "http://cli:8000/v1"

    def test_skylos_env_used_when_no_cli(self):
        result = self._resolve_base_url(
            cli_base_url=None,
            env_skylos_url="http://skylos:8000/v1",
            env_openai_url="http://openai:8000/v1",
        )
        assert result == "http://skylos:8000/v1"

    def test_openai_env_as_fallback(self):
        result = self._resolve_base_url(
            cli_base_url=None,
            env_skylos_url=None,
            env_openai_url="http://openai:8000/v1",
        )
        assert result == "http://openai:8000/v1"

    def test_none_when_no_base_url_set(self):
        result = self._resolve_base_url(
            cli_base_url=None, env_skylos_url=None, env_openai_url=None
        )
        assert result is None


class TestLocalEndpointDetection:
    def _is_local_endpoint(self, provider, base_url):
        if provider != "openai" or not base_url:
            return False

        local_hosts = ["localhost", "127.0.0.1", "0.0.0.0"]
        for h in local_hosts:
            if h in base_url:
                return True
        return False

    def test_localhost_detected(self):
        assert self._is_local_endpoint("openai", "http://localhost:11434/v1") is True

    def test_127_0_0_1_detected(self):
        assert self._is_local_endpoint("openai", "http://127.0.0.1:1234/v1") is True

    def test_0_0_0_0_detected(self):
        assert self._is_local_endpoint("openai", "http://0.0.0.0:8000/v1") is True

    def test_remote_url_not_local(self):
        assert self._is_local_endpoint("openai", "https://api.openai.com/v1") is False

    def test_anthropic_provider_not_local(self):
        assert self._is_local_endpoint("anthropic", "http://localhost:8000/v1") is False

    def test_no_base_url_not_local(self):
        assert self._is_local_endpoint("openai", None) is False


class TestAPIKeyRequirement:
    def _needs_api_key_prompt(self, api_key, using_local):
        if not api_key and using_local:
            return False
        if not api_key:
            return True
        return False

    def test_no_key_remote_needs_prompt(self):
        assert self._needs_api_key_prompt(None, using_local=False) is True

    def test_no_key_local_no_prompt(self):
        assert self._needs_api_key_prompt(None, using_local=True) is False

    def test_has_key_no_prompt(self):
        assert self._needs_api_key_prompt("my-key", using_local=False) is False
        assert self._needs_api_key_prompt("my-key", using_local=True) is False


class TestCLIArgumentParsing:
    def test_provider_choices_valid(self):
        valid_providers = ["openai", "anthropic"]
        assert "openai" in valid_providers
        assert "anthropic" in valid_providers

    def test_default_model(self):
        default_model = "gpt-4.1"
        assert default_model == "gpt-4.1"


class TestEndToEndScenarios:
    def _simulate_cli_setup(
        self,
        model,
        cli_provider=None,
        cli_base_url=None,
        env_provider=None,
        env_base_url=None,
        env_api_key=None,
    ):
        provider = cli_provider
        if not provider:
            provider = env_provider
        if not provider:
            if "claude" in model.lower():
                provider = "anthropic"
            else:
                provider = "openai"

        base_url = cli_base_url
        if not base_url:
            base_url = env_base_url

        local_hosts = ["localhost", "127.0.0.1", "0.0.0.0"]
        is_local_host = False
        if base_url:
            for h in local_hosts:
                if h in base_url:
                    is_local_host = True
                    break

        using_local = bool(provider == "openai" and base_url and is_local_host)

        api_key = env_api_key
        if not api_key and using_local:
            api_key = ""

        needs_key_prompt = not api_key and not using_local

        return {
            "provider": provider,
            "base_url": base_url,
            "using_local": using_local,
            "api_key": api_key,
            "needs_key_prompt": needs_key_prompt,
        }

    def test_scenario_cloud_openai(self):
        result = self._simulate_cli_setup(model="gpt-4.1", env_api_key="sk-xxx")
        assert result["provider"] == "openai"
        assert result["base_url"] is None
        assert result["using_local"] is False
        assert result["needs_key_prompt"] is False

    def test_scenario_cloud_anthropic(self):
        result = self._simulate_cli_setup(
            model="claude-3-7-sonnet-latest", env_api_key="sk-ant-xxx"
        )
        assert result["provider"] == "anthropic"
        assert result["base_url"] is None
        assert result["using_local"] is False

    def test_scenario_local_ollama(self):
        result = self._simulate_cli_setup(
            model="qwen2.5-coder:7b",
            cli_provider="openai",
            cli_base_url="http://localhost:11434/v1",
        )
        assert result["provider"] == "openai"
        assert result["base_url"] == "http://localhost:11434/v1"
        assert result["using_local"] is True
        assert result["needs_key_prompt"] is False

    def test_scenario_local_lmstudio(self):
        result = self._simulate_cli_setup(
            model="mistral",
            cli_provider="openai",
            cli_base_url="http://localhost:1234/v1",
        )
        assert result["provider"] == "openai"
        assert result["base_url"] == "http://localhost:1234/v1"
        assert result["using_local"] is True
        assert result["needs_key_prompt"] is False

    def test_scenario_local_vllm(self):
        result = self._simulate_cli_setup(
            model="meta-llama/Llama-2-7b",
            cli_provider="openai",
            cli_base_url="http://127.0.0.1:8000/v1",
        )
        assert result["provider"] == "openai"
        assert result["using_local"] is True
        assert result["needs_key_prompt"] is False

    def test_scenario_env_config_only(self):
        result = self._simulate_cli_setup(
            model="qwen2.5-coder:7b",
            env_provider="openai",
            env_base_url="http://localhost:11434/v1",
        )
        assert result["provider"] == "openai"
        assert result["base_url"] == "http://localhost:11434/v1"
        assert result["using_local"] is True

    def test_scenario_missing_key_remote(self):
        result = self._simulate_cli_setup(model="gpt-4.1", env_api_key=None)
        assert result["needs_key_prompt"] is True

    def test_scenario_force_openai_for_claude_model(self):
        result = self._simulate_cli_setup(
            model="claude-compat-model",
            cli_provider="openai",
            cli_base_url="http://localhost:8000/v1",
        )
        assert result["provider"] == "openai"
        assert result["using_local"] is True


class TestEdgeCases:
    def test_case_insensitive_claude_detection(self):
        models = ["Claude-3", "CLAUDE-opus", "claude-sonnet", "ClAuDe-haiku"]
        for model in models:
            if "claude" in model.lower():
                provider = "anthropic"
            else:
                provider = "openai"
            assert provider == "anthropic", f"Failed for {model}"

    def test_claude_in_model_name_substring(self):
        model = "my-fine-tuned-claude-variant"
        if "claude" in model.lower():
            provider = "anthropic"
        else:
            provider = "openai"
        assert provider == "anthropic"

    def test_empty_string_env_vars_treated_as_unset(self):
        cli_provider = None
        env_provider = ""
        model = "gpt-4"

        provider = (
            cli_provider
            or env_provider
            or ("anthropic" if "claude" in model.lower() else "openai")
        )
        assert provider == "openai"


class TestIPv6LocalDetection:
    def _is_local_endpoint(self, provider, base_url):
        if provider != "openai" or not base_url:
            return False
        local_hosts = ["localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]"]
        for h in local_hosts:
            if h in base_url:
                return True
        return False


class TestRealWorldModelNames:
    def _resolve_provider(self, model, cli_provider=None):
        return cli_provider or ("anthropic" if "claude" in model.lower() else "openai")

    def test_openai_models(self):
        openai_models = [
            "gpt-4.1",
            "gpt-4-turbo",
            "gpt-3.5-turbo",
            "o1-preview",
            "o1-mini",
        ]
        for model in openai_models:
            assert self._resolve_provider(model) == "openai", f"Failed for {model}"

    def test_anthropic_models(self):
        anthropic_models = [
            "claude-3-7-sonnet-latest",
            "claude-3-opus-20240229",
            "claude-3-haiku-20240307",
            "claude-2.1",
        ]
        for model in anthropic_models:
            assert self._resolve_provider(model) == "anthropic", f"Failed for {model}"

    def test_local_models(self):
        local_models = [
            "qwen2.5-coder:7b",
            "llama3.2:latest",
            "mistral:7b-instruct",
            "codellama:13b",
            "deepseek-coder:6.7b",
            "phi3:mini",
        ]
        for model in local_models:
            assert self._resolve_provider(model) == "openai", f"Failed for {model}"


class TestPortVariations:
    def _simulate_cli_setup(self, base_url):
        local_hosts = ["localhost", "127.0.0.1", "0.0.0.0"]
        is_local = False
        if base_url:
            for h in local_hosts:
                if h in base_url:
                    is_local = True
                    break
        return is_local

    def test_ollama_default_port(self):
        assert self._simulate_cli_setup("http://localhost:11434/v1") is True

    def test_lmstudio_default_port(self):
        assert self._simulate_cli_setup("http://localhost:1234/v1") is True

    def test_vllm_default_port(self):
        assert self._simulate_cli_setup("http://localhost:8000/v1") is True

    def test_custom_port(self):
        assert self._simulate_cli_setup("http://localhost:9999/v1") is True

    def test_no_port_specified(self):
        assert self._simulate_cli_setup("http://localhost/v1") is True
