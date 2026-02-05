class TestModuleComputation:

    def _make_analyzer(self):
        from skylos.analyzer import Skylos
        return Skylos()

    def test_regular_layout(self, tmp_path):
        analyzer = self._make_analyzer()
        
        pkg = tmp_path / "mypackage"
        pkg.mkdir()
        (pkg / "__init__.py").touch()
        cli = pkg / "cli.py"
        cli.touch()
        
        result = analyzer._module(tmp_path, cli)
        assert result == "mypackage.cli"

    def test_src_layout(self, tmp_path):
        analyzer = self._make_analyzer()
        
        src = tmp_path / "src"
        src.mkdir()
        pkg = src / "mypackage"
        pkg.mkdir()
        (pkg / "__init__.py").touch()
        cli = pkg / "cli.py"
        cli.touch()
        
        result = analyzer._module(tmp_path, cli)
        assert result == "mypackage.cli"

    def test_monorepo_src_layout(self, tmp_path):
        analyzer = self._make_analyzer()
        
        pkg1_dir = tmp_path / "package1" / "src" / "pkg1"
        pkg1_dir.mkdir(parents=True)
        (pkg1_dir / "__init__.py").touch()
        cli = pkg1_dir / "cli.py"
        cli.touch()
        
        result = analyzer._module(tmp_path, cli)
        assert result == "pkg1.cli"

    def test_src_as_real_package(self, tmp_path):
        analyzer = self._make_analyzer()
        
        src = tmp_path / "src"
        src.mkdir()
        (src / "__init__.py").touch()
        cli = src / "cli.py"
        cli.touch()
        
        result = analyzer._module(tmp_path, cli)
        assert result == "src.cli"

    def test_nested_src_layout(self, tmp_path):
        analyzer = self._make_analyzer()
        
        nested = tmp_path / "sub" / "src" / "pkg"
        nested.mkdir(parents=True)
        (nested / "__init__.py").touch()
        mod = nested / "module.py"
        mod.touch()
        
        result = analyzer._module(tmp_path, mod)
        assert result == "pkg.module"

    def test_init_file(self, tmp_path):
        analyzer = self._make_analyzer()
        
        src = tmp_path / "src"
        src.mkdir()
        pkg = src / "mypackage"
        pkg.mkdir()
        init = pkg / "__init__.py"
        init.touch()
        
        result = analyzer._module(tmp_path, init)
        assert result == "mypackage"

    def test_deep_module(self, tmp_path):
        analyzer = self._make_analyzer()
        
        deep = tmp_path / "src" / "pkg" / "sub" / "deep"
        deep.mkdir(parents=True)
        mod = deep / "module.py"
        mod.touch()
        
        result = analyzer._module(tmp_path, mod)
        assert result == "pkg.sub.deep.module"