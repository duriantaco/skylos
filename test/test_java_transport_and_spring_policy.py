from textwrap import dedent

from skylos.visitors.languages.java import scan_java_file


def _findings(tmp_path, source, rule):
    path = tmp_path / "ServiceConfig.java"
    path.write_text(dedent(source), encoding="utf-8")
    return [
        (finding["rule_id"], finding["line"])
        for finding in scan_java_file(str(path), {})[7]
        if finding["rule_id"] == rule
    ]


def test_native_trust_managers_only_report_nonvalidating_methods(tmp_path):
    assert _findings(
        tmp_path,
        """\
        import javax.net.ssl.X509TrustManager;
        import javax.net.ssl.X509ExtendedTrustManager;
        import java.security.cert.X509Certificate;
        import java.security.cert.CertificateException;
        class Manager implements X509TrustManager {
          public void checkServerTrusted(X509Certificate[] chain, String auth) {}
          public void checkClientTrusted(X509Certificate[] chain, String auth) throws CertificateException {
            throw new CertificateException("unexpected client");
          }
          public X509Certificate[] getAcceptedIssuers() { return null; }
        }
        class Extended extends X509ExtendedTrustManager {
          public void checkServerTrusted(X509Certificate[] chain, String auth, java.net.Socket socket) { return; }
        }
        class Provider {
          Object manager = new javax.net.ssl.X509TrustManager() {
            public void checkServerTrusted(X509Certificate[] chain, String auth) {}
          };
        }
        class Example {
          public void checkServerTrusted(X509Certificate[] chain, String auth) {}
        }
        class WrongSignature implements X509TrustManager {
          public void checkServerTrusted(String name, String auth) {}
        }
        """,
        "SKY-D210",
    ) == [("SKY-D210", 6), ("SKY-D210", 13), ("SKY-D210", 17)]


def test_non_jdk_trust_manager_lookalike_is_quiet(tmp_path):
    assert (
        _findings(
            tmp_path,
            """\
        import local.net.X509TrustManager;
        class Manager implements X509TrustManager {
          public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String auth) {}
        }
        """,
            "SKY-D210",
        )
        == []
    )


def test_spring_csrf_disabling_requires_native_security_configuration(tmp_path):
    assert _findings(
        tmp_path,
        """\
        import org.springframework.security.config.annotation.web.builders.HttpSecurity;
        import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
        import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
        class ServiceConfig {
          void config(HttpSecurity http, Local local) {
            http.csrf().disable();
            http.csrf(AbstractHttpConfigurer::disable);
            http.csrf(csrf -> csrf.disable());
            http.csrf(csrf -> csrf.ignoringRequestMatchers("/health"));
            local.csrf().disable();
            http.csrf(Local::disable);
            http.csrf(csrf -> local.disable());
            http.authorizeHttpRequests(rules -> rules.anyRequest().authenticated())
                .csrf(CsrfConfigurer::disable);
          }
          void reference(HttpSecurity http, Local AbstractHttpConfigurer) {
            http.csrf(AbstractHttpConfigurer::disable);
          }
          static class Local {
            Local csrf() { return this; }
            void disable() {}
            void disable(CsrfConfigurer<?> configurer) {}
          }
        }
        """,
        "SKY-D433",
    ) == [("SKY-D433", 6), ("SKY-D433", 7), ("SKY-D433", 8), ("SKY-D433", 14)]
