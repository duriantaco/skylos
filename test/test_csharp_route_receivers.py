from textwrap import dedent

import pytest

from skylos.visitors.languages.csharp._lex import mask_comments_and_strings
from skylos.visitors.languages.csharp.routes import endpoint_receiver_offsets


def registrations(source, **kwargs):
    source = dedent(source).strip()
    offsets = endpoint_receiver_offsets(mask_comments_and_strings(source), **kwargs)
    return sorted(1 + source.count("\n", 0, offset) for offset in offsets)


def test_builders_and_groups_share_framework_ownership():
    assert registrations("""
        var builder = WebApplication.CreateBuilder(args);
        var app = builder.Build();
        var api = app.MapGroup("/api");
        var v1 = api.MapGroup("/v1");
        var alias = v1;
        alias.MapGet("/read", Read);
        app.MapGroup("/more").MapPost("/write", Write);
        WebApplication.CreateBuilder(args).Build().MapGet("/inline", Read);
        WebApplication.Create().MapMethods("/methods", verbs, Handle);
    """) == [6, 7, 8, 9]


def test_unrelated_receivers_and_lost_identity_are_quiet():
    assert registrations("""
        var app = new Table();
        app.MapGet("/fake", Read);
        var other = Factory.CreateBuilder(args).Build();
        other.MapGet("/other", Read);
        var real = WebApplication.CreateBuilder(args).Build();
        var alias = real;
        alias.MapPost("/yes", Save);
        alias = Lookup();
        alias.MapPost("/unknown", Save);
        fake.app.MapGet("/member", Read);
    """) == [7]


def test_service_extension_receiver_and_sibling_methods():
    assert registrations("""
        static class Endpoints {
            public static void Register(this IEndpointRouteBuilder routes) {
                var group = routes.MapGroup("/users");
                group.MapGet("/", Handlers.All);
            }
            public static void Load(Table routes) {
                routes.MapGet("/", Handlers.All);
            }
        }
    """) == [4]


def test_untyped_lambda_shadows_framework_receiver():
    assert registrations("""
        var app = WebApplication.Create();
        table.Each(app => { app.MapGet("/", Read); });
        app.MapGet("/", Read);
    """) == [3]


@pytest.mark.parametrize("type_kind", ["class", "record", "interface", "struct"])
def test_framework_type_homonym_is_quiet(type_kind):
    assert (
        registrations(f"""
        var app = WebApplication.CreateBuilder().Build();
        app.MapGet("/", Read);
        {type_kind} WebApplication {{}}
    """)
        == []
    )


def test_project_shadowing_does_not_hide_explicit_framework_name():
    assert registrations(
        """
        var local = WebApplication.Create();
        var actual = global::Microsoft.AspNetCore.Builder.WebApplication.Create();
        local.MapGet("/fake", Read);
        actual.MapGet("/real", Read);
    """,
        shadowed_types=frozenset({"WebApplication"}),
    ) == [4]


def test_type_aliases():
    assert registrations("""
        using Framework = Microsoft.AspNetCore.Builder.WebApplication;
        using WebApplication = Other.Factory;
        var actual = Framework.Create();
        var local = WebApplication.Create();
        actual.MapGet("/real", Read);
        local.MapGet("/fake", Read);
    """) == [5]


def test_compatibility_for_standalone_registration():
    assert registrations('app.MapGet("/single", (string q) => q);') == [1]
    assert (
        registrations('class Sample { void Run(Table app) { app.MapGet("/", Read); } }')
        == []
    )


def test_branch_reassignment_and_block_scope():
    assert registrations("""
        var app = WebApplication.Create();
        var routes = app;
        if (flag) { routes = MaybeOther(); }
        routes.MapGet("/uncertain", Read);
        { var child = app.MapGroup("/"); child.MapGet("/", Read); }
        MapGroupHolder.child.MapGet("/", Read);
    """) == [5]


def test_scoped_using_and_standalone_imported_value():
    assert registrations("""
        namespace Web {
            using Routes = Microsoft.AspNetCore.Routing.IEndpointRouteBuilder;
            class A { public void Add(Routes r) { r.MapGet("/", Read); } }
        }
        namespace Other {
            class B { public void Add(Routes r) { r.MapGet("/", Read); } }
        }
    """) == [3]
    assert registrations('using static LocalCache; app.MapGet("key", Read);') == []


def test_conditional_unbraced_assignment_does_not_prove_endpoint():
    assert (
        registrations("""
        dynamic app = new Table();
        if (flag) app = WebApplication.Create();
        app.MapGet("key", Read);
    """)
        == []
    )


def test_namespaces_keep_unrelated_project_types_out_of_route_binding():
    source = 'var api = WebApplication.Create(); api.MapGet("/", Read);'
    shadowed = frozenset({"Unrelated.WebApplication"})
    assert registrations(source, shadowed_types=shadowed) == [1]
    assert registrations("using Unrelated; " + source, shadowed_types=shadowed) == []
    assert (
        registrations(
            source, shadowed_types=shadowed, global_usings=[(None, False, "Unrelated")]
        )
        == []
    )
    assert (
        registrations(
            source, global_usings=[("WebApplication", False, "Unrelated.LocalTable")]
        )
        == []
    )
    assert registrations("""
        namespace Unrelated {
            public class WebApplication {}
        }
        namespace Real {
            class Endpoints {
                public void Register() {
                    var api = WebApplication.Create();
                    api.MapGet("/", Read);
                }
            }
        }
    """) == [8]


def test_only_file_local_framework_homonyms_stay_in_their_own_file():
    from skylos.visitors.languages.csharp.routes import declared_framework_homonyms

    assert (
        declared_framework_homonyms("namespace Other; file class WebApplication {}")
        == set()
    )
    assert declared_framework_homonyms("namespace Other; class WebApplication {}") == {
        "Other.WebApplication"
    }


def test_versioning_keeps_proven_eshop_group_and_requires_real_package():
    source = """
        static class Catalog {
            public static void Map(this IEndpointRouteBuilder app) {
                var api = app.NewVersionedApi("Catalog");
                var both = api.MapGroup("/items").HasApiVersion(1, 0).HasApiVersion(2, 0);
                var v1 = api.MapGroup("/items").HasApiVersion(1, 0);
                both.MapGet("/", Read);
                v1.MapPost("/", Write);
            }
        }
    """
    assert registrations(source, versioning_package=True) == [6, 7]
    assert registrations("using Asp.Versioning;\n" + source) == []
    assert (
        registrations(
            source, versioning_package=True, versioning_overrides={"NewVersionedApi"}
        )
        == []
    )
    assert (
        registrations(
            source.replace("this IEndpointRouteBuilder app", "this Table app"),
            versioning_package=True,
        )
        == []
    )


@pytest.mark.parametrize(
    "local",
    [
        "static class Other { public static Table HasApiVersion(this RouteGroupBuilder e, int major) => new(); }",
        "static class Other { extension(RouteGroupBuilder e) { public Table HasApiVersion(int major) => new(); } }",
    ],
)
def test_custom_versioning_extensions_do_not_create_route_proof(local):
    source = """
        var app = WebApplication.Create();
        var real = app.MapGroup("/items");
        var local = real.HasApiVersion(1);
        real.MapGet("/", Read);
        local.MapGet("/", Read);
    """
    assert registrations(source + local, versioning_package=True) == [4]
