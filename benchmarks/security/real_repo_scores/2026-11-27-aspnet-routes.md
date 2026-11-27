# ASP.NET Core Minimal API route handlers

We labeled the registrations from pinned C# source before scoring each sample.
The counts below measure whether the security analyzer found the handler that
ASP.NET calls. None of the labeled handlers sends request input to an outbound
HTTP destination. These samples measure route coverage and false alerts. The
positive security checks use local fixtures.

| Upstream sample and labeled sites | Before (`7d3187de`) | After |
| --- | ---: | ---: |
| [eShop Catalog API](https://github.com/dotnet/eShop/blob/3c6e531a6063676ece317644f72172fb42a935b3/src/Catalog.API/Apis/CatalogApi.cs) – `GetAllItemsV1`, `GetItemsByIds`, `GetCatalogFacets` | 3/3 | 3/3 |
| [WebMinRouteGroup V1](https://github.com/dotnet/AspNetCore.Docs.Samples/blob/df6d0a3aa5e3f0af44394495f3a8ce40a94ad361/fundamentals/minimal-apis/samples/MinApiTestsSample/WebMinRouteGroup/TodoEndpointsV1.cs) and [V2](https://github.com/dotnet/AspNetCore.Docs.Samples/blob/df6d0a3aa5e3f0af44394495f3a8ce40a94ad361/fundamentals/minimal-apis/samples/MinApiTestsSample/WebMinRouteGroup/TodoEndpointsV2.cs) – five V1 and six V2 named handlers | 11/11 | 11/11 |
| [Todo parameter-binding sample](https://github.com/dotnet/AspNetCore.Docs.Samples/blob/df6d0a3aa5e3f0af44394495f3a8ce40a94ad361/fundamentals/minimal-apis/samples/arg-lists/Program.cs) – nine lambdas registered on `app` | 9/9 | 9/9 |
| [DefaultBuilder sample](https://github.com/dotnet/aspnetcore/blob/58e64be7c22eea2b6f1221f3cb310071237115e4/src/DefaultBuilder/samples/SampleApp/Program.cs#L17) – one lambda with a delegate cast | 0/1 | 1/1 |
| [MinimalApis.Extensions example](https://github.com/DamianEdwards/MinimalApis.Extensions/blob/79eb9064e839295c055ca38ea1b785faba5eacb3/samples/MinimalApis.Examples/Program.cs#L26) – the POST handlers on lines 26 and 31 | 2/2 | 2/2 |
| [MinimalApiPlayground Todo.EFCore](https://github.com/davidfowl/MinimalApiPlayground/blob/42119ce2de724e424b62877f0dec5ba331cfd019/src/Todo.EFCore/Program.cs#L27) – the GET handlers on lines 27, 37 and 45 | 3/3 | 3/3 |

The baseline also classified five legacy router callbacks in DefaultBuilder as
Minimal API handlers. The updated analyzer classified all five correctly. An
early candidate dropped all three labeled eShop routes. We used eShop and
DefaultBuilder to correct the implementation, so their final scores are
regression checks. We selected the Todo.EFCore sample after those corrections
and froze its three labels before running either scanner.

The CLI scanned 66 C# source files across these six sample projects. It reported
zero unchecked files and zero `SKY-D216` findings. Only the named sites above
were manually labeled. No sample application was built or run.

The [whole-analyzer tests](../../../test/test_csharp_minimal_api_routes.py)
move a request-bound `HttpClient` call into a second file, check its reported
line and remove its route registration between scans. Paired controls use a
fixed destination, an explicitly injected service, a same-named handler in a
different namespace and a user-defined `MapGet` method. The project's C#
security benchmark had eight positive cases and eleven safe cases. All nineteen
matched their expected findings.
