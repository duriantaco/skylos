import io.ktor.http.ContentType
import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing

fun Application.module() {
    routing {
        get("/hello") {
            val name = call.request.queryParameters["name"]
            call.respondText("<h1>$name</h1>", ContentType.Text.Html)
        }
    }
}
