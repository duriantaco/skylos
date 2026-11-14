import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.application.log
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.get
import io.ktor.server.routing.routing

fun Application.module() {
    routing {
        get("/next") {
            val next = call.request.queryParameters["next"] ?: "/"
            application.log.info("ignored redirect hint of length ${next.length}")
            call.respondRedirect("/home")
        }
    }
}
