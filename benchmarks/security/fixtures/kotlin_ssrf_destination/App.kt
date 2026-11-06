import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.server.application.Application
import io.ktor.server.request.*
import io.ktor.server.routing.*

fun Application.module(client: HttpClient) {
    routing {
        get("/catalogue") {
            val destination = call.request.queryParameters["destination"]!!
            client.get(destination) // SINK
        }
    }
}
