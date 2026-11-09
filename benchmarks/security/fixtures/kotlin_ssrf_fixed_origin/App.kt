import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.server.application.Application
import io.ktor.server.request.*
import io.ktor.server.routing.*

fun Application.module(client: HttpClient) {
    routing {
        get("/catalogue") {
            val key = call.request.queryParameters["key"]!!
            client.get("https://api.example.invalid/v1/$key") // SINK
        }
    }
}
