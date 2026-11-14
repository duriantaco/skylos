import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondText
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class Payload(val name: String)

fun Application.module() {
    routing {
        post("/load") {
            val payload = Json.decodeFromString<Payload>(call.receiveText())
            call.respondText(payload.name)
        }
    }
}
