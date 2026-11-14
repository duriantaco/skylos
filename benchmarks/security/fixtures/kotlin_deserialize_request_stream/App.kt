import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.request.receiveStream
import io.ktor.server.response.respondText
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import java.io.ObjectInputStream

fun Application.module() {
    routing {
        post("/load") {
            val value = ObjectInputStream(call.receiveStream()).readObject()
            call.respondText(value.toString())
        }
    }
}
