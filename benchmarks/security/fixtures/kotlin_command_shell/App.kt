import javax.servlet.http.HttpServletRequest

class ProcessPage {
    fun render(req: HttpServletRequest): Any {
        val requested = req.getParameter("command")
        return ProcessBuilder("sh", "-c", requested).start() // SINK
    }
}
