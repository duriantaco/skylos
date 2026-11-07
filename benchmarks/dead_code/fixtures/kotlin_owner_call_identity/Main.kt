class PrimaryProcessor {
    fun run() { process() }
    private fun process() { println("primary") }
}

class SecondaryProcessor {
    private fun process() { println("secondary") }
}

fun main() {
    PrimaryProcessor().run()
    SecondaryProcessor()
}
