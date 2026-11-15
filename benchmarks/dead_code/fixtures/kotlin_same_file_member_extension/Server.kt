package app

class Wrapper(val inner: Wrapper?)

class Server {
    fun depth(wrapper: Wrapper): Int = wrapper.run { this.unwrapAll() }

    private fun Wrapper.unwrapAll(): Int {
        val next = this.inner ?: return 0
        return 1 + next.unwrapAll()
    }

    private fun Wrapper.unusedExtension(): Int = 0
}
