package app

private fun unwrapAll(error: Throwable): Throwable = error.cause ?: error

fun rootMessage(error: Throwable): String = unwrapAll(error).message ?: ""
