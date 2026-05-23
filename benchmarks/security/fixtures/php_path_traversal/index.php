<?php

function read_file() {
    $path = $_GET["path"];
    return file_get_contents($path);
}
