<?php

function read_file() {
    $name = basename($_GET["path"]);
    return file_get_contents(__DIR__ . "/uploads/" . $name);
}
