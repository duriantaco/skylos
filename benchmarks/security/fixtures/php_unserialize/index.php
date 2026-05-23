<?php

function load_payload() {
    $payload = $_POST["payload"];
    return unserialize($payload);
}
