<?php

function load_payload() {
    $payload = $_POST["payload"];
    return json_decode($payload, true);
}
