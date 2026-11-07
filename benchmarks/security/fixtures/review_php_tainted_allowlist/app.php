<?php
$page = $_GET['page'];
$allowed = [$_GET['allowed']];
if (in_array($page, $allowed, true)) {
    include $page; // sink
}
