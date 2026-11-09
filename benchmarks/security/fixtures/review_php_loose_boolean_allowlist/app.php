<?php
$page = $_GET['page'];
if (in_array($page, [true])) {
    include $page; // sink
}
