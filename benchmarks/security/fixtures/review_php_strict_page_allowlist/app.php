<?php
$page = $_GET['page'];
if (in_array($page, ['home.php', 'about.php'], true)) {
    include $page; // sink
}
