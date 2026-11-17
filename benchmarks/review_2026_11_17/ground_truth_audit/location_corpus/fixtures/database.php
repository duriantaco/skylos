<?php
function lookup($pdo) {
    $pdo->query("SELECT * FROM users WHERE id = '" . $_GET['id'] . "'");
    $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
    $stmt->execute([$_GET['id']]);
}
