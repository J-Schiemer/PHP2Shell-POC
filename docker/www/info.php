<?php
header('Content-Type: application/json');
$keys = [
    'memory_limit', 'post_max_size', 'display_errors', 'output_buffering',
    'session.save_path', 'session.upload_progress.enabled',
    'session.upload_progress.cleanup', 'max_input_vars', 'max_file_uploads',
    'max_multipart_body_parts', 'fatal_error_backtraces',
];
$out = ['version' => PHP_VERSION, 'sapi' => php_sapi_name()];
foreach ($keys as $key) {
    $out[$key] = ini_get($key);
}
echo json_encode($out), "\n";
