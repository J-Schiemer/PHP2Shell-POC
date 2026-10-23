<?php
$mode = $_GET['mode'] ?? 'user_error';
switch ($mode) {
    case 'user_error':
        trigger_error('p2s-backtrace-producer', E_USER_ERROR);
        break;
    case 'require':
        require '/nonexistent-p2s-producer.php';
        break;
    case 'oom':
        $x = str_repeat('A', 200 * 1024 * 1024);
        break;
    case 'object':
        class P2SBacktraceProbe
        {
            public function __destruct()
            {
                @file_put_contents('/out/destructor-ran', microtime(true) . "\n", FILE_APPEND);
            }
        }
        function p2s_boom_object($arg): void
        {
            trigger_error('p2s-backtrace-object', E_USER_ERROR);
        }
        p2s_boom_object(new P2SBacktraceProbe());
        break;
    case 'exception':
    default:
        throw new RuntimeException('p2s-backtrace-producer');
}
