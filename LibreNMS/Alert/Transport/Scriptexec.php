<?php

namespace LibreNMS\Alert\Transport;

use LibreNMS\Alert\Transport;

class Scriptexec extends Transport
{
    public function deliverAlert(array $alert_data): bool
    {
        $cmd = trim((string)($this->config['command'] ?? ''));
        if ($cmd === '') {
            \Log::error('Scriptexec: command is empty');
            return false;
        }

        $allowedPrefix = trim((string)($this->config['allowed_prefix'] ?? '/opt/librenms/scripts/'));
        if ($allowedPrefix !== '' && strpos($cmd, $allowedPrefix) !== 0) {
            \Log::error("Scriptexec: command not allowed (must start with {$allowedPrefix}): {$cmd}");
            return false;
        }

        $payloadMode = (string)($this->config['payload_mode'] ?? 'full');
        $payloadData = $alert_data;
        if ($payloadMode === 'details' && isset($alert_data['details'])) {
            $payloadData = $alert_data['details'];
        }

        $payload = json_encode($payloadData, JSON_UNESCAPED_SLASHES);
        if ($payload === false) {
            \Log::error('Scriptexec: json_encode failed');
            return false;
        }

        $timeout = (int)($this->config['timeout'] ?? 20);
        if ($timeout < 1 || $timeout > 300) {
            $timeout = 20;
        }

        $logStdoutRaw = $this->config['log_stdout'] ?? false;
        $logStdout = filter_var($logStdoutRaw, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
        $logStdout = ($logStdout === null) ? false : $logStdout;

        $env = [
            'LIBRENMS_TRANSPORT' => 'Scriptexec',
            'LIBRENMS_ALERT_NAME' => (string)($alert_data['name'] ?? $alert_data['title'] ?? ''),
            'LIBRENMS_ALERT_SEVERITY' => (string)($alert_data['severity'] ?? ''),
            'LIBRENMS_DEVICE' => (string)($alert_data['sysName'] ?? $alert_data['hostname'] ?? ''),
        ];

        return $this->contactScriptexec($cmd, $payload, $timeout, $env, $logStdout);
    }

    public function contactScriptexec(string $cmd, string $payload, int $timeout, array $env, bool $logStdout): bool
    {
        $descriptorspec = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $process = proc_open($cmd, $descriptorspec, $pipes, null, $env);
        if (!is_resource($process)) {
            \Log::error("Scriptexec: proc_open failed for cmd={$cmd}");
            return false;
        }

        fwrite($pipes[0], $payload);
        fclose($pipes[0]);

        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);

        fclose($pipes[1]);
        fclose($pipes[2]);

        $exit = proc_close($process);

        if ($logStdout && trim($stdout) !== '') {
            \Log::info("Scriptexec stdout cmd={$cmd}: " . trim($stdout));
        }

        if ($exit !== 0) {
            \Log::error("Scriptexec failed exit={$exit} cmd={$cmd} stderr={$stderr} stdout={$stdout}");
            return false;
        }

        return true;
    }

    public static function configTemplate(): array
    {
        return [
            'config' => [
                [
                    'title' => 'Command',
                    'name' => 'command',
                    'descr' => 'Command to execute (reads JSON from STDIN)',
                    'type' => 'text',
                ],
                [
                    'title' => 'Allowed prefix',
                    'name' => 'allowed_prefix',
                    'descr' => 'Restrict scripts to this path',
                    'type' => 'text',
                    'default' => '/opt/librenms/scripts/',
                ],
                [
                    'title' => 'Payload mode',
                    'name' => 'payload_mode',
                    'type' => 'select',
                    'options' => [
                        'full' => 'full',
                        'details' => 'details',
                    ],
                    'default' => 'full',
                ],
                [
                    'title' => 'Timeout (seconds)',
                    'name' => 'timeout',
                    'type' => 'text',
                    'default' => '20',
                ],
                [
                    'title' => 'Log stdout',
                    'name' => 'log_stdout',
                    'type' => 'checkbox',
                    'default' => false,
                ],
            ],
            'validation' => [
                'command' => 'required|string|min:3',
                'allowed_prefix' => 'nullable|string',
                'payload_mode' => 'required|in:full,details',
                'timeout' => 'nullable|integer|min:1|max:300',
                'log_stdout' => 'nullable|in:0,1,on,off,true,false',
            ],
        ];
    }
}
