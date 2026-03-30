<?php

/*Copyright (c) 2019 GitStoph <https://github.com/GitStoph>
 * Original Alerta transport author: GitStoph
 * Updated/customised for LibreNMS -> Alerta integration: 2026-03-30
 * Updated by: Pizu (DM)
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version. Please see LICENSE.txt at the top level of
 * the source code distribution for details.
 */

/**
 * Alerta Transport
 *
 * Custom LibreNMS -> Alerta transport with generic per-fault handling.
 *
 * Summary:
 * - Sends one Alerta event per LibreNMS fault row
 * - Keeps resource mapped to configured origin
 * - Keeps group mapped to top-level sysContact
 * - Re-renders the LibreNMS alert template per fault for text/description
 * - Uses a stable per-fault event signature for repeats and recovery matching
 *
 * Notes:
 * - The MD5 hash is used only as a compact fault fingerprint for uniqueness
 *   and recovery matching; it is not used for security
 * - Optional debug fields such as 'fault' and 'rawData' can be enabled
 *   temporarily for troubleshooting
 */

namespace LibreNMS\Alert\Transport;

use Illuminate\Support\Facades\Cache;
use LibreNMS\Alert\Template as LibreNmsTemplate;
use LibreNMS\Alert\Transport;
use LibreNMS\Enum\AlertState;
use LibreNMS\Exceptions\AlertTransportDeliveryException;
use LibreNMS\Util\Http;

class Alerta extends Transport
{
    /**
     * Human-readable transport name shown by LibreNMS.
     */
    protected string $name = 'Alerta';

    /**
     * Number of days to retain cached active fault signatures.
     *
     * The cache is used to compare previously active faults with the current
     * fault set so that partial and full recovery can clear the correct Alerta
     * events.
     */
    private const CACHE_DAYS = 30;

    /**
     * Fields ignored when generating a fault signature.
     *
     * These values are intentionally excluded because they tend to be noisy,
     * volatile, or informational only. Including them would make logically
     * identical faults look different and would break repeat / recovery
     * matching in Alerta.
     */
    private const FAULT_SIGNATURE_IGNORE = [
        'string',
        'sysDescr',
        'last_polled',
        'last_poll_attempted',
        'last_polled_timetaken',
        'last_discovered',
        'last_discovered_timetaken',
        'last_ping',
        'last_ping_timetaken',
        'poll_time',
        'poll_prev',
        'poll_period',
        'uptime',
        'agent_uptime',
    ];

    /**
     * Deliver a LibreNMS alert to Alerta.
     *
     * High-level flow:
     * 1. Build the shared Alerta context (resource, environment, group, service).
     * 2. Load the previously cached fault signatures for this device/rule pair.
     * 3. Extract the current fault rows and turn them into stable signatures.
     * 4. Clear any signatures that disappeared since the last run.
     * 5. If the alert fully recovered, clear cache and stop.
     * 6. Otherwise, send all currently active fault signatures and refresh cache.
     */
    public function deliverAlert(array $alert_data): bool
    {
        // Alerta resource is intentionally kept as the configured LibreNMS
        // origin rather than the device name. This was a design requirement.
        $resource = $this->cleanString($this->config['origin'] ?? 'LibreNMS') ?: 'LibreNMS';

        // Environment is passed through as-is after normalization so it can be
        // used by Alerta for namespacing and routing.
        $environment = $this->cleanString($this->config['environment'] ?? '');

        // Group is intentionally mapped from the top-level LibreNMS sysContact.
        $group = $this->cleanString($alert_data['sysContact'] ?? 'Unknown') ?: 'Unknown';

        // Service is kept as a single-item array, following Alerta's payload
        // format for service values.
        $service = [$this->cleanString($alert_data['type'] ?? 'LibreNMS') ?: 'LibreNMS'];

        // Load the previously known active fault signatures for this device/rule.
        $cacheKey = $this->buildCacheKey($alert_data);
        $previousIndexedFaults = Cache::get($cacheKey, []);

        // Determine whether LibreNMS marked this notification as fully recovered.
        $state = $alert_data['state'] ?? null;
        $isRecovered = ($state == AlertState::RECOVERED);

        // Extract the current real fault rows. For active notifications we allow
        // a fallback empty fault so generic alerts can still be sent. For fully
        // recovered alerts we do not force an empty fault row here.
        $currentFaults = $this->extractFaults($alert_data, ! $isRecovered);

        // Build a lookup table of current fault signatures => fault payload.
        $currentIndexedFaults = $this->indexFaultsBySignature($alert_data, $currentFaults);

        // Determine which previously active fault signatures disappeared from the
        // current fault set. Those missing signatures must be cleared in Alerta.
        $faultsToClear = [];
        foreach ($previousIndexedFaults as $signature => $fault) {
            if (! array_key_exists($signature, $currentIndexedFaults)) {
                $faultsToClear[$signature] = $fault;
            }
        }

        // On full recovery, also clear anything that is still listed in the
        // current recovery payload. This handles the case where LibreNMS sends
        // recovery with one or more remaining fault rows present.
        if ($isRecovered) {
            foreach ($currentIndexedFaults as $signature => $fault) {
                $faultsToClear[$signature] = $fault;
            }

            // If nothing is cached and nothing is present in the current payload,
            // send a generic fallback clear event so recovery still has a chance
            // to close the alert path in Alerta.
            if (empty($faultsToClear) && empty($previousIndexedFaults)) {
                $fallbackSignature = $this->buildFaultSignature($alert_data, []);
                $faultsToClear[$fallbackSignature] = [];
            }
        }

        // Send all clears first so Alerta can close removed / recovered faults.
        foreach ($faultsToClear as $signature => $fault) {
            $this->sendToAlerta(
                $alert_data,
                $fault,
                $signature,
                $resource,
                $environment,
                $group,
                $service,
                $this->config['recoverstate'] ?? 'normal'
            );
        }

        // For full recovery, clear the cached active set and stop here.
        if ($isRecovered) {
            Cache::forget($cacheKey);

            return true;
        }

        // If no current fault rows were available, send one generic active event.
        if (empty($currentIndexedFaults)) {
            $currentIndexedFaults = [
                $this->buildFaultSignature($alert_data, []) => [],
            ];
        }

        // Send all currently active fault signatures. This intentionally resends
        // the full active set so repeat dispatches continue to update the same
        // Alerta events rather than only sending deltas.
        foreach ($currentIndexedFaults as $signature => $fault) {
            $this->sendToAlerta(
                $alert_data,
                $fault,
                $signature,
                $resource,
                $environment,
                $group,
                $service,
                $this->config['alertstate'] ?? 'major'
            );
        }

        // Refresh the cache with the currently active signatures so later partial
        // or full recovery notifications can close the correct events.
        Cache::put($cacheKey, $currentIndexedFaults, now()->addDays(self::CACHE_DAYS));

        return true;
    }

    /**
     * Build and send one Alerta payload.
     *
     * Each call sends exactly one Alerta event. For multi-fault LibreNMS alerts,
     * deliverAlert() calls this method once per fault signature.
     */
    private function sendToAlerta(
        array $alertData,
        array $fault,
        string $faultSignature,
        string $resource,
        string $environment,
        string $group,
        array $service,
        string $severity
    ): void {
        // Render the human-readable description for this specific fault.
        $text = $this->buildAlertText($alertData, $fault);

        // Build the stable Alerta event name used for repeat / clear matching.
        $event = $this->buildEventName($alertData, $faultSignature);

        // Build the Alerta payload.
        $payload = [
            // Required / primary routing fields.
            'resource' => $resource,
            'event' => $event,
            'environment' => $environment,
            'severity' => $severity,
            'service' => $service,
            'group' => $group,

            // Value is kept as the LibreNMS state for visibility inside Alerta.
            'value' => (string) ($alertData['state'] ?? ''),

            // Human-readable text shown in Alerta.
            'text' => $text,

            // Additional attributes preserved for searching / debugging.
            'attributes' => [
                'alert_id' => $alertData['alert_id'] ?? null,
                'alert_uid' => $alertData['uid'] ?? ($alertData['id'] ?? null),
                'deviceName' => $alertData['sysName'] ?? ($alertData['hostname'] ?? null),
                'description' => $text,
                'sysName' => $alertData['sysName'] ?? null,
                'hostname' => $alertData['hostname'] ?? null,
                'title' => $alertData['title'] ?? null,
                'display' => $alertData['display'] ?? null,
                'rule' => $alertData['name'] ?? null,
                'rule_id' => $alertData['rule_id'] ?? null,
                'device_id' => $alertData['device_id'] ?? null,
                'sysDescr' => $alertData['sysDescr'] ?? null,
                'os' => $alertData['os'] ?? null,
                'ip' => $alertData['ip'] ?? null,
                'uptime' => $alertData['uptime_long'] ?? ($alertData['uptime'] ?? null),
                'state' => $alertData['state'] ?? null,
                'timestamp' => $alertData['timestamp'] ?? null,
                'fault_signature' => $faultSignature,

                // Optional debug field:
                // Enable temporarily to include the matched fault row in the
                // Alerta payload. Useful when validating per-fault uniqueness,
                // template rendering, or recovery matching.
                // 'fault' => $fault,
            ],

            // Optional debug field:
            // Enable temporarily to include the full LibreNMS alert payload in
            // Alerta. Useful for troubleshooting template content, missing
            // fields, or unexpected recovery behaviour. Keep disabled during
            // normal operation to avoid sending excessive data.
            // 'rawData' => json_encode(
            //     $alertData,
            //     JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
            // ),

            // Keep origin aligned with the chosen Alerta resource/origin value.
            'origin' => $resource,
        ];

        // Send the payload to Alerta using the configured API key.
        $res = Http::client()
            ->acceptJson()
            ->withHeaders([
                'Authorization' => 'Key ' . $this->config['apikey'],
            ])
            ->post($this->config['alerta-url'], $payload);

        // Successful delivery needs no further handling.
        if ($res->successful()) {
            return;
        }

        // Throw a transport exception with response details so LibreNMS can log
        // exactly why Alerta delivery failed.
        throw new AlertTransportDeliveryException(
            $alertData,
            $res->status(),
            $res->body(),
            $payload['text'],
            $payload
        );
    }

    /**
     * Extract fault rows from the LibreNMS alert payload.
     *
     * LibreNMS may supply:
     * - an array of fault rows
     * - a single associative fault row
     * - no fault rows at all
     *
     * This helper normalizes all of those cases into a simple list of fault
     * arrays so the rest of the transport can process them consistently.
     */
    private function extractFaults(array $alertData, bool $includeEmptyFallback = true): array
    {
        // Read the raw LibreNMS faults field.
        $faults = $alertData['faults'] ?? null;

        // If faults is missing or empty, optionally return one empty fault row so
        // generic alerts can still be sent through the normal code path.
        if (!is_array($faults) || empty($faults)) {
            return $includeEmptyFallback ? [[]] : [];
        }

        $rows = [];

        // If the first element is an array, treat the input as a list of fault
        // rows. Otherwise treat it as one associative fault row.
        $first = reset($faults);
        if (is_array($first)) {
            foreach ($faults as $fault) {
                if (is_array($fault)) {
                    $rows[] = $fault;
                }
            }
        } else {
            $rows[] = $faults;
        }

        // If normalization still produced no rows, optionally return one empty
        // fallback row.
        if (empty($rows)) {
            return $includeEmptyFallback ? [[]] : [];
        }

        return $rows;
    }

    /**
     * Build a lookup table of fault signature => fault payload.
     *
     * This makes it easy to compare current vs previously cached fault sets and
     * identify which signatures disappeared.
     */
    private function indexFaultsBySignature(array $alertData, array $faults): array
    {
        $indexed = [];

        foreach ($faults as $fault) {
            $signature = $this->buildFaultSignature($alertData, $fault);
            $indexed[$signature] = is_array($fault) ? $fault : [];
        }

        return $indexed;
    }

    /**
     * Build a stable cache key for active fault tracking.
     *
     * The cache key is intentionally based on:
     * - the transport origin
     * - the LibreNMS device
     * - the LibreNMS rule
     *
     * It intentionally does not include title or alert instance ids because those
     * can differ between active and recovery processing.
     */
    private function buildCacheKey(array $alertData): string
    {
        $parts = [
            'alerta_faults',
            $this->cleanString($this->config['origin'] ?? 'LibreNMS') ?: 'LibreNMS',
            $alertData['device_id'] ?? 'unknown-device',
            $alertData['rule_id'] ?? 'unknown-rule',
        ];

        return implode(':', array_map(fn ($v) => (string) $v, $parts));
    }

    /**
     * Build the Alerta event name.
     *
     * The event name must remain stable between active and recovery so Alerta can
     * correlate repeats and clears with the same event. Title is intentionally
     * avoided because it may differ between active and recovery messages.
     */
    private function buildEventName(array $alertData, string $faultSignature): string
    {
        // Use the most stable rule-like name available.
        $ruleName = $this->cleanString(
            $alertData['name']
            ?? $alertData['rule']
            ?? $alertData['type']
            ?? 'LibreNMSAlert'
        ) ?: 'LibreNMSAlert';

        // Add device scope into the event key because the Alerta resource is the
        // shared LibreNMS origin, not the device itself.
        $deviceScope = $this->cleanString(
            (string) (
                $alertData['device_id']
                ?? $alertData['sysName']
                ?? $alertData['hostname']
                ?? $alertData['ip']
                ?? 'unknown-device'
            )
        ) ?: 'unknown-device';

        return sprintf('%s|dev=%s|sig=%s', $ruleName, $deviceScope, $faultSignature);
    }

    /**
     * Build a compact signature for one fault.
     *
     * Signature strategy:
     * - normalize fault content
     * - remove noisy fields
     * - JSON-encode the normalized result
     * - hash it with MD5 for a compact fixed-length fingerprint
     *
     * MD5 is used here only as a practical event fingerprint, not for security.
     */
    private function buildFaultSignature(array $alertData, array $fault): string
    {
        // If a real fault row exists, try to build the signature from it.
        if (!empty($fault)) {
            $normalizedFault = $this->normalizeForSignature($fault, self::FAULT_SIGNATURE_IGNORE);

            // If removing noisy fields leaves nothing useful, fall back to the
            // LibreNMS fault string if it exists.
            if (empty($normalizedFault) && !empty($fault['string'])) {
                $normalizedFault = ['string' => $this->cleanString((string) $fault['string'])];
            }

            // Return the compact hash of the normalized fault payload.
            if (!empty($normalizedFault)) {
                return md5(json_encode($normalizedFault, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
            }
        }

        // Generic fallback signature for alerts without a usable fault row.
        $generic = [
            'device_id' => (string) ($alertData['device_id'] ?? ''),
            'rule_id' => (string) ($alertData['rule_id'] ?? ''),
            'name' => $this->cleanString((string) ($alertData['name'] ?? '')),
            'type' => $this->cleanString((string) ($alertData['type'] ?? '')),
        ];

        return md5(json_encode($generic, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    }

    /**
     * Normalize an associative array so it can be used in a stable signature.
     *
     * Rules:
     * - ignore configured noisy keys
     * - ignore arrays / objects
     * - ignore null and empty-string values
     * - normalize all remaining scalar values with cleanString()
     * - sort keys so the JSON output remains stable
     */
    private function normalizeForSignature(array $data, array $ignoreKeys = []): array
    {
        $normalized = [];

        foreach ($data as $key => $value) {
            // Skip keys that were explicitly marked as too noisy.
            if (in_array((string) $key, $ignoreKeys, true)) {
                continue;
            }

            // Skip non-scalar values because they are harder to keep stable and
            // are not needed for the event fingerprint.
            if (is_array($value) || is_object($value)) {
                continue;
            }

            // Skip null or empty values.
            if ($value === null || $value === '') {
                continue;
            }

            // Normalize the remaining scalar into a clean string.
            $normalized[(string) $key] = $this->cleanString((string) $value);
        }

        // Sort keys so JSON encoding stays deterministic.
        ksort($normalized);

        return $normalized;
    }

    /**
     * Build the Alerta text / description for one fault.
     *
     * Preferred source order:
     * 1. Re-render the LibreNMS alert template body for only this fault.
     * 2. Use fault['string'] if present.
     * 3. Flatten the fault row into a key/value string.
     * 4. Fall back to top-level title / msg / name.
     */
    private function buildAlertText(array $alertData, array $fault): string
    {
        // First preference: render the actual LibreNMS alert template body using
        // only the current fault row.
        $rendered = $this->renderTemplateBodyForFault($alertData, $fault);
        if ($rendered !== '') {
            return $rendered;
        }

        // Second preference: LibreNMS sometimes provides a fault['string'] value
        // that already contains a human-readable summary.
        if (!empty($fault['string'])) {
            return $this->cleanString((string) $fault['string']);
        }

        // Third preference: build a generic human-readable line from the scalar
        // fault fields.
        if (!empty($fault)) {
            $parts = [];

            foreach ($fault as $key => $value) {
                if (is_array($value) || is_object($value)) {
                    continue;
                }

                if ($value === null || $value === '') {
                    continue;
                }

                $parts[] = $key . ': ' . $this->cleanString((string) $value);
            }

            if (!empty($parts)) {
                return implode(' | ', $parts);
            }
        }

        // Final fallback: use top-level alert fields if nothing fault-specific was
        // available.
        $parts = [];
        foreach (['title', 'msg', 'name'] as $field) {
            if (!empty($alertData[$field])) {
                $parts[] = $this->cleanString((string) $alertData[$field]);
            }
        }

        $parts = array_values(array_unique(array_filter($parts)));

        return !empty($parts) ? implode(' | ', $parts) : 'LibreNMS alert';
    }

    /**
     * Re-render the LibreNMS alert template body for a single fault.
     *
     * This is the key piece that lets Alerta description/text follow the
     * LibreNMS alert template while still sending one Alerta event per fault.
     */
    private function renderTemplateBodyForFault(array $alertData, array $fault): string
    {
        try {
            // Build the LibreNMS template engine and resolve the template that
            // belongs to this alert.
            $templateEngine = new LibreNmsTemplate();
            $templateModel = $templateEngine->getTemplate($alertData);

            // If no template could be resolved, return an empty string so the
            // caller can continue through the fallback chain.
            if (!$templateModel) {
                return '';
            }

            // Rebuild the alert payload but limit faults to only the current row.
            $renderAlert = $alertData;
            $renderAlert['faults'] = !empty($fault) ? [$fault] : [];

            // Render the template body.
            $body = $templateEngine->getBody([
                'alert' => $renderAlert,
                'template' => $templateModel,
            ]);

            // Normalize the rendered body so it can be sent as Alerta text.
            return $this->cleanMultilineText((string) $body);
        } catch (\Throwable $e) {
            // Any template failure should fall back quietly to the generic text
            // builders rather than breaking alert delivery.
            return '';
        }
    }

    /**
     * Normalize a single-line string.
     *
     * This helper strips HTML, trims the value, and collapses internal
     * whitespace to one space.
     */
    private function cleanString(string $value): string
    {
        $value = strip_tags($value);
        $value = preg_replace('/\s+/', ' ', trim($value));

        return $value ?? '';
    }

    /**
     * Normalize a multi-line text block.
     *
     * This helper keeps meaningful line breaks while cleaning each line.
     */
    private function cleanMultilineText(string $value): string
    {
        // Remove HTML and normalize line endings first.
        $value = strip_tags($value);
        $value = str_replace(["\r\n", "\r"], "\n", $value);

        $lines = explode("\n", $value);
        $cleaned = [];

        foreach ($lines as $line) {
            // Clean each line independently so we preserve readable newlines.
            $line = preg_replace('/[ \t]+/', ' ', trim($line));
            if ($line !== null && $line !== '') {
                $cleaned[] = $line;
            }
        }

        return trim(implode("\n", $cleaned));
    }

    /**
     * LibreNMS transport configuration form.
     *
     * These fields are shown in the LibreNMS web UI when configuring the Alerta
     * transport.
     */
    public static function configTemplate(): array
    {
        return [
            'config' => [
                [
                    'title' => 'API Endpoint',
                    'name' => 'alerta-url',
                    'descr' => 'Alerta API URL',
                    'type' => 'text',
                ],
                [
                    'title' => 'Api Key',
                    'name' => 'apikey',
                    'descr' => 'Your Alerta API key with minimally write:alert permissions.',
                    'type' => 'password',
                ],
                [
                    'title' => 'Origin',
                    'name' => 'origin',
                    'descr' => 'Name of this monitoring source, e.g. LibreNMS.',
                    'type' => 'text',
                ],
                [
                    'title' => 'Environment',
                    'name' => 'environment',
                    'descr' => 'An allowed environment from your Alerta configuration.',
                    'type' => 'text',
                ],
                [
                    'title' => 'Alert State',
                    'name' => 'alertstate',
                    'descr' => 'Severity to send to Alerta when the alert is active.',
                    'type' => 'text',
                ],
                [
                    'title' => 'Recover State',
                    'name' => 'recoverstate',
                    'descr' => 'Severity to send to Alerta when the alert recovers.',
                    'type' => 'text',
                ],
            ],
            'validation' => [
                'alerta-url' => 'required|url',
                'apikey' => 'required|string',
            ],
        ];
    }
}
