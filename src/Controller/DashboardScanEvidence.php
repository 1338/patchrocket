<?php
declare(strict_types=1);

namespace App\Controller;

use App\Audit\Store;

final class DashboardScanEvidence
{
    /** Use a trusted integer timestamp or a bound parameter for the snapshot time. */
    public static function scheduleStateSql(int|string $now): string
    {
        return "CASE WHEN s.id IS NULL THEN 'unscheduled' WHEN s.lease_until > $now THEN 'running'
            WHEN s.next_at <= $now THEN 'due' ELSE 'scheduled' END";
    }

    public static function stateSql(Store $store): string
    {
        $outcome = $store->jsonText('a.data', 'scan_outcome');
        $source = $store->jsonText('a.data', 'scan_source');
        $scanned = $store->jsonText('a.data', 'scanned_at');
        $attempted = self::attemptSql($store);

        return "CASE
            WHEN $attempted IS NOT NULL AND ($scanned IS NULL OR $attempted >= $scanned) THEN 'failed'
            WHEN $outcome = 'failed' AND $attempted IS NULL THEN 'failed'
            WHEN NULLIF($scanned, '') IS NOT NULL OR NULLIF($source, '') IS NOT NULL THEN 'recorded'
            WHEN EXISTS(SELECT 1 FROM findings evidence WHERE evidence.asset_id = a.id) THEN 'recorded'
            WHEN a.kind IN ('image', 'linux', 'repository') THEN 'unscanned'
            ELSE '' END";
    }

    public static function attemptSql(Store $store): string
    {
        $asset = $store->jsonText('a.data', 'scan_attempted_at');
        $assetOutcome = $store->jsonText('a.data', 'scan_outcome');
        $schedule = $store->jsonText('s.data', 'attempted_at');
        $scheduleOutcome = $store->jsonText('s.data', 'outcome');

        return "CASE
            WHEN $scheduleOutcome = 'failed' AND ($assetOutcome IS NULL OR $assetOutcome <> 'failed' OR $asset IS NULL OR $schedule >= $asset)
                THEN $schedule
            WHEN $assetOutcome = 'failed' THEN $asset
            ELSE NULL END";
    }
}
