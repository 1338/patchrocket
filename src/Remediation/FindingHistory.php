<?php
declare(strict_types=1);

namespace App\Remediation;

use App\Audit\Store;
use Doctrine\DBAL\Platforms\SQLitePlatform;

final class FindingHistory
{
    private const PAGE_SIZE = 25;

    public function __construct(private readonly Store $store, private readonly DashboardStatuses $statuses)
    {
    }

    public function page(array $finding, array $asset, string $search, int $page, string $attempt): array
    {
        $sqlite = $this->store->db->getDatabasePlatform() instanceof SQLitePlatform;
        $advisory = $sqlite ? "json_extract(c.data, '$.finding.advisory')" : "(CAST(c.data AS jsonb)#>>'{finding,advisory}')";
        $title = $this->store->jsonText('c.data', 'title');
        $query = $this->statuses->query("c.id, c.strategy, c.created_at, COALESCE($title, $advisory, SUBSTR(c.id, 1, 8)) AS title");
        $scope = 'c.finding_id = ?';
        $parameters = [$finding['id']];
        if ('image' === $asset['kind'] && !empty($asset['data']['digest'])) {
            $digest = $this->store->jsonText('c.data', 'observed_image');
            $package = $sqlite ? "json_extract(c.data, '$.finding.package')" : "(CAST(c.data AS jsonb)#>>'{finding,package}')";
            $ecosystem = $sqlite ? "json_extract(c.data, '$.finding.type')" : "(CAST(c.data AS jsonb)#>>'{finding,type}')";
            $includesAdvisory = $sqlite
                ? "EXISTS (SELECT 1 FROM json_each(CASE WHEN json_type(c.data, '$.plan.advisories') = 'array'
                    THEN json_extract(c.data, '$.plan.advisories') ELSE '[]' END) advisory WHERE advisory.type = 'text' AND advisory.value = ?)"
                : "(CAST(c.data AS jsonb)#>'{plan,advisories}') @> jsonb_build_array(CAST(? AS text))";
            $scope .= " OR (c.strategy = 'docker-base' AND $digest = ? AND $package = ? AND $ecosystem = ? AND $includesAdvisory)";
            array_push($parameters, $asset['data']['digest'], $finding['data']['package'], $finding['data']['type'], $finding['data']['advisory']);
        }
        $filter = '';
        if ('' !== $search) {
            $filter = "WHERE LOWER(title) LIKE LOWER(?) ESCAPE '!' OR LOWER(id) LIKE LOWER(?) ESCAPE '!'";
            $pattern = '%'.strtr($search, ['!' => '!!', '%' => '!%', '_' => '!_']).'%';
            array_push($parameters, $pattern, $pattern);
        }
        $size = self::PAGE_SIZE;
        $offset = ($page - 1) * $size;
        // Rank the selection and read its page within one database snapshot.
        $result = $this->store->db->fetchAllAssociative("WITH scoped AS ($query WHERE $scope),
            ranked AS (SELECT scoped.*, ROW_NUMBER() OVER (ORDER BY created_at DESC, id DESC) AS position FROM scoped $filter),
            summary AS (SELECT COUNT(*) AS total, MAX(CASE WHEN id = ? THEN position END) AS selected_position FROM ranked),
            window_start AS (SELECT summary.*, COALESCE(((selected_position - 1) / $size) * $size, $offset) AS row_offset FROM summary)
            SELECT ranked.id, ranked.strategy, ranked.created_at, ranked.title, ranked.display_status,
                window_start.total, window_start.selected_position, window_start.row_offset
            FROM window_start LEFT JOIN ranked ON ranked.position > window_start.row_offset AND ranked.position <= window_start.row_offset + $size
            ORDER BY ranked.position", [...$parameters, $attempt]);
        $total = (int) $result[0]['total'];
        $offset = (int) $result[0]['row_offset'];
        $page = intdiv($offset, $size) + 1;
        $lastPage = intdiv(max(0, $total - 1), $size) + 1;
        $selected = null !== $result[0]['selected_position'] ? $attempt : null;
        $rows = [];
        foreach ($result as $row) {
            if (null !== $row['id']) {
                unset($row['total'], $row['selected_position'], $row['row_offset']);
                $rows[] = $row;
            }
        }

        return compact('rows', 'search', 'page', 'lastPage', 'total', 'offset', 'attempt', 'selected');
    }
}
